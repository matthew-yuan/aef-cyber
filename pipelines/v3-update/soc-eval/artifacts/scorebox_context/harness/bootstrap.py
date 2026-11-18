"""bootstrap: the child side of sandboxrun. This is the one place analyst code is compiled and executed,
always inside a container, as a demoted user, under rlimits and a deadline.

    python3 -I -S -B bootstrap.py <run_dir> <dataset.json> <kind>

It loads the dataset, hardens the interpreter (an import allow-list enforced both through sys.modules
and a meta-path finder, and a reduced builtins without open/exec/eval/compile/__import__), executes
<run_dir>/script.py in a fresh module namespace, calls the entry function with a deep copy of the
data, validates the shape of what comes back and writes <run_dir>/result.json. Exit 0 means the
entry returned; 1 means it raised or returned the wrong shape; 2 means the harness itself failed.
"""
import builtins
import copy
import importlib.abc
import json
import sys
import traceback

ALLOWED_IMPORTS = frozenset(
    "re json collections itertools functools datetime time math statistics string ipaddress base64 binascii "
    "hashlib textwrap typing dataclasses enum operator copy bisect heapq fnmatch csv io decimal fractions pprint "
    "difflib unicodedata calendar uuid abc contextlib types numbers random struct".split()
)
ALLOWED_DOTTED = frozenset({"urllib.parse"})
DENIED_ROOTS = (
    "os posix nt socket _socket ssl select selectors asyncio subprocess _posixsubprocess ctypes _ctypes multiprocessing "
    "threading _thread signal resource importlib runpy pty tty termios http urllib xmlrpc ftplib smtplib poplib imaplib "
    "telnetlib shutil pathlib tempfile glob pickle marshal shelve dbm code codeop inspect gc sysconfig site webbrowser "
    "builtins sys mmap fcntl pwd grp platform zipfile tarfile zipimport pkgutil ensurepip venv pdb bdb"
).split()
ENTRY = {"hunt_script": "hunt", "ioc_extractor": "extract"}
MAX_ITEMS = 5000


def _allowed(name: str) -> bool:
    return name in ALLOWED_DOTTED or (name.split(".")[0] in ALLOWED_IMPORTS and name.split(".")[0] != "urllib")


class _Denier(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if not _allowed(name):
            raise ImportError(f"import of {name!r} is not allowed in the sandbox")
        return None


def _harden():
    real_import = builtins.__import__

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level or not _allowed(name):
            raise ImportError(f"import of {name!r} is not allowed in the sandbox")
        return real_import(name, globals, locals, fromlist, level)

    safe = {k: v for k, v in vars(builtins).items()
            if k not in ("open", "exec", "eval", "compile", "breakpoint", "input", "help", "exit", "quit", "memoryview", "__import__", "__loader__", "__spec__")}
    safe["__import__"] = guarded_import
    sys.meta_path.insert(0, _Denier())
    for root in DENIED_ROOTS:
        # threading is referenced by the interpreter at shutdown; the finder still blocks a fresh import of it.
        if root in ("threading", "_thread"):
            continue
        sys.modules[root] = None
    sys.path[:] = []
    return safe


def _check_shape(kind, value):
    if kind == "hunt_script":
        if not isinstance(value, list) or not all(isinstance(x, dict) for x in value):
            return "hunt() must return a list of dicts"
    elif kind == "ioc_extractor":
        if not isinstance(value, dict) or not isinstance(value.get("indicators"), list) \
                or not all(isinstance(x, dict) for x in value["indicators"]):
            return "extract() must return {'indicators': [dict, ...]}"
    return None


def main(argv):
    run_dir, dataset_path, kind = argv[1], argv[2], argv[3]
    out = {"ok": False, "kind": kind, "entry": ENTRY.get(kind), "result": None, "error": None, "traceback_tail": None}

    def finish(code):
        with open(run_dir + "/result.json", "w", encoding="utf-8") as fh:
            json.dump(out, fh, default=str)
        return code

    if kind not in ENTRY:
        out["error"] = f"unknown kind {kind!r}"
        return finish(2)
    with open(dataset_path, encoding="utf-8") as fh:
        data = json.load(fh)
    with open(run_dir + "/script.py", encoding="utf-8") as fh:
        source = fh.read()
    safe_builtins = _harden()
    module = {"__name__": "__aef_sandbox__", "__builtins__": safe_builtins}
    try:
        exec(compile(source, f"<agent:{kind}>", "exec"), module)  # the only place agent code runs
        fn = module.get(ENTRY[kind])
        if not callable(fn):
            out["error"] = f"{ENTRY[kind]} is not defined"
            return finish(1)
        value = fn(copy.deepcopy(data))
    except BaseException as exc:  # noqa: BLE001 - anything the script raises is a result, not a harness failure
        out["error"] = f"{type(exc).__name__}: {exc}"[:2000]
        out["traceback_tail"] = traceback.format_exc()[-2000:]
        return finish(1)
    problem = _check_shape(kind, value)
    if problem:
        out["error"] = problem
        out["result"] = None
        return finish(1)
    if kind == "hunt_script":
        out["truncated"] = len(value) > MAX_ITEMS
        out["result"] = value[:MAX_ITEMS]
    else:
        out["truncated"] = len(value["indicators"]) > MAX_ITEMS
        out["result"] = {"indicators": value["indicators"][:MAX_ITEMS]}
    out["ok"] = True
    return finish(0)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
