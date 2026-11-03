"""codescreen: a static screen for analyst-written Python, applied before the code goes near an interpreter.

Pure `ast` analysis: the source is parsed, never compiled or executed, so this is safe to run anywhere,
including on the host. It enforces a small contract for the two Python artifact kinds:

  hunt_script    defines `hunt(data) -> list[dict]`
  ioc_extractor  defines `extract(data) -> dict`

and rejects anything that could reach outside the data it is given: imports outside an allow-list of
pure stdlib modules, calls that execute or import code or open files, reflection through dunder
attributes, async code, and top-level statements with side effects. It is one of three layers (the
others are the runtime import denier in the sandbox child and the container the child runs in); a
pass here is necessary, never sufficient.

The same file is copied into the soc image, the lab image and the scoring image; tests assert the
copies are identical.
"""
from __future__ import annotations

import ast
import hashlib

MAX_BYTES = 64 * 1024
MAX_LINES = 1500

# kind -> (entry function, number of required positional parameters)
KINDS = {"hunt_script": ("hunt", 1), "ioc_extractor": ("extract", 1)}

ALLOWED_IMPORTS = frozenset(
    "re json collections itertools functools datetime time math statistics string ipaddress base64 binascii "
    "hashlib textwrap typing dataclasses enum operator copy bisect heapq fnmatch csv io decimal fractions pprint "
    "difflib unicodedata calendar uuid abc contextlib types numbers random struct".split()
)
ALLOWED_DOTTED = frozenset({"urllib.parse"})
DENIED_CALLS = frozenset(
    "eval exec compile __import__ open globals locals vars breakpoint input help exit quit memoryview delattr".split()
)
REFLECTION_CALLS = frozenset({"getattr", "setattr", "hasattr"})
ALLOWED_DUNDER_ATTRS = frozenset({"__name__", "__doc__"})
DENIED_NAMES = frozenset({"__builtins__", "__loader__", "__spec__", "__import__", "__file__"})
TOP_LEVEL_OK = (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef, ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Pass)


def _is_dunder(name: str) -> bool:
    return len(name) > 4 and name.startswith("__") and name.endswith("__")


def _import_allowed(module: str) -> bool:
    if module in ALLOWED_DOTTED:
        return True
    root = module.split(".")[0]
    return root in ALLOWED_IMPORTS and root != "urllib"


def _is_main_guard(node: ast.If) -> bool:
    test = node.test
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)):
        return False
    sides = [test.left, test.comparators[0]]
    names = [s.id for s in sides if isinstance(s, ast.Name)]
    consts = [s.value for s in sides if isinstance(s, ast.Constant)]
    return names == ["__name__"] and consts == ["__main__"]


def screen(source: str, kind: str) -> dict:
    """Screen `source` as artifact `kind`. Never raises on bad input: problems come back in the result."""
    problems: list[dict] = []

    def deny(rule: str, line: int, detail: str) -> None:
        problems.append({"rule": rule, "line": int(line or 0), "detail": detail})

    data = source.encode("utf-8", "surrogatepass")
    lines = source.count("\n") + (0 if source.endswith("\n") else 1) if source else 0
    result = {
        "ok": False, "kind": kind, "problems": problems, "entry": None, "functions": [], "imports": [],
        "bytes": len(data), "lines": lines, "sha256": hashlib.sha256(data).hexdigest(),
    }
    if kind not in KINDS:
        deny("kind", 0, f"unknown kind {kind!r}; Python kinds are {sorted(KINDS)}")
        return result
    entry, required_params = KINDS[kind]
    result["entry"] = entry
    if len(data) > MAX_BYTES:
        deny("size", 0, f"{len(data)} bytes; the limit is {MAX_BYTES}")
        return result
    if lines > MAX_LINES:
        deny("size", 0, f"{lines} lines; the limit is {MAX_LINES}")
        return result
    try:
        tree = ast.parse(source, filename=f"<{kind}>")
    except SyntaxError as exc:
        deny("syntax", exc.lineno or 0, exc.msg)
        return result
    except (ValueError, RecursionError, MemoryError) as exc:
        deny("syntax", 0, f"cannot parse: {type(exc).__name__}")
        return result

    imports: set[str] = set()
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
                if not _import_allowed(alias.name):
                    deny("import", line, f"import of {alias.name!r} is not allowed")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                deny("import", line, "relative imports are not allowed")
                continue
            names = [a.name for a in node.names]
            if "*" in names:
                deny("import", line, f"'from {module} import *' is not allowed")
            if module == "urllib" and all(n == "parse" for n in names):
                imports.add("urllib.parse")
            elif _import_allowed(module):
                imports.add(module)
            else:
                deny("import", line, f"import from {module!r} is not allowed")
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                if func.id in DENIED_CALLS:
                    deny("call", line, f"call to {func.id}() is not allowed")
                elif func.id == "type" and len(node.args) == 3:
                    deny("call", line, "type(name, bases, dict) is not allowed")
                elif func.id in REFLECTION_CALLS:
                    attr = node.args[1] if len(node.args) > 1 else None
                    if not (isinstance(attr, ast.Constant) and isinstance(attr.value, str) and not attr.value.startswith("__")):
                        deny("reflection", line, f"{func.id}() needs a literal, non-dunder attribute name")
            elif isinstance(func, ast.Attribute) and func.attr in ("format", "format_map"):
                if isinstance(func.value, ast.Constant) and isinstance(func.value.value, str) and "__" in func.value.value:
                    deny("reflection", line, "format strings may not reach dunder attributes")
        elif isinstance(node, ast.Attribute):
            if _is_dunder(node.attr) and node.attr not in ALLOWED_DUNDER_ATTRS:
                deny("dunder", line, f"attribute {node.attr!r} is not allowed")
        elif isinstance(node, ast.Name):
            if node.id in DENIED_NAMES:
                deny("name", line, f"{node.id!r} is not allowed")
        elif isinstance(node, (ast.AsyncFunctionDef, ast.Await, ast.AsyncFor, ast.AsyncWith)):
            deny("async", line, "async code is not allowed")

    for node in tree.body:
        if isinstance(node, TOP_LEVEL_OK):
            continue
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            continue  # docstring
        if isinstance(node, ast.If) and _is_main_guard(node):
            continue
        deny("top-level", getattr(node, "lineno", 0),
             f"top-level {type(node).__name__} is not allowed; keep module scope to imports, constants, defs "
             "and an `if __name__ == \"__main__\":` guard")

    functions = [n.name for n in tree.body if isinstance(n, ast.FunctionDef)]
    result["functions"] = functions
    result["imports"] = sorted(imports)
    fn = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == entry), None)
    if fn is None:
        deny("interface", 0, f"a {kind} must define `def {entry}(data)` at module level")
    else:
        positional = [*fn.args.posonlyargs, *fn.args.args]
        required = len(positional) - len(fn.args.defaults)
        kw_required = len(fn.args.kwonlyargs) - sum(d is not None for d in fn.args.kw_defaults)
        if required != required_params or kw_required:
            deny("interface", fn.lineno, f"`{entry}` must take exactly {required_params} required positional argument (the data)")

    result["ok"] = not problems
    return result


# ---- the contract shown to the analyst (soc_get_log_schema, lab_describe_dataset) ------------------

CONTRACT = {
    "data": (
        "Your function receives one dict: {'incident_id': str, 'sources': ['auth','dns','proxy','endpoint'], "
        "'auth': [record, ...], 'dns': [...], 'proxy': [...], 'endpoint': [...]}. Every record is a flat dict with "
        "an 'id' (such as 'dns-004'), a 'source', a 'time' (ISO 8601 UTC) and a 'host', plus the fields of its source "
        "(auth: user, event, logon_type, result, src, detail; dns: query, answer, detail; proxy: user, method, url, "
        "dest_ip, status, bytes_out, bytes_in, detail; endpoint: user, event, process, parent, command_line or path, detail)."
    ),
    "hunt_script": (
        "Define `def hunt(data) -> list[dict]`. Return one finding per suspicious record: "
        "{'source': str, 'id': str, 'behavior': str, 'host': str, 'reason': str}. Flag records, not hosts: a host is "
        "judged by the records you flag on it. Only the Python standard library modules on the allow-list may be "
        "imported; no network, files, processes or reflection. Module scope holds imports, constants and defs only."
    ),
    "ioc_extractor": (
        "Define `def extract(data) -> dict`. Return {'indicators': [{'type': str, 'value': str, 'context': str}, ...]} "
        "with types such as domain, ipv4, url_path, file, scheduled_task, service, account, mutex, user_agent. Include "
        "only indicators tied to the intrusion; never the enclave's own hosts, scanners or benign domains. Same import "
        "and scope rules as hunt scripts."
    ),
    "sigma_rule": (
        "One YAML document per rule: title, logsource {service: auth|dns|proxy|endpoint}, detection {named selections, "
        "condition}, and optionally id, level, tags (ATT&CK ids). Selections are maps (AND of fields; a list value is OR); "
        "modifiers: contains, startswith, endswith, all, cidr, gt, gte, lt, lte; wildcards * and ?; conditions may use "
        "and, or, not, parentheses, '1 of sel*', 'all of them'. No regex, no aggregations, no timeframe."
    ),
    "allowed_imports": sorted(ALLOWED_IMPORTS | ALLOWED_DOTTED),
}
