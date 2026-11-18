"""sandboxrun: run an analyst script in a child process with every isolation this container can give it.

Used by the lab env (interactive runs) and by the scoring image (authoritative runs). The parent never
compiles or imports the script; it only writes the bytes to a private run directory and starts
`bootstrap.py` in a child that:

  - runs as a demoted uid/gid when the parent is root (the compose stack has no `user:` knob),
  - has hard resource limits (cpu seconds, address space, processes, file size, open files, no core),
  - gets a scrubbed environment (no compose variables, no credentials, dead proxies),
  - has stdin closed, stdout and stderr captured to files and tail-capped,
  - is killed as a whole process group at the wall-clock deadline.

The result is whatever the child wrote to `result.json`, parsed with a size cap, plus the exit status.
"""
from __future__ import annotations

import json
import os
import resource
import shutil
import signal
import subprocess
import time
import uuid
from pathlib import Path

ENTRY_FOR_KIND = {"hunt_script": "hunt", "ioc_extractor": "extract"}
TAIL_BYTES = 4096
MAX_RESULT_BYTES = 1024 * 1024
MAX_TIMEOUT_S = 60


def _limits(timeout_s: int):
    def apply() -> None:
        resource.setrlimit(resource.RLIMIT_CPU, (timeout_s, timeout_s + 2))
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))
        resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024, 8 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.umask(0o077)
    return apply


def _tail(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    return data[-TAIL_BYTES:].decode("utf-8", "replace")


def run_untrusted(*, code: str, kind: str, dataset_path: str, work_root: str, bootstrap_path: str,
                  timeout_s: int = 20, uid: int | None = None, gid: int | None = None,
                  python: str = "/usr/local/bin/python3") -> dict:
    """Run `code` of artifact `kind` against the JSON file at `dataset_path`. Returns a dict with
    run_id, executed, exit_code, timed_out, elapsed_ms, stdout_tail, stderr_tail, result, result_error."""
    if kind not in ENTRY_FOR_KIND:
        raise ValueError(f"unknown kind {kind!r}")
    timeout_s = max(1, min(int(timeout_s), MAX_TIMEOUT_S))
    run_id = uuid.uuid4().hex[:12]
    run_dir = Path(work_root) / run_id
    run_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    script = run_dir / "script.py"
    script.write_text(code, encoding="utf-8")
    script.chmod(0o444)
    out_path, err_path, result_path = run_dir / "stdout.txt", run_dir / "stderr.txt", run_dir / "result.json"
    demote = uid is not None and os.geteuid() == 0
    if demote:
        os.chown(run_dir, uid, gid if gid is not None else uid)
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(run_dir), "LANG": "C.UTF-8",
           "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1",
           "http_proxy": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9", "no_proxy": ""}
    cmd = [python, "-I", "-S", "-B", bootstrap_path, str(run_dir), dataset_path, kind]
    started = time.monotonic()
    timed_out = False
    exit_code: int | None = None
    with open(out_path, "wb") as out, open(err_path, "wb") as err:
        kwargs = dict(cwd=str(run_dir), env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                      start_new_session=True, preexec_fn=_limits(timeout_s))
        if demote:
            kwargs.update(user=uid, group=gid if gid is not None else uid, extra_groups=[])
        proc = subprocess.Popen(cmd, **kwargs)
        try:
            exit_code = proc.wait(timeout=timeout_s + 5)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=10)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    # The cpu rlimit delivers SIGXCPU (then SIGKILL) before the wall-clock deadline; that is a timeout too.
    killed_by = -exit_code if exit_code is not None and exit_code < 0 else None
    if killed_by in (signal.SIGXCPU, signal.SIGKILL):
        timed_out = True
    result, result_error = None, None
    if result_path.exists():
        try:
            if result_path.stat().st_size > MAX_RESULT_BYTES:
                result_error = f"result.json is over {MAX_RESULT_BYTES} bytes"
            else:
                result = json.loads(result_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError) as exc:
            result_error = f"result.json unreadable: {type(exc).__name__}"
    elif not timed_out:
        result_error = "the child wrote no result.json"
    summary = {
        "run_id": run_id, "kind": kind, "executed": True, "exit_code": exit_code, "timed_out": timed_out,
        "elapsed_ms": elapsed_ms, "killed_by_signal": killed_by, "stdout_tail": _tail(out_path), "stderr_tail": _tail(err_path),
        "result": result, "result_error": result_error,
    }
    shutil.rmtree(run_dir, ignore_errors=True)
    return summary
