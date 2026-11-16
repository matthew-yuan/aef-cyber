"""Host-side code may parse analyst text but never execute it. This scans every file that runs on the host
(verifiers, build and export scripts, run_code scripts) for the calls that could execute or import it."""
import ast

from conftest import REPO

HOST_FILES = (
    list(REPO.glob("soc-env/*/artifacts/*/verify.py")) + list(REPO.glob("pipelines/*/soc-eval/artifacts/*/verify.py"))
    + list(REPO.glob("pipelines/*/soc-eval/artifacts/*/run.py")) + list(REPO.glob("soc-env/*/artifacts/*/run.py"))
    + list(REPO.glob("pipelines/*/build.py")) + list(REPO.glob("pipelines/*/export_run.py"))
    + list(REPO.glob("pipelines/shared/*/run.py"))
)
BANNED_CALLS = {"exec", "eval", "compile", "__import__"}
BANNED_MODULES = {"subprocess", "runpy", "pty", "ctypes"}
# build.py and export_run.py load the project's own verify.py modules with importlib (by path, since both are named
# verify.py); nothing else may import modules dynamically.
IMPORTLIB_ALLOWED = {"build.py", "export_run.py"}
# export_run.py may use subprocess only to call the agent-env CLI with a literal argument list.
SUBPROCESS_ALLOWED = {"export_run.py"}


def _agent_env_cli_call(node: ast.Call) -> bool:
    first = node.args[0] if node.args else None
    return (isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess"
            and isinstance(first, ast.List) and bool(first.elts) and isinstance(first.elts[0], ast.Constant) and first.elts[0].value == "agent-env")


def test_host_side_files_cannot_execute_agent_content():
    assert HOST_FILES, "no host-side files found"
    problems = []
    for path in HOST_FILES:
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in BANNED_CALLS:
                problems.append(f"{path.relative_to(REPO)}:{node.lineno} calls {node.func.id}()")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "exec_module" and path.name not in IMPORTLIB_ALLOWED:
                problems.append(f"{path.relative_to(REPO)}:{node.lineno} exec_module")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) \
                    and node.func.value.id == "subprocess" and not (path.name in SUBPROCESS_ALLOWED and _agent_env_cli_call(node)):
                problems.append(f"{path.relative_to(REPO)}:{node.lineno} subprocess call that is not the agent-env CLI")
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                for name in names:
                    root = name.split(".")[0]
                    if root == "subprocess" and path.name in SUBPROCESS_ALLOWED:
                        continue
                    if root in BANNED_MODULES or (root == "importlib" and path.name not in IMPORTLIB_ALLOWED):
                        problems.append(f"{path.relative_to(REPO)}:{node.lineno} imports {name}")
    assert problems == [], problems
