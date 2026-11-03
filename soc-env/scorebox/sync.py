"""Sync the scorebox build context: copy the shared trusted modules and the data files into this folder, then mirror
the folder into every bundle that ships it as the `scorebox_context` artifact.

    uv run python soc-env/scorebox/sync.py

Run it after changing anything under soc-env/shared/, soc-env/data/ or soc-env/scorebox/. tests/test_sync.py fails
when a copy is stale.
"""
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
SHARED = REPO / "soc-env" / "shared"
DATA = REPO / "soc-env" / "data"
MODULES = ("codescreen.py", "sigma_lite.py", "sandboxrun.py", "bootstrap.py", "logexport.py")
DATA_FILES = ("log_export.json", "ground_truth.json")
TARGETS = (
    REPO / "soc-env" / "scorebox-smoke" / "artifacts" / "scorebox_context",
    REPO / "pipelines" / "v2-artifacts" / "soc-eval" / "artifacts" / "scorebox_context",
)


def expected_files() -> dict[str, bytes]:
    files = {"Dockerfile": (HERE / "Dockerfile").read_bytes(), "artifact.toml": (HERE / "artifact.toml").read_bytes(),
             "harness/run_tests.py": (HERE / "harness" / "run_tests.py").read_bytes()}
    for m in MODULES:
        files[f"harness/{m}"] = (SHARED / m).read_bytes()
    for f in DATA_FILES:
        files[f"data/{f}"] = (DATA / f).read_bytes()
    return files


def write_tree(root: Path, files: dict[str, bytes]) -> None:
    if root.exists():
        shutil.rmtree(root)
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def stale(root: Path, files: dict[str, bytes]) -> list[str]:
    if not root.exists():
        return ["<missing>"]
    present = {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()}
    return sorted({rel for rel, data in files.items() if not (root / rel).exists() or (root / rel).read_bytes() != data}
                  | (present - set(files)))


def main(check_only: bool = False) -> int:
    files = expected_files()
    write_tree(HERE, {k: v for k, v in files.items() if k.startswith(("harness/", "data/"))}) if False else None
    for m in MODULES:
        (HERE / "harness" / m).write_bytes(files[f"harness/{m}"])
    for f in DATA_FILES:
        (HERE / "data" / f).write_bytes(files[f"data/{f}"])
    problems = []
    for target in TARGETS:
        if not target.parent.exists():
            continue
        if check_only:
            problems += [f"{target.relative_to(REPO)}: {s}" for s in stale(target, files)]
        else:
            write_tree(target, files)
            print(f"synced {target.relative_to(REPO)} ({len(files)} files)")
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(check_only="--check" in sys.argv))
