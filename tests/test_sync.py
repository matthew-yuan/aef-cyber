"""The scorebox build context is copied into every bundle that ships it; the copies must match the source."""
import importlib.util

from conftest import REPO


def test_scorebox_copies_are_in_sync():
    spec = importlib.util.spec_from_file_location("sync", REPO / "soc-env" / "scorebox" / "sync.py")
    sync = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sync)
    files = sync.expected_files()
    for target in sync.TARGETS:
        if target.parent.exists():
            assert sync.stale(target, files) == [], f"run `uv run python soc-env/scorebox/sync.py` ({target})"


def test_ground_truth_ships_only_in_the_scorebox():
    hits = []
    for path in REPO.rglob("Dockerfile"):
        text = path.read_text()
        if "ground_truth" in text and "scorebox" not in str(path):
            hits.append(str(path))
    for path in list(REPO.glob("soc-env/soc/*")) + list(REPO.glob("soc-env/lab/*")):
        if path.is_file() and "ground_truth" in path.read_text(errors="ignore"):
            hits.append(str(path))
    assert hits == []
