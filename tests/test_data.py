import importlib.util
import json

from conftest import DATA, REPO


def _build_exports():
    spec = importlib.util.spec_from_file_location("build_exports", DATA / "build_exports.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_ground_truth_ids_exist_and_export_is_current(incident, ground_truth, export):
    be = _build_exports()
    assert be.validate(incident, ground_truth) == []
    assert be.build_export(incident) == export, "run `uv run python soc-env/data/build_exports.py`"
    ids = [r["id"] for s in be.SOURCES for r in export[s]]
    assert len(ids) == len(set(ids)) == 57


def test_ground_truth_never_reaches_env_data(incident):
    assert "ground_truth" not in incident and "labels" not in incident
    text = (DATA / "incident.json").read_text()
    assert "malicious_records" not in text


def test_evidence_only_indicators_are_absent_from_logs(export, ground_truth):
    blob = json.dumps(export).lower()
    for ioc in ground_truth["expected_iocs"]["evidence_only"]:
        assert ioc["value"].lower() not in blob, ioc
