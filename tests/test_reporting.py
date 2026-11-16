import json
from conftest import REPO
from webapp.reporting import scorecard, product, rubric
from webapp.store import PIPELINES


def test_rules_scorecard_explains_performance():
    data = {"exec-tests": {"score": .7143, "extracted_files": {"results.json": {
        "rows": [{"id": "sigma-recall", "result": False, "description": "11 of 39 malicious records"}],
        "details": {"sigma": {"union": {"precision": 1, "recall": .28},
                    "rules": [{"title": "Rule A", "source": "dns", "matched": 2, "tp": 2, "fp": 0, "precision": 1}],
                    "behaviors": {"beacon": {"detected": False, "recall": .2}}}}}}}}
    text = scorecard("Rules", data)
    assert "28.0%" in text and "100.0%" in text and "Rule A" in text
    assert "| Check | Result |" in text and "Behavior coverage" in text
    assert '"result":' not in text


def test_products_and_all_scenario_rubrics():
    assert "```json" not in product("triage", {"assessments": [{"alert_id": "ALT-1", "verdict": "true_positive", "rationale": "Evidence"}]})
    assert "## Summary" in product("report", {"summary": "Confirmed incident"})
    for config in PIPELINES.values():
        bundle = REPO / config["bundle"]
        steps = [s for path in (bundle / "tasks").glob("*.json") for s in json.loads(path.read_text())]
        text = rubric(steps, bundle)
        assert text.startswith("# Evaluation rubric")
        for step in steps:
            if step["type"] == "rubrics_verifier":
                assert all(c["criterion"] in text for c in step["criteria"])
