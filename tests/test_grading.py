"""Critical compromise misses cannot be compensated by perfect judge scores."""
import importlib.util
import json

import pytest
from agent_env.task_step.task_steps.verifiers.scoring import ScoreAggregator, aggregate_score

from conftest import REPO
from grading import CRITICAL_CHECKS, assess
from regrade_runs import regrade


def load_facts():
    path = REPO / "pipelines/v1-triage/soc-eval/artifacts/check_facts/verify.py"
    spec = importlib.util.spec_from_file_location("critical_facts", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("total_weight", [12, 7, 9])
@pytest.mark.parametrize("missing", list(CRITICAL_CHECKS))
def test_missing_compromise_zeroes_real_framework_aggregate(total_weight, missing):
    facts = load_facts()
    assert facts.CRITICAL_CHECKS == CRITICAL_CHECKS
    rows = [{"id": key, "result": key != missing} for key in CRITICAL_CHECKS]
    # Even every positive criterion and every judge passing cannot compensate.
    aggregate_rows = [{"result": True, "weight": total_weight}]
    aggregate_rows += [{"result": row["result"], "weight": -facts.CRITICAL_PENALTY} for row in rows]
    assert aggregate_score(aggregate_rows, ScoreAggregator.WEIGHTED_AVERAGE) == 0
    assert assess(1.0, rows)["score"] == 0


def test_complete_compromise_scope_keeps_score():
    rows = [{"id": key, "result": True} for key in CRITICAL_CHECKS]
    assert assess(.87, rows)["score"] == .87
    assert assess(.87, rows)["critical_failure"] is False
    assert assess(.87, [])["critical_failure"] is True


def test_real_gpt4o_miss_fails_and_gpt5_complete_scope_passes():
    facts = load_facts()
    for run_id, expected in [("soc_triage-wl9guskc", 0), ("soc_triage-03y84uu4", 1)]:
        folder = REPO / "runs/v1" / run_id
        if not folder.exists():
            pytest.skip("Local historical exports are not present")
        state = json.loads((folder / "end_state.json").read_text())
        rows = facts.score(state)
        gates = [row for row in rows if row.get("critical")]
        assert len(gates) == 3
        assert assess(1, rows)["score"] == expected
        positive = [row for row in rows if row["weight"] > 0]
        assert len(positive) == 31


def test_historical_regrade_is_idempotent_and_preserves_scores(tmp_path):
    data = {"soc-v1": {"score": .55}, "facts": {"results": []}}
    (tmp_path / "verifications.json").write_text(json.dumps(data))
    (tmp_path / "scorecard.md").write_text("# Original scorecard\n\nStored 0.55\n")
    assert regrade(tmp_path)["score"] == 0
    first = (tmp_path / "scorecard.md").read_text()
    regrade(tmp_path)
    assert (tmp_path / "scorecard.md").read_text() == first
    assert "CRITICAL FAILURE" in first and "Stored 0.55" in first
    assert json.loads((tmp_path / "verifications.json").read_text()) == data
