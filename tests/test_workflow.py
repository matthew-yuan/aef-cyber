"""Graph API preserves AEF fan-out, fan-in, and implicit sequential dependencies."""
import json

from webapp import workflow as graphs


def test_actual_evaluation_graphs():
    graph = graphs.workflow("v3")
    assert len(graph) == 37
    nodes = {s["id"]: s for s in graph}
    assert nodes["soc"]["depends_on"] == []
    assert nodes["lab"]["depends_on"] == []
    assert set(nodes["triage"]["depends_on"]) == {"seed", "seed-lab", "analyst"}
    assert nodes["judge-triage"]["depends_on"] == ["triage", "evidence-triage"]
    assert set(nodes["handoff"]["depends_on"]) == {"snap-final", "scorebox-ctr"}
    assert "snap-revised" in nodes["score"]["depends_on"]
    seen = set()
    for node in graph:
        assert set(node["depends_on"]) <= seen
        seen.add(node["id"])


def test_implicit_dependencies_are_all_prior_steps(tmp_path, monkeypatch):
    tasks = tmp_path / "tasks"
    tasks.mkdir()
    (tasks / "task.json").write_text(json.dumps([
        {"id": "a", "type": "deploy_env", "depends_on": []},
        {"id": "b", "type": "deploy_env", "depends_on": []},
        {"id": "c", "type": "snapshot_env"},
    ]))
    monkeypatch.setattr(graphs, "ROOT", tmp_path)
    monkeypatch.setattr(graphs, "PIPELINES", {"test": {"bundle": "."}})
    assert graphs.workflow("test")[-1]["depends_on"] == ["a", "b"]
