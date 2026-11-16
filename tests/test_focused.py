"""Focused scenarios grade only their intended product and preserve container boundaries."""
import importlib.util
import json

from conftest import REPO

HERE = REPO / "pipelines/focused"


def load(path):
    spec = importlib.util.spec_from_file_location("focused_" + path.parent.name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_focused_dags_and_single_generation_phase():
    build = load(HERE / "build.py")
    for kind in ("triage", "report", "rules"):
        steps = build.focused(kind)
        assert steps == json.loads((HERE / kind / "tasks/task.json").read_text())
        assert len([s for s in steps if s["type"] == "prompt_agent"]) == 1
        seen = set()
        for step in steps:
            assert step["id"] not in seen
            assert all(d["task_step_id"] in seen for d in step.get("depends_on", []))
            seen.add(step["id"])
        if kind == "rules":
            nodes = {s["id"]: s for s in steps}
            assert nodes["scorebox-ctr"]["network"] == "none"
            assert nodes["exec-tests"]["command"].endswith("--only sigma")
            assert nodes["exec-tests"]["user"] == "runner"
            assert nodes["analyst"]["env_ids"] == ["soc", "lab"]


def test_focused_fact_weights_and_absent_product():
    for kind, prefixes in (("triage", ("triage-", "process-")), ("report", ("report-", "contain-"))):
        checks = load(HERE / kind / "artifacts/check_facts/verify.py")
        rows = checks.score({})
        assert rows and all(r["id"].startswith(prefixes) for r in rows)
        assert abs(sum(r["weight"] for r in rows) - 1) < 1e-9
        assert not any(r["result"] for r in rows)


def test_consolidated_infrastructure_checks_are_one_task():
    steps = json.loads((HERE / "infrastructure/tasks/task.json").read_text())
    seen = set()
    for step in steps:
        assert step["id"] not in seen
        assert all(d["task_step_id"] in seen for d in step.get("depends_on", []))
        seen.add(step["id"])
    assert not any(s["type"] == "prompt_agent" for s in steps)
    assert sum(s["type"] == "deploy_env" and s["env_id"] == "soc" for s in steps) == 1
    assert {s.get("verifier_id") for s in steps} >= {"soc-smoke", "lab-smoke", "exec-tests"}
