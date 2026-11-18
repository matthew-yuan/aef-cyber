"""Narrative claims, rejected calls, wrong hashes and late actions earn no action credit."""
import asyncio
from copy import deepcopy
import hashlib
import importlib.util
import json
import sys

import pytest
from agent_env.task_step.task_steps.verifiers.scoring import aggregate_score, ScoreAggregator
from conftest import REPO


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, REPO / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


evidence = load("pipelines/shared/action_evidence/run.py", "action_collector")
facts = load("pipelines/v1-triage/soc-eval/artifacts/check_facts/verify.py", "action_facts")
revision = load("pipelines/v3-update/soc-eval/artifacts/check_revision/verify.py", "action_revision")
sys.path.insert(0, str(REPO / "soc-env/shared"))
box = load("soc-env/scorebox/harness/run_tests.py", "action_scorebox")


def event(tool, outcome="ok", **args):
    return {"role": "analyst", "tool": tool, "outcome": outcome, "args": args, "version": "INITIAL"}


@pytest.mark.parametrize("phase", ["triage", "report", "evidence", "artifacts", "revision"])
def test_claimed_or_rejected_submission_is_not_accepted(phase):
    state = {"summary": "I submitted all products and tested everything", "audit_log": []}
    assert evidence.collect(state, phase)["accepted_submission"] is False
    state["audit_log"] = [event("submit_triage", "rejected"), event("submit_incident_report", "rejected"),
                          event("submit_evidence_report", "rejected"), event("submit_artifact", "rejected")]
    assert evidence.collect(state, phase)["accepted_submission"] is False


@pytest.mark.parametrize("phase,tool,product", [
    ("triage", "submit_triage", {"triage": {"assessments": [{"alert_id": "ALT-1001"}]}}),
    ("report", "submit_incident_report", {"report": {"summary": "Accepted report"}}),
    ("evidence", "submit_evidence_report", {"evidence_report": {"summary": "Accepted analysis"}}),
    ("artifacts", "submit_artifact", {"artifacts": {"sigma_rule": {"r": {"content": "YAML"}}}}),
    ("revision", "submit_incident_report", {"reports": [{"version": "UPDATE-01", "summary": "Revision"}]})])
def test_collector_recognizes_real_actions_and_bounds_reads(phase, tool, product):
    accepted = event(tool, "accepted")
    accepted["version"] = "UPDATE-01" if phase == "revision" else "INITIAL"
    state = {**product, "audit_log": [event("get_intel", "not_found"), event("get_playbook"), accepted,
                                    event("get_asset", host="TOO-LATE")]}
    if phase == "revision":
        for entry in state["audit_log"]:
            entry["version"] = "UPDATE-01"
    result = evidence.collect(state, phase)
    assert result["accepted_submission"] is True
    assert result["successful_read_tools"] == ["get_playbook"]
    assert result["failed_or_rejected_calls"] == 1


def test_absent_or_rejected_products_zero_aggregate_even_with_perfect_judge():
    for phase in ("triage", "report"):
        checks = load(f"pipelines/focused/{phase}/artifacts/check_facts/verify.py", "focused_action_" + phase)
        rows = checks.score({"summary": "I submitted it"})
        assert aggregate_score(rows + [{"score": 1, "weight": 1}], ScoreAggregator.WEIGHTED_AVERAGE) == 0


def test_failed_reads_other_roles_and_empty_searches_do_not_count():
    log = [event("get_intel", "not_found", intel_id="INT-26-031"),
           event("list_change_records", "error"), event("get_asset", "not_found", host="SRV-WEB-02"),
           {**event("search_logs", host="WS-G3-014"), "matched": 0}, event("submit_triage", "accepted")]
    rows = {r["id"]: r for r in facts.score({"triage": {"assessments": []}, "audit_log": log})}
    assert not rows["process-read-intel"]["result"]
    assert not rows["process-read-changes"]["result"]
    assert not rows["process-read-web02-asset"]["result"]
    assert not rows["process-searched-ws-logs"]["result"]
    for e in log:
        e["role"] = "grader"
    assert not any(r["result"] for r in facts.score({"audit_log": log}) if r["id"].startswith("process-"))


def artifact_fixture():
    code = "def hunt(data):\n    return []\n"
    digest = hashlib.sha256(code.encode()).hexdigest()
    state = {"artifacts": {"hunt_script": {"hunt": {"content": code, "submitted_at": "2026-11-16T12:00:10+00:00"}}},
             "audit_log": [event("submit_artifact", "accepted", kind="hunt_script", name="hunt", sha256=digest)]}
    lab = {"runs": [{"kind": "hunt_script", "sha256": digest, "executed": True, "outcome": "ok", "exit_code": 0,
                     "at": "2026-11-16T12:00:09+00:00"}]}
    return state, lab


def test_exact_hash_success_before_submission_required():
    state, lab = artifact_fixture()
    assert box.lab_testing(state, lab)[0]
    assert not box.lab_testing(state, {})[0]
    for changes in ({"sha256": "another-hash"}, {"executed": False}, {"exit_code": 1}, {"outcome": "timed_out"},
                    {"at": "2026-11-16T12:00:11+00:00"}, {"timed_out": True}):
        wrong = deepcopy(lab)
        wrong["runs"][0].update(changes)
        assert not box.lab_testing(state, wrong)[0]
    state["audit_log"][0]["outcome"] = "rejected"
    assert not box.lab_testing(state, lab)[0]


def test_revision_requires_accepted_submission_not_only_persisted_text():
    state = {"reports": [{"version": "INITIAL", "affected_hosts": ["WS-G3-014"]},
                         {"version": "UPDATE-01", "affected_hosts": ["WS-G1-007"]}],
             "audit_log": [dict(event("submit_incident_report", "rejected"), version="UPDATE-01")]}
    rows = revision.score(state)
    assert not any(r["result"] for r in rows if r["weight"] > 0)
    assert aggregate_score(rows + [{"score": 1, "weight": 8}], ScoreAggregator.WEIGHTED_AVERAGE) == 0


def test_evidence_paging_is_measured_in_actual_server_calls(incident):
    server = load("soc-env/soc/server.py", "paged_action_server")
    async def run():
        env = server.CyberDefenseCellEnv()
        await env._add([server.DataPart(data=deepcopy(incident))])
        response = await env.get_evidence("EV-01", offset=0, length=1)
        audit = env.audit_log[-1]
        assert audit["returned_chars"] == 1
        assert audit["total_chars"] == response["total_chars"]
        assert response["more"] is True
        await env.get_evidence("missing")
        assert env.audit_log[-1]["outcome"] == "not_found"
    asyncio.run(run())


def test_every_model_scenario_judge_receives_trajectory_and_trusted_receipts():
    from webapp.store import PIPELINES
    for pipeline, config in PIPELINES.items():
        if not config["model"]:
            continue
        steps = json.loads(next((REPO / config["bundle"] / "tasks").glob("*.json")).read_text())
        seen = {}
        for step in steps:
            assert all(d["task_step_id"] in seen for d in step.get("depends_on", []))
            if step["type"] == "rubrics_verifier":
                assert step["use_trajectory"] is True
                assert step.get("context_facts_for_judge")
                assert any(d["task_step_id"].startswith("evidence-") for d in step["depends_on"])
                assert "accepted" in step["grading_policy_prompt"].lower()
            seen[step["id"]] = step
        if pipeline in ("v2", "v3", "rules"):
            assert {d["task_step_id"] for d in seen["exec-tests"]["depends_on"]} == {"handoff", "handoff-lab"}
            assert "--require-lab" in seen["exec-tests"]["command"]
            judge = seen["judge-rules" if pipeline == "rules" else "judge-artifacts"]
            assert "exec-tests" in [d["task_step_id"] for d in judge["depends_on"]]


def test_actual_framework_judge_prompt_contains_calls_results_and_trusted_receipts(monkeypatch):
    from agent_env.task_step.context import TaskStepContext, PromptResponse
    from agent_env.task_step.task_steps.verifiers.rubrics_verifier import RubricsVerifierTaskStep
    config = json.loads((REPO / "pipelines/focused/triage/tasks/task.json").read_text())
    definition = next(s for s in config if s["type"] == "rubrics_verifier")
    judge = RubricsVerifierTaskStep.from_dict(definition)
    trajectory = json.dumps([
        {"type": "tool_call", "tool": "soc_submit_triage", "input": {"assessments": []},
         "output": {"error": "Triage incomplete: unique-error-evidence"}},
        {"type": "answer", "text": "I successfully submitted all triage assessments."}])
    monkeypatch.setattr(judge, "_read_trajectory_text", lambda uri: trajectory)
    captured = []

    async def capture(**kwargs):
        prompt = kwargs["eval_prompt"]
        captured.append(prompt)
        assert "unique-error-evidence" in prompt
        assert "soc_submit_triage" in prompt
        assert "Accepted submission receipt" in prompt and "false" in prompt
        assert "No accepted product submission means score every product criterion 0" in prompt
        return ([{"id": f"c{i}", "score": 0, "result": False, "weight": 1/4}
                 for i in (1, 2, 3, 4)], [], [], None)

    monkeypatch.setattr(judge, "_run_judge_with_output_retries", capture)
    context = TaskStepContext(prompt_responses=[PromptResponse(prompt_id="triage", response="I submitted everything",
        agent_trajectory_object_url="file:///trusted-test-trajectory.json")],
        metadata={"script_results": {"evidence-triage": evidence.collect({}, "triage")}})
    asyncio.run(judge.execute(context))
    assert captured
    assert context.metadata["verifications"]["judge-triage"]["score"] == 0


def test_evidence_page_gaps_and_late_reads_fail(ground_truth):
    checks = load("pipelines/v2-artifacts/soc-eval/artifacts/check_artifacts/verify.py", "paged_checks")
    state = {"evidence_ids": ["EV-01"], "audit_log": [
        {**event("get_evidence", evidence_id="EV-01"), "offset": 0, "returned_chars": 5, "total_chars": 10},
        event("submit_evidence_report", "accepted")], "evidence_report": {"findings": []}}
    def complete():
        return next(r["result"] for r in checks.score(state) if r["id"] == "process-read-all-evidence")
    assert not complete()
    page = {**event("get_evidence", evidence_id="EV-01"), "offset": 5, "returned_chars": 5, "total_chars": 10}
    state["audit_log"].append(page)
    assert not complete()  # reading after the accepted report cannot earn credit
    state["audit_log"].insert(1, state["audit_log"].pop())
    assert complete()


def test_scorebox_reward_deducts_real_lab_mismatch(tmp_path, monkeypatch):
    state, lab = artifact_fixture()
    handoff = tmp_path / "handoff"
    (handoff / "soc").mkdir(parents=True)
    (handoff / "lab").mkdir()
    (handoff / "soc/state.json").write_text(json.dumps(state))
    (handoff / "lab/state.json").write_text(json.dumps({**lab, "rule_tests": []}))
    data = tmp_path / "data"
    data.mkdir()
    for name in ("ground_truth.json", "log_export.json"):
        (data / name).write_text("{}")
    monkeypatch.setattr(box, "sandbox_checks", lambda: [{"id": "test-isolation", "result": True}])
    monkeypatch.setattr(box, "write_artifacts", lambda *args: {"sigma_rule": {}, "hunt_script": {}, "ioc_extractor": {}})
    monkeypatch.setattr(box, "grade_sigma", lambda *args: ([{"id": "functional", "weight": .35, "result": True}], {}))
    out = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", ["run_tests.py", "--handoff", str(handoff), "--data", str(data),
                                    "--out", str(out), "--work", str(tmp_path / "work"), "--only", "sigma", "--require-lab"])
    # Rules-only expects Sigma fixtures, so no submitted Sigma rule means no lab credit.
    assert box.main() == 0
    assert float((out / "reward.txt").read_text()) == .8
    rule = "title: rule\ndetection: {}\n"
    digest = hashlib.sha256(rule.encode()).hexdigest()
    state["artifacts"] = {"sigma_rule": {"rule": {"content": rule, "submitted_at": "2026-11-16T12:00:10+00:00"}}}
    state["audit_log"] = [event("submit_artifact", "accepted", kind="sigma_rule", name="rule", sha256=digest)]
    lab["rule_tests"] = [{"sha256": digest, "valid": True, "at": "2026-11-16T12:00:09+00:00"}]
    (handoff / "soc/state.json").write_text(json.dumps(state))
    (handoff / "lab/state.json").write_text(json.dumps(lab))
    box.main()
    assert float((out / "reward.txt").read_text()) == 1


def test_collector_fails_closed_on_rpc_error(monkeypatch):
    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"error": {"message": "denied"}}
    monkeypatch.setattr(evidence.httpx, "post", lambda *args, **kwargs: Response())
    with pytest.raises(RuntimeError, match="data/get failed"):
        evidence.run({"env": {"mcp_url": "http://soc/mcp"}, "args": {"phase": "triage"}})
