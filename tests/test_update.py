"""Stateful update/revision lifecycle and scoring controls: no-op, correct adaptation and regressions."""
import asyncio
from copy import deepcopy
import importlib.util
import json
import sys

import pytest

from conftest import REPO

V3 = REPO / "pipelines/v3-update"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


server = load("soc_update_server", REPO / "soc-env/soc/server.py")
grader = load("revision_grader", V3 / "soc-eval/artifacts/check_revision/verify.py")
UPDATE = json.loads((V3 / "update_01.json").read_text())
REPORT = {
    "summary": "Confirmed CINDER KESTREL intrusion.",
    "affected_hosts": ["WS-G3-014", "SRV-FILE-01", "SRV-WEB-02"],
    "compromised_accounts": ["j.okafor", "svc_backup"],
    "indicators": ["cdn-metrics.updatesvc.example", "203.0.113.154"],
    "attack_narrative": "PLANS OPORD archive exfiltrated via the original C2.",
    "containment_actions": [
        {"action": "isolate_host", "target": "WS-G3-014"},
        {"action": "isolate_host", "target": "SRV-WEB-02"},
        {"action": "reset_account", "target": "j.okafor"},
        {"action": "reset_account", "target": "svc_backup"},
        {"action": "block_indicator", "target": "cdn-metrics.updatesvc.example"},
    ],
    "escalation": "G-6 within 1 hour; CPT for data loss; G-3 for PLANS loss.",
    "evidence_preserved": ["Original workstation memory and disk"],
}


def revised_report():
    report = deepcopy(REPORT)
    report["affected_hosts"].append("WS-G1-007")
    report["indicators"] += ["cdn-telemetry.updatesvc.example", "203.0.113.155"]
    report["attack_narrative"] += " At 14:35Z SRV-WEB-02 reached WS-G1-007 as svc_backup; UpdateSvcHelper at 14:36Z, then fallback beacon. No new personnel-data exfiltration is established."
    report["containment_actions"] += [
        {"action": "isolate_host", "target": "WS-G1-007"},
        {"action": "block_indicator", "target": "cdn-telemetry.updatesvc.example"},
        {"action": "block_indicator", "target": "203.0.113.155"},
    ]
    report["evidence_preserved"].append("WS-G1-007 memory and disk")
    return report


def test_update_lifecycle_preserves_state_and_unlocks_one_revision(incident):
    async def scenario():
        env = server.CyberDefenseCellEnv()
        await env._add([server.DataPart(data=deepcopy(incident))])
        assert (await env.submit_incident_report(**deepcopy(REPORT)))["version"] == "INITIAL"
        original = await env.get_incident_report("INITIAL")
        assert "error" in await env.submit_incident_report(**deepcopy(REPORT))
        before_alerts, before_logs, before_audit = len(env.alerts), deepcopy(env.logs), len(env.audit_log)
        await env._add([server.DataPart(data=deepcopy(UPDATE))])
        assert len(env.alerts) == before_alerts + 1
        assert all(env.logs[k][:len(v)] == v for k, v in before_logs.items())
        assert len(env.audit_log) > before_audit
        assert (await env.list_injects())["current_version"] == "UPDATE-01"
        assert (await env.get_alert("ALT-1007"))["host"] == "WS-G1-007"
        assert (await env.get_intel("INT-26-032"))["indicators"]
        assert (await env.search_logs("all", host="WS-G1-007"))["matched"] >= 4
        revised = revised_report()
        assert (await env.submit_incident_report(**revised))["version"] == "UPDATE-01"
        revised["affected_hosts"].clear()  # A caller must not be able to mutate accepted history.
        assert "WS-G1-007" in env.report["affected_hosts"]
        assert await env.get_incident_report("INITIAL") == original
        assert "error" in await env.submit_incident_report(**deepcopy(REPORT))
        alerts, logs = deepcopy(env.alerts), deepcopy(env.logs)
        await env._add([server.DataPart(data=deepcopy(UPDATE))])  # Retry is idempotent.
        assert len(env.injects) == 1 and env.alerts == alerts and env.logs == logs
        changed = deepcopy(UPDATE)
        changed["metadata"]["current_time"] = "bad"
        with pytest.raises(ValueError, match="different content"):
            await env._add([server.DataPart(data=changed)])
        assert env.metadata["current_time"] == UPDATE["metadata"]["current_time"]
        for invalid in ({}, {"id": "INITIAL"}, {"id": " "}):
            with pytest.raises(ValueError):
                await env._add([server.DataPart(data={"inject": invalid, "alerts": [{"id": "BAD"}]})])
        assert env.alerts == alerts
        await env._reset()
        assert not env.reports and not env.injects and not env.audit_log
    asyncio.run(scenario())


def ideal_state():
    def event(tool, **args):
        return {"role": "analyst", "version": "UPDATE-01", "tool": tool, "outcome": "ok", "args": args}
    return {
        "reports": [{**deepcopy(REPORT), "version": "INITIAL"}, {**revised_report(), "version": "UPDATE-01"}],
        "audit_log": [event("list_injects"), event("get_incident_report", version="INITIAL"),
                      event("get_alert", alert_id="ALT-1007"), event("get_intel", intel_id="INT-26-032"),
                      event("get_asset", host="WS-G1-007"), event("get_playbook"),
                      {**event("search_logs", source="all", host="WS-G1-007"), "matched": 4},
                      {"role": "analyst", "version": "UPDATE-01", "tool": "submit_incident_report", "outcome": "accepted"}],
    }


def test_adaptation_grade_rejects_noop_and_detects_regressions():
    rows = grader.score(ideal_state())
    assert all(r["result"] for r in rows)
    assert sum(r["weight"] for r in rows if r["weight"] > 0) == pytest.approx(1)
    assert not any(r["result"] for r in grader.score({}) if r["weight"])
    noop = ideal_state()
    noop["reports"][1] = {**deepcopy(REPORT), "version": "UPDATE-01"}
    result = {r["id"]: r for r in grader.score(noop)}
    assert not result["revision-new-host"]["result"]
    assert not result["revision-fallback-ip"]["result"]
    regression = ideal_state()
    regression["reports"][1]["affected_hosts"] = ["WS-G1-007", "SRV-DC-01"]
    result = {r["id"]: r for r in grader.score(regression)}
    assert result["regression-hosts"]["regressed"]
    assert not result["revision-no-spurious-hosts"]["result"]
    late = ideal_state()
    late["audit_log"] = late["audit_log"][-1:] + late["audit_log"][:-1]
    assert not next(r for r in grader.score(late) if r["id"] == "revision-read-intel")["result"]


def test_v3_bundle_dag_and_baseline_contexts():
    build = load("v3_build", V3 / "build.py")
    steps = build.task()
    assert steps == json.loads((V3 / "soc-eval/tasks/soc_update.json").read_text())
    seen = set()
    for step in steps:
        assert step["id"] not in seen
        assert all(d["task_step_id"] in seen for d in step.get("depends_on", []))
        seen.add(step["id"])
    by_id = {s["id"]: s for s in steps}
    extension = (V3 / "prompts/analyst_update_system.md").read_text().strip()
    assert by_id["analyst"]["system_prompt"] == build.baseline.prompt("analyst_system") + "\n\n" + extension
    assert "soc_get_incident_report" in by_id["analyst"]["system_prompt"]
    assert by_id["revision"]["prompt"] == (V3 / "prompts/revision_user.md").read_text().strip()
    assert by_id["revision"]["context_id"] == by_id["triage"]["context_id"]
    assert {d["task_step_id"] for d in by_id["issue-update"]["depends_on"]} >= {"baseline-score", "snap-final", "snap-lab"}
    assert by_id["handoff"]["artifact_from_step_id"] == "snap-final"
    assert by_id["scorebox-ctr"]["network"] == "none"
    assert set(by_id["score"]["verifier_ids"]) == set(build.VERIFIERS)
    for name in ("check_facts", "check_artifacts", "scorebox_context"):
        source = build.V2 / "soc-eval/artifacts" / name
        for path in source.rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                assert path.read_bytes() == (V3 / "soc-eval/artifacts" / name / path.relative_to(source)).read_bytes()


def test_inject_script_preserves_data_plane_and_checks_rpc_errors(monkeypatch):
    script = load("incident_update_script", V3 / "soc-eval/artifacts/incident_update/run.py")
    sent = []

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"result": {}}

    def post(url, **kwargs):
        sent.append((url, kwargs["json"]))
        return Response()

    monkeypatch.setattr(script.httpx, "post", post)
    payload = {"env": {"mcp_url": "http://soc/mcp/"}, "args": {"update": UPDATE}}
    assert script.run(payload)["issued"] == "UPDATE-01"
    assert sent == [("http://soc/agentenv", {"jsonrpc": "2.0", "id": 1, "method": "data/add",
                                            "params": {"parts": [{"kind": "data", "data": UPDATE}]}})]
    monkeypatch.setattr(Response, "json", lambda self: {"error": "refused"})
    with pytest.raises(RuntimeError, match="refused"):
        script.run(payload)


def test_export_revision_keeps_baseline_and_reports_missing_revision(tmp_path, monkeypatch):
    build = load("export_v3_build", V3 / "build.py")
    monkeypatch.setitem(sys.modules, "build", build)
    exporter = load("update_exporter", V3 / "export_run.py")
    state = ideal_state()
    monkeypatch.setattr(exporter.base, "snapshot", lambda *args: state)
    record = {"metadata": {"verifications": {"soc-v2": {"score": 0.8}, "soc-v3": {"score": 0.9},
                                             "judge-revision": {"score": 1.0}}}}
    scorecard = tmp_path / "scorecard.md"
    scorecard.write_text("Original baseline scorecard")
    exporter.export_revision(record, tmp_path, {})
    assert "WS-G1-007" in (tmp_path / "revised_report.md").read_text()
    assert "Original baseline scorecard" in scorecard.read_text()
    assert "0.80" in scorecard.read_text() and "0.90" in scorecard.read_text()
    assert json.loads((tmp_path / "revised_state.json").read_text()) == state
    assert all(r["result"] for r in json.loads((tmp_path / "revision_checks.json").read_text()))
    state["reports"] = state["reports"][:1]
    exporter.export_revision(record, tmp_path, {})
    assert "Not submitted" in (tmp_path / "revised_report.md").read_text()
