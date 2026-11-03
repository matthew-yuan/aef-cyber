"""v2 pipeline consistency: the host-side evidence facts mirror the ground truth, the artifact checks pass on an ideal
end state and fail cleanly on an empty one, and the build's weight contract holds."""
import importlib.util
import json

from conftest import DATA, REPO

V2 = REPO / "pipelines" / "v2-artifacts"


def _load(path):
    spec = importlib.util.spec_from_file_location(path.stem + "_" + path.parent.name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_evidence_facts_mirror_ground_truth(ground_truth):
    verify = _load(V2 / "soc-eval" / "artifacts" / "check_artifacts" / "verify.py")
    assert verify.EVIDENCE_FACTS == ground_truth["evidence_facts"]


def test_artifact_checks_on_ideal_and_empty_state(ground_truth):
    import hashlib
    verify = _load(V2 / "soc-eval" / "artifacts" / "check_artifacts" / "verify.py")
    golden = (REPO / "tests" / "fixtures" / "golden" / "hunt.py").read_text()
    rule = (REPO / "tests" / "fixtures" / "golden" / "sigma" / "c2_beacon_dns.yml").read_text()

    def art(kind, name, content, check):
        return {kind: {name: {"kind": kind, "name": name, "content": content, "check": check,
                              "sha256": hashlib.sha256(content.encode()).hexdigest()}}}

    def e(tool, outcome="ok", **args):
        return {"role": "analyst", "tool": tool, "args": args, "outcome": outcome}

    ev_ids = list(ground_truth["evidence_facts"])
    findings = [
        {"evidence_id": "EV-01", "finding": "Decoded cradle downloads odsh.exe from cdn-metrics.updatesvc.example and creates the OneDriveSyncHelper task via schtasks."},
        {"evidence_id": "EV-02", "finding": "Task OneDriveSyncHelper, author j.okafor, hidden, trigger PT5M, runs C:\\Users\\Public\\odsh.exe."},
        {"evidence_id": "EV-03", "finding": "odsh.exe connected to 203.0.113.154; bk_2026.7z still on disk; persistence is the scheduled task OneDriveSyncHelper; the OneDrive run key is legitimate."},
        {"evidence_id": "EV-04", "finding": "Service UpdateSvcHelper runs C:\\Windows\\Temp\\odsh.exe; uptime 37 days contradicts CHG-0398; connection to 203.0.113.154; svc_backup is local admin."},
        {"evidence_id": "EV-05", "finding": "Strings show updatesvc.example, /api/v1/upload and /api/v1/ping, the PDB path odsh.pdb under kestrel, user agent UpdateSvc/1.2."},
        {"evidence_id": "EV-06", "finding": "Credential lure to portal-benefits-login.example; unrelated to the intrusion, no follow-on."},
        {"evidence_id": "EV-07", "finding": "Config: fallback cdn-telemetry.updatesvc.example, beacon 300 s, mutex Global\\ODSH-7c1e, kill date 2026-12-31."},
    ]
    ideal = {
        "artifacts": {**art("hunt_script", "h", golden, {"ok": True}), **art("sigma_rule", "r", rule, {"valid": True}),
                      **art("ioc_extractor", "x", "def extract(data):\n    return {'indicators': []}\n", {"ok": True})},
        "artifact_attempts": [{"kind": "hunt_script", "outcome": "accepted"}, {"kind": "sigma_rule", "outcome": "rejected"}, {"kind": "sigma_rule", "outcome": "accepted"}],
        "evidence_ids": ev_ids,
        "evidence_report": {"verdict": "v", "summary": "s", "findings": findings, "indicators": ["cdn-telemetry.updatesvc.example"], "recommended_actions": []},
        "audit_log": [e("get_situation")] + [e("get_evidence", evidence_id=i) for i in ev_ids] + [e("submit_evidence_report", "accepted"),
                      e("get_log_schema"), e("submit_artifact", "accepted", kind="hunt_script")],
    }
    rows = verify.score(ideal)
    scored = [r for r in rows if r.get("weight")]
    assert [r["id"] for r in scored if not r["result"]] == []
    assert abs(sum(r["weight"] for r in scored) - 1.0) < 1e-9
    empty = [r for r in verify.score({}) if r.get("weight")]
    assert all(not r["result"] for r in empty)


def test_build_weights_and_task_shape():
    build = _load(V2 / "build.py")
    build.check_weights()
    task = json.loads((V2 / "soc-eval" / "tasks" / "soc_artifacts.json").read_text())
    by_id = {s["id"]: s for s in task}
    for step in ("judge-triage", "judge-report", "judge-evidence", "judge-artifacts"):
        assert abs(sum(c["weight"] for c in by_id[step]["criteria"]) - 1.0) < 1e-9
    assert by_id["scorebox-ctr"]["network"] == "none"
    assert by_id["exec-tests"]["user"] == "runner"
    assert all(by_id["exec-tests"]["env_vars"][k] in ("", "{}") for k in ("LITELLM_API_KEY", "ANTHROPIC_API_KEY", "LITELLM_EXTRA_HEADERS"))
    assert by_id["handoff"]["artifact_from_step_id"] == "snap-final"
    assert set(by_id["score"]["verifier_ids"]) == set(build.VERIFIERS)
    assert task == build.task(), "run `uv run python pipelines/v2-artifacts/build.py`"
