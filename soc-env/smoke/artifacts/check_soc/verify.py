"""Smoke test for the soc env: calls every tool over MCP, submits a triage and a report, then reads data/get.

It checks the env's behaviour, not the incident's content, so it still passes after the sample
incident.json is swapped for another one in the same schema.
"""
import json

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

EXPECTED_TOOLS = {
    "soc_get_situation", "soc_list_alerts", "soc_get_alert", "soc_list_assets", "soc_get_asset", "soc_search_logs",
    "soc_list_intel", "soc_get_intel", "soc_list_change_records", "soc_get_playbook", "soc_list_injects",
    "soc_submit_triage", "soc_submit_incident_report",
    "soc_get_log_schema", "soc_list_evidence", "soc_get_evidence", "soc_submit_artifact", "soc_submit_evidence_report",
}
HUNT = 'def hunt(data):\n    return [{"source": "dns", "id": r["id"], "behavior": "smoke", "host": r.get("host", ""), "reason": "smoke"} for r in data.get("dns", [])]\n'
BANNED = "import socket\ndef hunt(data):\n    socket.create_connection(('203.0.113.1', 80))\n    return []\n"
RULE = "title: smoke rule\nlogsource: {service: dns}\ndetection:\n  sel:\n    query|endswith: .example\n  condition: sel\n"
BAD_RULE = "title: bad\nlogsource: {service: dns}\ndetection:\n  sel:\n    query|re: '.*'\n  condition: sel\n"
EVIDENCE_REPORT = {"evidence_ids": ["SMOKE"], "verdict": "smoke", "summary": "smoke", "findings": [], "indicators": [], "recommended_actions": []}
REPORT = {
    "summary": "Smoke test report.",
    "affected_hosts": ["SMOKE-HOST"],
    "compromised_accounts": ["smoke.user"],
    "indicators": ["smoke.example"],
    "attack_narrative": "At T+0 a smoke test happened.",
    "containment_actions": [{"action": "isolate_host", "target": "SMOKE-HOST", "rationale": "smoke"}],
    "escalation": "Tell the smoke-test lead.",
    "evidence_preserved": ["memory capture of SMOKE-HOST"],
}


async def _call(session, name, args=None):
    result = await session.call_tool(name, args or {})
    text = "".join(getattr(part, "text", "") for part in result.content)
    try:
        body = json.loads(text)
    except json.JSONDecodeError:
        body = {"_text": text}
    return result.isError, body


def _row(id, ok, description):
    return {"id": id, "result": bool(ok), "description": description}


async def verify(mcp_url):
    rows = []
    async with streamable_http_client(mcp_url) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = {t.name for t in (await session.list_tools()).tools}
            missing = EXPECTED_TOOLS - tools
            rows.append(_row("tools-listed", not missing, f"missing tools: {sorted(missing)}" if missing else f"{len(tools)} tools"))

            err, body = await _call(session, "soc_get_situation")
            incident = body.get("metadata", {}).get("incident_id")
            rows.append(_row("data-loaded", not err and incident and body.get("organization", {}).get("name"), f"incident {incident!r}"))

            _, body = await _call(session, "soc_list_alerts")
            alert_ids = [a["id"] for a in body.get("alerts", [])]
            _, first = await _call(session, "soc_get_alert", {"alert_id": alert_ids[0].lower()}) if alert_ids else (None, {})
            _, unknown = await _call(session, "soc_get_alert", {"alert_id": "ALT-0000"})
            rows.append(_row("alerts", alert_ids and first.get("description") and "error" in unknown,
                             f"{len(alert_ids)} alerts; first read by lower-cased id; ALT-0000 refused"))

            _, body = await _call(session, "soc_list_assets")
            assets = body.get("assets", [])
            ok = bool(assets)
            for asset in assets:
                _, by_name = await _call(session, "soc_get_asset", {"host": asset["hostname"].lower()})
                _, by_ip = await _call(session, "soc_get_asset", {"host": asset["ip"]})
                ok = ok and by_name.get("hostname") == asset["hostname"] and by_ip.get("hostname") == asset["hostname"]
            _, unknown = await _call(session, "soc_get_asset", {"host": "NO-SUCH-HOST"})
            rows.append(_row("assets", ok and "error" in unknown, f"{len(assets)} assets read by name and ip; unknown host refused"))

            counts = {}
            for source in ("auth", "dns", "proxy", "endpoint"):
                _, found = await _call(session, "soc_search_logs", {"source": source})
                counts[source] = found.get("matched", 0)
            _, everything = await _call(session, "soc_search_logs", {"source": "all", "limit": 200})
            host = assets[0]["hostname"] if assets else ""
            _, by_host = await _call(session, "soc_search_logs", {"source": "all", "host": host.lower()})
            _, limited = await _call(session, "soc_search_logs", {"source": "all", "host": host, "limit": 3})
            _, by_text = await _call(session, "soc_search_logs", {"source": "all", "contains": "zzz-no-such-text"})
            _, bad = await _call(session, "soc_search_logs", {"source": "syslog"})
            rows.append(_row("logs", all(counts.values()) and everything.get("matched") == sum(counts.values())
                             and 0 < by_host.get("matched", 0) < everything.get("matched", 0)
                             and limited.get("returned") == min(3, by_host.get("matched", 0)) and by_text.get("matched") == 0 and "error" in bad,
                             f"{counts}; all={everything.get('matched')}; host filter {host!r} -> {by_host.get('matched')} (limit 3 -> {limited.get('returned')}); "
                             f"no-match text -> {by_text.get('matched')}; unknown source refused"))

            _, body = await _call(session, "soc_list_intel")
            intel_ids = [i["id"] for i in body.get("intel", [])]
            _, bulletin = await _call(session, "soc_get_intel", {"intel_id": intel_ids[-1]}) if intel_ids else (None, {})
            _, unknown = await _call(session, "soc_get_intel", {"intel_id": "INT-00-000"})
            rows.append(_row("intel", intel_ids and bulletin.get("indicators") and "error" in unknown, f"{intel_ids}; unknown bulletin refused"))

            _, changes = await _call(session, "soc_list_change_records")
            rows.append(_row("change-records", changes.get("change_records"), f"{len(changes.get('change_records', []))} records"))

            _, playbook = await _call(session, "soc_get_playbook")
            rows.append(_row("playbook", playbook.get("rules") and playbook.get("containment_options"), f"{len(playbook.get('rules', []))} rules"))

            _, injects = await _call(session, "soc_list_injects")
            rows.append(_row("injects-empty", injects.get("injects") == [], f"injects: {injects}"))

            _, schema = await _call(session, "soc_get_log_schema")
            rows.append(_row("log-schema", set(schema.get("sources", {})) == set(counts) and "hunt_script" in schema.get("contract", {})
                             and schema.get("contract", {}).get("allowed_imports"),
                             f"schema sources {sorted(schema.get('sources', {}))}; contract keys {sorted(schema.get('contract', {}))}"))

            _, ev = await _call(session, "soc_list_evidence")
            items = ev.get("evidence", [])
            first = items[0]["id"] if items else ""
            _, page1 = await _call(session, "soc_get_evidence", {"evidence_id": first.lower(), "offset": 0, "length": 50})
            _, page2 = await _call(session, "soc_get_evidence", {"evidence_id": first, "offset": 50, "length": 50})
            _, unknown = await _call(session, "soc_get_evidence", {"evidence_id": "EV-99"})
            rows.append(_row("evidence", items and len(page1.get("content", "")) == 50 and page1.get("more") is True
                             and page2.get("offset") == 50 and page1["content"] != page2.get("content") and "error" in unknown,
                             f"{len(items)} items; {first} paged by 50 chars; unknown id refused"))

            _, banned = await _call(session, "soc_submit_artifact", {"kind": "hunt_script", "name": "banned", "content": BANNED})
            _, badrule = await _call(session, "soc_submit_artifact", {"kind": "sigma_rule", "name": "bad", "content": BAD_RULE})
            _, badkind = await _call(session, "soc_submit_artifact", {"kind": "binary", "name": "x", "content": "x"})
            _, badname = await _call(session, "soc_submit_artifact", {"kind": "hunt_script", "name": "Bad Name!", "content": HUNT})
            rows.append(_row("artifact-rejects", all(r.get("status") == "rejected" for r in (banned, badrule, badkind, badname))
                             and any("socket" in e for e in banned.get("errors", [])),
                             f"banned: {banned.get('errors')}; bad rule: {badrule.get('errors')}; bad kind/name rejected"))
            _, hunt_ok = await _call(session, "soc_submit_artifact", {"kind": "hunt_script", "name": "smoke", "content": HUNT})
            _, dup = await _call(session, "soc_submit_artifact", {"kind": "hunt_script", "name": "smoke", "content": HUNT})
            _, rule_ok = await _call(session, "soc_submit_artifact", {"kind": "sigma_rule", "name": "smoke", "content": RULE})
            rows.append(_row("artifact-accepts", hunt_ok.get("status") == "accepted" and hunt_ok.get("sha256") and "content" not in hunt_ok
                             and dup.get("status") == "rejected" and rule_ok.get("status") == "accepted" and rule_ok.get("check", {}).get("source") == "dns",
                             f"hunt: {hunt_ok.get('status')}; duplicate: {dup.get('status')}; rule: {rule_ok.get('status')} ({rule_ok.get('check')})"))

            _, empty_ev = await _call(session, "soc_submit_evidence_report", EVIDENCE_REPORT)
            good_ev = {**EVIDENCE_REPORT, "evidence_ids": [first], "findings": [{"evidence_id": first, "finding": "smoke", "confidence": "low"}]}
            _, ev_ok = await _call(session, "soc_submit_evidence_report", good_ev)
            _, ev_again = await _call(session, "soc_submit_evidence_report", good_ev)
            rows.append(_row("evidence-report-once", "error" in empty_ev and ev_ok.get("status") == "submitted" and "error" in ev_again,
                             f"empty refused: {'error' in empty_ev}; first: {ev_ok}; second refused: {'error' in ev_again}"))

            full = [{"alert_id": a, "verdict": "needs_more_info", "rationale": "smoke", "related_hosts": []} for a in alert_ids]
            _, empty = await _call(session, "soc_submit_triage", {"assessments": []})
            _, partial = await _call(session, "soc_submit_triage", {"assessments": full[:1]})
            _, badverdict = await _call(session, "soc_submit_triage", {"assessments": [{**full[0], "verdict": "maybe"}] + full[1:]})
            rows.append(_row("triage-rejects-incomplete", "error" in empty and "error" in partial and "error" in badverdict,
                             f"empty: {'error' in empty}; partial: {'error' in partial}; bad verdict: {'error' in badverdict}"))
            _, accepted = await _call(session, "soc_submit_triage", {"assessments": full})
            _, again = await _call(session, "soc_submit_triage", {"assessments": full})
            rows.append(_row("triage-once", accepted.get("status") == "submitted" and "error" in again, f"first: {accepted}; second refused: {'error' in again}"))

            _, empty = await _call(session, "soc_submit_incident_report", {**REPORT, "summary": "  "})
            _, badaction = await _call(session, "soc_submit_incident_report", {**REPORT, "containment_actions": [{"action": "isolate_host"}]})
            rows.append(_row("report-rejects-incomplete", "error" in empty and "error" in badaction, f"empty summary: {empty}; action without target: {'error' in badaction}"))
            _, first = await _call(session, "soc_submit_incident_report", REPORT)
            _, second = await _call(session, "soc_submit_incident_report", REPORT)
            rows.append(_row("report-once", first.get("status") == "submitted" and first.get("version") == "INITIAL" and "error" in second,
                             f"first: {first}; second refused: {'error' in second}"))

    # The end state a verifier or snapshot_env reads: data/get on the env's data plane, beside /mcp.
    base_url = mcp_url.removesuffix("/").removesuffix("/mcp")
    async with httpx.AsyncClient() as client:
        response = await client.post(f"{base_url}/agentenv", json={"jsonrpc": "2.0", "id": 1, "method": "data/get", "params": {}}, timeout=30)
    parts = response.json().get("result", {}).get("parts", [])
    state = next((p.get("data") for p in parts if p.get("data")), {})
    triage = state.get("triage") or {}
    report = state.get("report") or {}
    outcomes = [(e["tool"], e["outcome"]) for e in state.get("audit_log", []) if e["tool"] in ("submit_triage", "submit_incident_report")]
    artifacts = state.get("artifacts") or {}
    attempts = [(a["kind"], a["outcome"]) for a in state.get("artifact_attempts", [])]
    artifact_audit = [e for e in state.get("audit_log", []) if e["tool"] == "submit_artifact"]
    expected = [("submit_triage", "rejected")] * 3 + [("submit_triage", "accepted"), ("submit_triage", "rejected"),
                ("submit_incident_report", "rejected")] * 1 + [("submit_incident_report", "rejected"),
                ("submit_incident_report", "accepted"), ("submit_incident_report", "rejected")]
    rows.append(_row("artifacts-stored", artifacts.get("hunt_script", {}).get("smoke", {}).get("content") == HUNT
                     and "smoke" in artifacts.get("sigma_rule", {}) and attempts.count(("hunt_script", "accepted")) == 1
                     and all("content" not in e.get("args", {}) for e in artifact_audit) and (state.get("evidence_report") or {}).get("verdict") == "smoke",
                     f"artifacts {{k: list(v) for k, v in artifacts.items()}}; attempts {attempts}; audit args carry no content"))
    rows.append(_row("data-get", len(triage.get("assessments", [])) == len(alert_ids) and report.get("summary") == REPORT["summary"]
                     and outcomes == expected,
                     f"triage stored: {bool(triage)}; report stored: {bool(report)}; submit audit {outcomes}; {len(state.get('audit_log', []))} audit entries"))
    return rows
