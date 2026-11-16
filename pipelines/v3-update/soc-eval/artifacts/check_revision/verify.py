"""Parse-only UPDATE-01 adaptation checks. Baseline grading remains a separate pre-update measurement."""
import json
import re

import httpx


def has(value, pattern):
    return bool(re.search(pattern, json.dumps(value, ensure_ascii=False), re.I))


def score(state):
    reports = state.get("reports") or []
    original = next((r for r in reports if r.get("version") == "INITIAL"), {})
    revised = next((r for r in reports if r.get("version") == "UPDATE-01"), {})
    log = [e for e in state.get("audit_log", []) if e.get("role") == "analyst"]
    end = next((i for i, e in enumerate(log) if e.get("tool") == "submit_incident_report"
                and e.get("outcome") == "accepted" and e.get("version") == "UPDATE-01"), None)
    reads = [e for e in log[:end] if e.get("version") == "UPDATE-01"] if end is not None else []

    def read(tool, **args):
        return any(e.get("tool") == tool and e.get("outcome") == "ok"
                   and all(str(e.get("args", {}).get(k, "")).upper() == str(v).upper() for k, v in args.items()) for e in reads)

    actions = revised.get("containment_actions") or []

    def action(kind, target):
        return any(has(a.get("action", ""), kind) and has(a.get("target", ""), target)
                   for a in actions if isinstance(a, dict))

    hosts = revised.get("affected_hosts") or []
    indicators = revised.get("indicators") or []
    narrative = [revised.get("summary", ""), revised.get("attack_narrative", "")]
    forbidden_hosts = r"WS-?G6-?021|SRV-?VSCAN-?01|WS-?MED-?003|SRV-?DC-?01"
    checks = [
        ("revision-submitted", "Original and UPDATE-01 reports are both retained", bool(original) and bool(revised)),
        ("revision-new-host", "WS-G1-007 is added to affected hosts", has(hosts, r"WS-?G1-?007")),
        ("revision-account", "svc_backup remains compromised", has(revised.get("compromised_accounts", []), r"svc_backup")),
        ("revision-fallback-domain", "Fallback C2 domain is included", has(indicators, r"cdn-telemetry\.updatesvc\.example")),
        ("revision-fallback-ip", "New C2 address is included", has(indicators, r"203\.0\.113\.155")),
        ("revision-lateral-movement", "Narrative links WEB-02 to G1-007 through the service account and service",
         all(has(narrative, p) for p in (r"SRV-?WEB-?02", r"WS-?G1-?007", r"svc_backup", r"UpdateSvcHelper", r"14:3[56]"))),
        ("revision-isolate", "Containment isolates the newly compromised workstation", action(r"isolat", r"WS-?G1-?007")),
        ("revision-block-domain", "Containment blocks the fallback domain", action(r"block", r"cdn-telemetry\.updatesvc\.example")),
        ("revision-block-ip", "Containment blocks the fallback address", action(r"block", r"203\.0\.113\.155")),
        ("revision-preserve", "Evidence preservation covers the new workstation", has(revised.get("evidence_preserved", []), r"WS-?G1-?007")),
        ("revision-escalate", "Expanded scope is escalated to G-6 and CPT",
         has(revised.get("escalation", ""), r"G-?6") and has(revised.get("escalation", ""), r"CPT|Cyber Protection")),
        ("revision-no-spurious-hosts", "No new compromise asserted for benign hosts or the domain controller", bool(revised) and not has(hosts, forbidden_hosts)),
        ("revision-no-spurious-containment", "Benign hosts and domain controller are not isolated",
         bool(revised) and not action(r"isolat|reimage|power|offline|shut", forbidden_hosts)),
        ("revision-crown-approval", "File-server isolation still requires G-6 approval",
         bool(revised) and all(has(a.get("rationale", ""), r"approv") and has(a.get("rationale", ""), r"G-?6")
                               for a in actions if isinstance(a, dict) and has(a.get("action", ""), r"isolat|reimage|offline|shut|power")
                               and has(a.get("target", ""), r"SRV-?FILE-?01"))),
        ("retain-original-block", "Original C2 blocking remains", action(r"block", r"cdn-metrics\.updatesvc\.example|203\.0\.113\.154")),
        ("retain-plans-loss", "Original confirmed PLANS exfiltration remains in the narrative",
         has(narrative, r"PLANS|OPORD") and has(narrative, r"exfil|upload")),
        ("retain-g3-escalation", "G-3 escalation for the original PLANS compromise remains", has(revised.get("escalation", ""), r"G-?3")),
        ("revision-read-update", "Update was read before revision", read("list_injects")),
        ("revision-read-original", "INITIAL report was read before revision", read("get_incident_report", version="INITIAL")),
        ("revision-read-alert", "New alert was read before revision", read("get_alert", alert_id="ALT-1007")),
        ("revision-read-intel", "New CPT bulletin was read before revision", read("get_intel", intel_id="INT-26-032")),
        ("revision-read-asset", "Newly affected asset was read before revision", read("get_asset", host="WS-G1-007")),
        ("revision-read-playbook", "Containment playbook was re-read", read("get_playbook")),
        ("revision-search-new-logs", "New workstation logs were searched before revision",
         any(e.get("tool") == "search_logs" and e.get("outcome") == "ok" and e.get("matched", 0) > 0
             and has(e.get("args", {}), r"WS-?G1-?007|192\.0\.2\.7") for e in reads)),
    ]
    # Retention checks assess the final product; regression metadata distinguishes loss from an initial miss.
    retained = [
        ("hosts", "affected_hosts", r"WS-?G3-?014", "Original workstation scope"),
        ("file", "affected_hosts", r"SRV-?FILE-?01", "Original file-server scope"),
        ("web", "affected_hosts", r"SRV-?WEB-?02", "Original web-server scope"),
        ("okafor", "compromised_accounts", r"j\.okafor", "Original compromised user"),
        ("c2", "indicators", r"cdn-metrics\.updatesvc\.example", "Original C2 domain"),
        ("exfil", "attack_narrative", r"PLANS|OPORD", "Original PLANS data loss narrative"),
    ]
    for key, field, pattern, title in retained:
        checks.append((f"retain-{key}", title + " remains in revision", has(revised.get(field, []), pattern)))
    for key, kind, target in [("ws-isolation", r"isolat", r"WS-?G3-?014"),
                              ("web-isolation", r"isolat|remove|offline|shut|power", r"SRV-?WEB-?02"),
                              ("okafor-reset", r"reset|disable", r"j\.okafor"),
                              ("backup-reset", r"reset|disable", r"svc_backup")]:
        checks.append((f"retain-{key}", "Original containment remains: " + key, action(kind, target)))
    rows = [{"id": k, "description": d, "result": end is not None and bool(revised) and bool(ok), "weight": 1 / len(checks)} for k, d, ok in checks]
    rows.append({"id": "revision-action-required", "result": end is not None and bool(revised), "weight": -12.0,
                 "description": "UPDATE-01 revision was accepted, not merely claimed", "action_gate": True})
    for key, field, pattern, title in retained:
        before, after = has(original.get(field, []), pattern), has(revised.get(field, []), pattern)
        rows.append({"id": f"regression-{key}", "description": title, "result": bool(revised) and not (before and not after),
                     "weight": 0, "in_original": before, "in_revision": after, "regressed": before and not after})
    rows.append({"id": "revision-tool-calls", "description": "Analyst calls after update and before accepted revision",
                 "result": bool(revised), "weight": 0, "count": len(reads), "tools": [e["tool"] for e in reads]})
    return rows


async def verify(mcp_url):
    base = mcp_url.removesuffix("/").removesuffix("/mcp")
    async with httpx.AsyncClient() as client:
        response = await client.post(f"{base}/agentenv", timeout=30, json={
            "jsonrpc": "2.0", "id": 1, "method": "data/get", "params": {}})
    response.raise_for_status()
    reply = response.json()
    if "error" in reply:
        raise RuntimeError(reply["error"])
    state = next((p["data"] for p in reply.get("result", {}).get("parts", []) if p.get("data")), {})
    return score(state)
