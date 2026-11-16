"""Code checks for the v1 triage eval, read from the soc env's end state.

Scored rows (their weights sum to FACTS_WEIGHT_TOTAL, the judge criteria's total, so code checks and
the judge count equally in the aggregate):
  triage-*   did the analyst give each alert the right verdict, link the intrusion's alerts and keep
             the unrelated one apart?
  report-*   does the incident report name the affected hosts, accounts, indicators and the data loss?
  contain-*  are the containment actions right and do they respect the playbook?
  process-*  did the analyst read the records it needed before submitting?
Unweighted rows: trace-* (per trap: missed, understood but not applied, applied, ...).

The checks are written for the sample incident (INC-26-1107); another incident needs its own
patterns here. Text checks are keyword heuristics; the judge covers wording they can't.
"""
import json
import re

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

FACTS_WEIGHT_TOTAL = 1.0  # v2: every verifier totals 1.0 (generated from v1 by build.py)

# The largest pipeline has total positive weight 12 (v1). One failed gate must
# outweigh every other earned point, including judge scores, in v1/v2/v3.
CRITICAL_PENALTY = 12.0
CRITICAL_CHECKS = {
    "report-host-ws-g3-014": "Missed confirmed compromise of WS-G3-014",
    "report-host-srv-file-01": "Missed confirmed compromise of SRV-FILE-01",
    "report-host-srv-web-02": "Missed confirmed compromise of SRV-WEB-02",
}

ALERTS = ["ALT-1001", "ALT-1002", "ALT-1003", "ALT-1004", "ALT-1005", "ALT-1006"]
C2_DOMAIN = r"cdn-metrics\.updatesvc\.example|updatesvc\.example"
C2_IP = r"203\.0\.113\.154"
VPN_SRC = r"203\.0\.113\.77"
WS = r"WS-?G3-?014|192\.0\.2\.14\b"
WEB02 = r"SRV-?WEB-?02|198\.51\.100\.22\b"
FILE01 = r"SRV-?FILE-?01|198\.51\.100\.10\b"
CROWN = r"SRV-?FILE-?01|SRV-?DC-?01|198\.51\.100\.(10|5)\b"
BENIGN = r"WS-?G6-?021|SRV-?VSCAN-?01|192\.0\.2\.21\b|198\.51\.100\.40\b"


def text_of(value) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def has(text: str, *patterns: str) -> bool:
    return all(re.search(p, text, re.IGNORECASE) for p in patterns)


def norm(value) -> str:
    return "".join(ch for ch in str(value).upper() if ch.isalnum())


def baseline_score(state: dict) -> list[dict]:
    """The check rows for one end state (data/get): scored rows, then unweighted trace rows."""
    triage = state.get("triage") or {}
    report = next((r for r in state.get("reports", []) if r.get("version") == "INITIAL"), None) or state.get("report") or {}
    log = state.get("audit_log") or []

    by_alert = {}
    for item in triage.get("assessments") or []:
        if isinstance(item, dict):
            by_alert[norm(item.get("alert_id", ""))] = item

    def verdict(alert_id: str) -> str:
        return str(by_alert.get(norm(alert_id), {}).get("verdict") or "")

    def assessment_text(alert_id: str) -> str:
        return text_of(by_alert.get(norm(alert_id), {}))

    hosts = text_of(report.get("affected_hosts") or [])
    accounts = text_of(report.get("compromised_accounts") or [])
    iocs = text_of(report.get("indicators") or [])
    narrative = text_of(report.get("summary") or "") + "\n" + text_of(report.get("attack_narrative") or "")
    actions = [a for a in report.get("containment_actions") or [] if isinstance(a, dict)]
    escalation = text_of(report.get("escalation") or "")
    evidence = report.get("evidence_preserved") or []
    report_text = text_of(report)

    def action(kind: str, target: str) -> bool:
        return any(has(text_of(a.get("action", "")), kind) and has(text_of(a.get("target", "")) + " " + text_of(a.get("rationale", "")), target)
                   for a in actions)

    crown_actions = [a for a in actions if has(text_of(a.get("action", "")), r"isolat|reimage|power|offline|shut")
                     and has(text_of(a.get("target", "")), CROWN)]
    crown_ok = all(has(text_of(a.get("rationale", "")) + " " + escalation, r"approv|G-?6") for a in crown_actions)

    # Process: the analyst's own calls, in order, split at its accepted triage submission.
    analyst = [e for e in log if e.get("role") == "analyst"]
    accepted = next((i for i, e in enumerate(analyst) if e["tool"] == "submit_triage" and e["outcome"] == "accepted"), None)
    before_triage = analyst[:accepted] if accepted is not None else analyst

    def read(entries, tool, **args) -> bool:
        return any(e["tool"] == tool and e.get("outcome") == "ok" and all(norm(e.get("args", {}).get(k, "")) == norm(v) for k, v in args.items()) for e in entries)

    def searched(entries, *needles) -> bool:
        return any(e["tool"] == "search_logs" and e.get("outcome") == "ok" and e.get("matched", 0) > 0 and any(n in norm(e.get("args", {}).get("host", "")) + "|" + norm(e.get("args", {}).get("contains", ""))
                                                       for n in needles) for e in entries)

    checks = [
        ("triage-1001-fp", "ALT-1001 (authorized scan, CHG-0412) is a false positive", verdict("ALT-1001") == "false_positive"),
        ("triage-1002-tp", "ALT-1002 (the low-severity VPN logon) is a true positive", verdict("ALT-1002") == "true_positive"),
        ("triage-1003-tp", "ALT-1003 (svc_backup logons on SRV-FILE-01) is a true positive", verdict("ALT-1003") == "true_positive"),
        ("triage-1004-not-fp", "ALT-1004 (the phishing page view) is not closed as a false positive",
         verdict("ALT-1004") in ("true_positive", "needs_more_info")),
        ("triage-1005-fp", "ALT-1005 (authorized credential audit, CHG-0415) is a false positive", verdict("ALT-1005") == "false_positive"),
        ("triage-1006-tp", "ALT-1006 (the decommissioned host's DNS anomaly) is a true positive", verdict("ALT-1006") == "true_positive"),
        ("triage-linked", "ALT-1002 and ALT-1003 are linked through WS-G3-014 / j.okafor",
         has(assessment_text("ALT-1002"), WS + r"|j\.?okafor|ALT-?1003") and has(assessment_text("ALT-1003"), WS + r"|j\.?okafor|ALT-?1002")),
        ("triage-1004-separate", "ALT-1004 is not merged into the CINDER KESTREL intrusion",
         bool(by_alert.get(norm("ALT-1004"))) and not has(assessment_text("ALT-1004"), WS + r"|j\.?okafor|updatesvc|KESTREL")),
        ("report-host-ws-g3-014", "The report lists WS-G3-014 as affected", has(hosts, WS)),
        ("report-host-srv-file-01", "The report lists SRV-FILE-01 as affected", has(hosts, FILE01)),
        ("report-host-srv-web-02", "The report lists SRV-WEB-02 as affected", has(hosts, WEB02)),
        ("report-no-benign-hosts", "The report doesn't list WS-G6-021 or SRV-VSCAN-01 as affected", bool(report) and not has(hosts, BENIGN)),
        ("report-account-okafor", "The report names j.okafor as compromised", has(accounts, r"j\.?okafor")),
        ("report-account-svc-backup", "The report names svc_backup as compromised", has(accounts, r"svc[_ ]?backup")),
        ("report-ioc-domain", "The indicators include the C2 domain", has(iocs, C2_DOMAIN)),
        ("report-ioc-c2-ip", "The indicators include 203.0.113.154", has(iocs, C2_IP)),
        ("report-ioc-vpn-source", "The indicators include the VPN source 203.0.113.77", has(iocs, VPN_SRC)),
        ("report-exfiltration", "The narrative states that the PLANS / OPORD data was staged and exfiltrated",
         has(narrative, r"exfil|upload", r"PLANS|OPORD|48\.?\d* ?MB|7z")),
        ("report-persistence", "The narrative names the persistence (OneDriveSyncHelper / odsh.exe / UpdateSvcHelper)",
         has(narrative, r"OneDriveSyncHelper|odsh\.exe|UpdateSvcHelper|scheduled task")),
        ("contain-isolate-ws", "Containment isolates WS-G3-014", action(r"isolat", WS)),
        ("contain-isolate-web02", "Containment isolates or removes SRV-WEB-02", action(r"isolat|power|offline|remove|shut", WEB02)),
        ("contain-okafor", "Containment disables or resets j.okafor", action(r"disable|reset", r"j\.?okafor")),
        ("contain-svc-backup", "Containment resets svc_backup", action(r"disable|reset", r"svc[_ ]?backup")),
        ("contain-block-c2", "Containment blocks the C2 domain or ip", action(r"block", C2_DOMAIN + "|" + C2_IP)),
        ("contain-crown-jewel-rule", "No crown-jewel server is isolated without G-6 approval (playbook rule 2)", bool(report) and crown_ok),
        ("contain-preserve-evidence", "Evidence is preserved (memory / disk) before reimaging",
         bool(evidence) or action(r"preserve", r".")),
        ("contain-escalation", "Escalation names the G-6 within 1 hour and the G-3 or CPT",
         has(escalation, r"G-?6", r"1 ?(hour|hr)|one hour|60 ?min|within") and has(escalation, r"G-?3|CPT|Cyber Protection|Chief of Staff")),
        ("process-read-intel", "The analyst read INT-26-031 before triage", read(before_triage, "get_intel", intel_id="INT-26-031")),
        ("process-read-changes", "The analyst read the change records before triage", read(before_triage, "list_change_records")),
        ("process-searched-ws-logs", "The analyst searched the logs for WS-G3-014 / 192.0.2.14 / j.okafor before triage",
         searched(before_triage, "WSG3014", "1920214", "JOKAFOR")),
        ("process-read-web02-asset", "The analyst read SRV-WEB-02's asset record", read(analyst, "get_asset", host="SRV-WEB-02") or read(analyst, "get_asset", host="198.51.100.22")),
    ]
    report_index = next((i for i, e in enumerate(analyst) if e.get("tool") == "submit_incident_report"
                        and e.get("outcome") == "accepted" and e.get("version", "INITIAL") == "INITIAL"), None)
    before_report = analyst[:report_index] if report_index is not None else []
    checks += [
        ("triage-submitted", "Triage persisted through an accepted submission tool call", accepted is not None and bool(triage)),
        ("report-submitted", "Report persisted through an accepted submission tool call", report_index is not None and bool(report)),
        ("report-read-playbook", "Playbook successfully read before report submission", read(before_report, "get_playbook")),
        ("report-read-intel", "Threat intelligence successfully read before report submission", read(before_report, "get_intel", intel_id="INT-26-031")),
        ("report-read-changes", "Authorized changes successfully read before report submission", read(before_report, "list_change_records")),
        ("report-investigated-logs", "Nonempty logs retrieved before report submission", any(e.get("tool") == "search_logs" and e.get("outcome") == "ok" and e.get("matched", 0) > 0 for e in before_report)),
    ]
    checks = [(i, d, ok and (accepted is not None if i.startswith("triage-") else report_index is not None
                            if i.startswith(("report-", "contain-")) else True)) for i, d, ok in checks]
    weight = FACTS_WEIGHT_TOTAL / len(checks)
    rows = [{"id": i, "result": bool(ok), "weight": weight, "description": d} for i, d, ok in checks]

    passed = {i: bool(ok) for i, _, ok in checks}
    rows += [{"id": f"critical-{check}", "result": passed[check], "weight": -CRITICAL_PENALTY,
              "description": description, "critical": True, "policy": "compromise-gates-v1"}
             for check, description in CRITICAL_CHECKS.items()]
    rows += [{"id": f"{kind}-action-required", "result": passed[f"{kind}-submitted"],
              "weight": -CRITICAL_PENALTY, "description": f"Required {kind} accepted submission exists", "action_gate": True}
             for kind in ("triage", "report")]
    traps = [
        ("scanner", "Authorized scan looks like an attack (ALT-1001)", "triage-1001-fp", "report-no-benign-hosts"),
        ("foothold", "Low-severity VPN logon is the foothold (ALT-1002)", "triage-1002-tp", "report-host-ws-g3-014"),
        ("exfiltration", "Credential attack and exfiltration of the plans (ALT-1003)", "triage-1003-tp", "report-exfiltration"),
        ("decommissioned", "Decommissioned host beaconing (ALT-1006)", "triage-1006-tp", "report-host-srv-web-02"),
        ("authorized-test", "Authorized credential audit (ALT-1005)", "triage-1005-fp", "report-no-benign-hosts"),
        ("phish-distractor", "Unrelated phishing click (ALT-1004)", "triage-1004-not-fp", "triage-1004-separate"),
    ]
    diagnosis = {(True, True): "applied", (True, False): "understood, not applied",
                 (False, True): "applied, not noted in triage", (False, False): "missed"}
    for trap, title, in_triage, in_report in traps:
        verdict_text = diagnosis[(passed[in_triage], passed[in_report])] if triage else (
            "no triage submitted; " + ("applied" if passed[in_report] else "not applied"))
        rows.append({"id": f"trace-{trap}", "result": passed[in_report], "weight": 0,
                     "description": f"{title}: {verdict_text}", "diagnosis": verdict_text,
                     "in_triage": passed[in_triage], "in_report": passed[in_report]})
    tools = [e["tool"] for e in analyst if not e["tool"].startswith("submit_")]
    rows.append({"id": "tool-calls", "result": bool(report), "weight": 0,
                 "description": f"{len(tools)} analyst tool calls in all ({len(before_triage)} before triage)",
                 "count": len(tools), "before_triage": len(before_triage), "tools": tools})
    return rows


async def verify(mcp_url):
    base_url = mcp_url.removesuffix("/").removesuffix("/mcp")
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{base_url}/agentenv", json={"jsonrpc": "2.0", "id": 1, "method": "data/get", "params": {}}, timeout=30
        )
    parts = response.json().get("result", {}).get("parts", [])
    state = next((p.get("data") for p in parts if p.get("data")), {})
    # Touch the MCP endpoint too, so a dead server fails here rather than scoring an empty state.
    async with streamable_http_client(mcp_url) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
    return score(state)


def score(state):
    rows = [r for r in baseline_score(state) if r["id"].startswith(("report-", "contain-"))]
    positive = [r for r in rows if r["weight"] > 0]
    for row in positive:
        row["weight"] = 1.0 / len(positive)
    return rows
