"""Code checks for the v2 artifact and evidence phases, read from the soc env's end state. Host side: parse only.

Scored rows (weights total ARTIFACT_WEIGHT_TOTAL = 1.0):
  art-*      an artifact of each kind was accepted; receipts are intact (sha256 matches the stored content and the
             submission-time check passed); every stored artifact still parses (ast.parse / yaml.safe_load, never
             executed); the analyst did not burn through rejections
  ev-*       the evidence report exists, states the facts each item holds, and does not call the legitimate run key
             malicious
  process-*  the analyst read the contract before coding and read every evidence item before reporting
Unweighted rows: diagnostics on attempts, sizes and lab usage visible from the soc side.

Everything this file does to analyst text is ast.parse, yaml.safe_load, hashing and regex. Execution and the
precision/recall scoring happen in the scorebox container (see soc-env/scorebox/harness/run_tests.py).
"""
import ast
import hashlib
import json
import re

import httpx
import yaml
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

ARTIFACT_WEIGHT_TOTAL = 1.0
MAX_REJECTIONS_PER_KIND = 4
# Mirrors soc-env/data/ground_truth.json["evidence_facts"]; tests/test_v2.py asserts they are equal.
EVIDENCE_FACTS = {
    "EV-01": ["cdn-metrics\\.updatesvc\\.example", "odsh\\.exe", "OneDriveSyncHelper|schtasks"],
    "EV-02": ["OneDriveSyncHelper", "PT5M|5 ?min|every 5|300 ?s", "odsh\\.exe", "j\\.?okafor|hidden"],
    "EV-03": ["odsh\\.exe", "203\\.0\\.113\\.154", "bk_2026\\.7z", "OneDriveSyncHelper|scheduled task"],
    "EV-04": ["UpdateSvcHelper", "Temp\\\\+odsh\\.exe|odsh\\.exe", "uptime|last boot|never (been )?powered off|2026-09-30|CHG-0398|still running", "203\\.0\\.113\\.154|svc_backup"],
    "EV-05": ["updatesvc\\.example", "/api/v1/(upload|ping)", "odsh\\.pdb|kestrel|UpdateSvc/1\\.2|PDB"],
    "EV-06": ["portal-benefits-login\\.example", "unrelated|not (part|related|connected)|separate|no follow|credential"],
    "EV-07": ["cdn-telemetry\\.updatesvc\\.example|fallback", "300|5 ?min", "ODSH-7c1e|mutex", "2026-12-31|kill.?date"],
}


def text_of(value) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def has(text: str, *patterns: str) -> bool:
    return all(re.search(p, text, re.IGNORECASE) for p in patterns)


def norm(value) -> str:
    return "".join(ch for ch in str(value).upper() if ch.isalnum())


def parses(kind: str, content: str) -> bool:
    try:
        if kind == "sigma_rule":
            docs = list(yaml.safe_load_all(content))
            return len(docs) == 1 and isinstance(docs[0], dict) and "detection" in docs[0]
        ast.parse(content)
        return True
    except (SyntaxError, ValueError, RecursionError, yaml.YAMLError):
        return False


def score(state: dict) -> list[dict]:
    artifacts = state.get("artifacts") or {}
    attempts = state.get("artifact_attempts") or []
    report = state.get("evidence_report") or {}
    evidence_ids = [norm(e) for e in state.get("evidence_ids") or []]
    log = state.get("audit_log") or []
    analyst = [e for e in log if e.get("role") == "analyst"]

    stored = [(kind, name, rec) for kind, items in artifacts.items() if isinstance(items, dict) for name, rec in items.items() if isinstance(rec, dict)]
    receipts_ok = bool(stored) and all(
        hashlib.sha256(str(rec.get("content", "")).encode("utf-8", "surrogatepass")).hexdigest() == rec.get("sha256")
        and (rec.get("check", {}).get("ok") is True or rec.get("check", {}).get("valid") is True) for _, _, rec in stored)
    syntax_ok = bool(stored) and all(parses(kind, str(rec.get("content", ""))) for kind, _, rec in stored)
    rejections = {}
    for a in attempts:
        if a.get("outcome") == "rejected":
            rejections[a.get("kind")] = rejections.get(a.get("kind"), 0) + 1

    findings = {norm(f.get("evidence_id")): text_of(f) for f in report.get("findings") or [] if isinstance(f, dict)}
    general = " ".join(text_of(report.get(k) or "") for k in ("verdict", "summary", "indicators", "recommended_actions"))

    def ev_text(ev: str) -> str:
        return findings.get(norm(ev), "") + "\n" + general

    def ev_row(ev: str) -> bool:
        return bool(report) and norm(ev) in findings and has(ev_text(ev), *EVIDENCE_FACTS[ev])

    ev03 = findings.get(norm("EV-03"), "")
    runkey_mentioned = bool(re.search(r"run ?key|OneDrive\.exe", ev03, re.IGNORECASE))
    runkey_ok = (not runkey_mentioned) or bool(re.search(r"legitimate|benign|normal|expected|not (malicious|persistence)|standard", ev03, re.IGNORECASE))

    def first_index(pred) -> int | None:
        return next((i for i, e in enumerate(analyst) if pred(e)), None)

    first_submit = first_index(lambda e: e.get("tool") == "submit_artifact")
    first_schema = first_index(lambda e: e.get("tool") == "get_log_schema" and e.get("outcome") == "ok")
    report_idx = first_index(lambda e: e.get("tool") == "submit_evidence_report" and e.get("outcome") == "accepted")
    read_before_report = {norm(e.get("args", {}).get("evidence_id", "")) for e in (analyst[:report_idx] if report_idx is not None else analyst)
                          if e.get("tool") == "get_evidence" and e.get("outcome") == "ok"}

    def fully_read(evidence_id):
        pages = [e for e in analyst[:report_idx] if e.get("tool") == "get_evidence" and e.get("outcome") == "ok"
                 and norm(e.get("args", {}).get("evidence_id", "")) == evidence_id and "total_chars" in e]
        end = 0
        for page in sorted(pages, key=lambda e: e.get("offset", 0)):
            if page.get("offset", 0) > end:
                break
            end = max(end, page.get("offset", 0) + page.get("returned_chars", 0))
        return bool(pages) and end >= max(p["total_chars"] for p in pages)

    checks = [
        ("art-sigma-accepted", "At least one Sigma rule was accepted", bool(artifacts.get("sigma_rule"))),
        ("art-hunt-accepted", "A hunt script was accepted", bool(artifacts.get("hunt_script"))),
        ("art-ioc-accepted", "An IOC extractor was accepted", bool(artifacts.get("ioc_extractor"))),
        ("art-receipts-intact", "Every stored artifact's sha256 matches its content and its submission check passed", receipts_ok),
        ("art-syntax", "Every stored artifact still parses (Python ast / single YAML mapping with a detection)", syntax_ok),
        ("art-attempts-bounded", f"No kind needed more than {MAX_REJECTIONS_PER_KIND} rejected submissions", bool(stored) and all(n <= MAX_REJECTIONS_PER_KIND for n in rejections.values())),
        ("ev-submitted", "The evidence report was submitted with a finding per item", bool(report) and len(findings) >= len(evidence_ids) > 0),
        *[(f"ev-{ev.lower()}", f"The report states what {ev} shows", ev_row(ev)) for ev in EVIDENCE_FACTS],
        ("ev-decoy-runkey", "The OneDrive run key in EV-03 is not called persistence or malicious", bool(report) and runkey_ok),
        ("process-schema-before-code", "The analyst read the contract (get_log_schema) before its first artifact submission",
         first_schema is not None and (first_submit is None or first_schema < first_submit)),
        ("process-read-all-evidence", "The analyst read every evidence item before submitting the evidence report",
         report_idx is not None and bool(evidence_ids) and all(fully_read(e) for e in evidence_ids)),
        ("process-report-after-reading", "The evidence report was accepted after at least one evidence read", report_idx is not None and bool(read_before_report)),
    ]
    accepted = {(e.get("args", {}).get("kind"), e.get("args", {}).get("name"), e.get("args", {}).get("sha256"))
                for e in analyst if e.get("tool") == "submit_artifact" and e.get("outcome") == "accepted"}
    checks += [("art-accepted-actions", "Every stored artifact has a matching accepted action and hash",
                bool(stored) and all((kind, name, rec.get("sha256")) in accepted for kind, name, rec in stored))]
    checks = [(i, d, ok and report_idx is not None if i.startswith("ev-") else ok) for i, d, ok in checks]
    weight = ARTIFACT_WEIGHT_TOTAL / len(checks)
    rows = [{"id": i, "result": bool(ok), "weight": weight, "description": d} for i, d, ok in checks]
    rows += [{"id": "action-evidence-required", "result": report_idx is not None and bool(report), "weight": -12.0,
              "description": "Required evidence report was actually accepted", "action_gate": True},
             {"id": "action-artifacts-required", "result": all(bool(artifacts.get(k)) for k in ("sigma_rule", "hunt_script", "ioc_extractor"))
              and bool(stored) and all((kind, name, rec.get("sha256")) in accepted for kind, name, rec in stored),
              "weight": -12.0, "description": "All required artifact kinds persisted with accepted action hashes", "action_gate": True}]
    rows.append({"id": "artifact-attempts", "result": bool(stored), "weight": 0,
                 "description": f"{len(attempts)} submissions, {sum(rejections.values())} rejected; accepted: "
                                f"{ {k: sorted(v) for k, v in artifacts.items() if v} }",
                 "attempts": [{k: a.get(k) for k in ('kind', 'name', 'outcome', 'bytes')} for a in attempts], "rejections": rejections})
    sizes = {f"{kind}/{name}": rec.get("bytes") for kind, name, rec in stored}
    rows.append({"id": "artifact-sizes", "result": bool(stored), "weight": 0, "description": f"bytes per artifact: {sizes}", "sizes": sizes})
    return rows


async def verify(mcp_url):
    base_url = mcp_url.removesuffix("/").removesuffix("/mcp")
    async with httpx.AsyncClient() as client:
        response = await client.post(f"{base_url}/agentenv", json={"jsonrpc": "2.0", "id": 1, "method": "data/get", "params": {}}, timeout=30)
    parts = response.json().get("result", {}).get("parts", [])
    state = next((p.get("data") for p in parts if p.get("data")), {})
    async with streamable_http_client(mcp_url) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
    return score(state)
