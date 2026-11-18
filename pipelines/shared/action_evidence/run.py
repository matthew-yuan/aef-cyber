"""Collect trusted environment action receipts for judges; never execute submissions."""
import httpx


def collect(state, phase):
    log = [e for e in state.get("audit_log", []) if e.get("role") == "analyst"]
    tool = {"triage": "submit_triage", "report": "submit_incident_report",
            "evidence": "submit_evidence_report", "artifacts": "submit_artifact", "revision": "submit_incident_report"}[phase]
    version = "UPDATE-01" if phase == "revision" else "INITIAL"
    submissions = [i for i, e in enumerate(log) if e.get("tool") == tool and e.get("outcome") == "accepted"
                   and (e.get("version", "INITIAL") == version if phase in ("report", "revision") else True)]
    if phase in ("report", "revision"):
        product = next((r for r in state.get("reports", []) if r.get("version") == version), None)
        product = product or (state.get("report") if version == "INITIAL" else None)
    elif phase == "artifacts":
        product = any(state.get("artifacts", {}).values())
    else:
        product = state.get("triage" if phase == "triage" else "evidence_report")
    prior = log[:max(submissions)+1] if submissions else []
    if phase == "revision":
        prior = [e for e in prior if e.get("version") == version]
    return {"accepted_submission": bool(submissions) and bool(product),
            "successful_read_tools": sorted({e["tool"] for e in prior if e.get("outcome") == "ok" and not e["tool"].startswith("submit_")}),
            "failed_or_rejected_calls": sum(e.get("outcome") not in ("ok", "accepted") for e in prior),
            "successful_log_queries": sum(e.get("tool") == "search_logs" and e.get("outcome") == "ok" and e.get("matched", 0) > 0 for e in prior),
            "accepted_artifacts": sum(len(items) for items in state.get("artifacts", {}).values()) if phase == "artifacts" else 0,
            "execution_scope": "SOC tools record recommendations only; no host isolation/account reset/blocking/notification/capture execution tools exist"}


def run(input):
    base = input["env"]["mcp_url"].removesuffix("/").removesuffix("/mcp")
    response = httpx.post(f"{base}/agentenv", timeout=30, json={
        "jsonrpc": "2.0", "id": 1, "method": "data/get", "params": {}})
    response.raise_for_status()
    reply = response.json()
    if "error" in reply:
        raise RuntimeError("Action evidence data/get failed")
    parts = reply.get("result", {}).get("parts", [])
    state = next((p["data"] for p in parts if p.get("data")), {})
    return collect(state, input["args"]["phase"])
