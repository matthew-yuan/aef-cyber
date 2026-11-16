"""Smoke test for the lab env: every tool over MCP, with model-free sample scripts, then data/get.

It proves the execution boundary: a banned script is refused without running, a spinning script is killed at
its time limit, a memory bomb dies under the address-space limit, a crashing script reports its error, and a
good script returns findings. The samples are the project's own fixtures, not agent output.
"""
import json

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

EXPECTED_TOOLS = {"lab_list_datasets", "lab_describe_dataset", "lab_screen", "lab_history", "lab_run_script", "lab_test_rule"}
GOLDEN_HUNT = '"""Reference hunt script for INC-26-1107 (trusted fixture, written by the project, not by an agent)."""\nimport ipaddress\nfrom collections import defaultdict\n\nC2_SUFFIX = ".updatesvc.example"\nC2_IP = "203.0.113.154"\nFOREIGN = ipaddress.ip_network("203.0.113.0/24")\nIMPLANT_WORDS = ("odsh.exe", "onedrivesynchelper", "updatesvchelper")\n\n\ndef _finding(record, behavior, reason):\n    return {"source": record["source"], "id": record["id"], "behavior": behavior, "host": record.get("host", ""), "reason": reason}\n\n\ndef hunt(data):\n    findings = []\n    # auth: foreign VPN logons, password sprays and what they led to\n    failures = defaultdict(list)\n    for r in data.get("auth", []):\n        if r.get("event") == "vpn_logon" and r.get("result") == "success":\n            try:\n                if ipaddress.ip_address(r.get("src", "")) in FOREIGN:\n                    findings.append(_finding(r, "vpn_foreign_logon", "VPN logon from the actor\'s range"))\n            except ValueError:\n                pass\n        if r.get("result") == "failure" and r.get("logon_type") == "network":\n            failures[(r.get("host"), r.get("user"), r.get("src"))].append(r)\n    sprayed = {k for k, v in failures.items() if len(v) >= 5}\n    for key in sprayed:\n        for r in failures[key]:\n            findings.append(_finding(r, "svc_backup_spray", f"{len(failures[key])} failed network logons for {key[1]} from {key[2]}"))\n    for r in data.get("auth", []):\n        key = (r.get("host"), r.get("user"), r.get("src"))\n        if key in sprayed and r.get("result") == "success":\n            findings.append(_finding(r, "svc_backup_success", "success after a spray from the same source"))\n        if r.get("result") == "success" and r.get("logon_type") == "remote_interactive" and str(r.get("src", "")).startswith("192.0.2.2"):\n            findings.append(_finding(r, "rdp_from_vpn", "RDP from the VPN pool"))\n        if r.get("user") == "svc_backup" and r.get("host") == "SRV-WEB-02":\n            findings.append(_finding(r, "lateral_wmi", "service account used on a decommissioned host"))\n    # dns and proxy: command and control, download, exfiltration\n    for r in data.get("dns", []):\n        if str(r.get("query", "")).lower().endswith(C2_SUFFIX):\n            findings.append(_finding(r, "c2_beacon_dns", "query for the C2 domain"))\n    for r in data.get("proxy", []):\n        url = str(r.get("url", "")).lower()\n        if C2_SUFFIX not in url and r.get("dest_ip") != C2_IP:\n            continue\n        if r.get("method") == "POST" and int(r.get("bytes_out") or 0) > 10_000_000:\n            findings.append(_finding(r, "exfil_upload", "large POST to the C2 server"))\n        elif url.endswith("/api/v1/ping"):\n            findings.append(_finding(r, "c2_beacon_proxy", "beacon to the C2 server"))\n        else:\n            findings.append(_finding(r, "payload_download", "download from the C2 server"))\n    # endpoint: cradle, persistence, collection, lateral movement, service install\n    for r in data.get("endpoint", []):\n        cmd = str(r.get("command_line") or r.get("path") or "").lower()\n        detail = str(r.get("detail", "")).lower()\n        proc = str(r.get("process", "")).lower()\n        if proc == "schtasks.exe" and "/create" in cmd:\n            findings.append(_finding(r, "persistence_task", "scheduled task created"))\n        elif proc == "wmic.exe" and "/node:" in cmd:\n            findings.append(_finding(r, "lateral_wmi", "remote process creation over WMI"))\n        elif r.get("event") == "service_install" and "\\\\temp\\\\" in cmd:\n            findings.append(_finding(r, "service_install_decommissioned", "service installed from Temp"))\n        elif proc == "7z.exe" or "bk_2026.7z" in cmd:\n            findings.append(_finding(r, "collection_archive", "archive of the plans share"))\n        elif "updatesvc.example" in detail or "download cradle" in detail:\n            findings.append(_finding(r, "download_cradle", "encoded download cradle"))\n        elif "svc_backup" in detail and "password" in detail:\n            findings.append(_finding(r, "svc_backup_spray", "spray script"))\n        elif any(w in cmd for w in IMPLANT_WORDS) and r.get("event") == "file_create":\n            findings.append(_finding(r, "payload_download", "implant written to disk"))\n    return findings\n'
BANNED = 'import socket\ndef hunt(data):\n    socket.create_connection(("203.0.113.1", 80))\n    return []\n'
RULE = 'title: DNS query for updatesvc.example\nlevel: critical\ntags: [attack.command_and_control, attack.t1071.004]\nlogsource: {category: dns_query}\ndetection:\n  selection:\n    QueryName|endswith: .updatesvc.example\n  condition: selection\n'
EXTRACTOR = 'def extract(data):\n    return {"indicators": [{"type": "domain", "value": r["query"], "context": r["id"]} for r in data.get("dns", [])]}\n'
SPIN = "def hunt(data):\n    while True:\n        pass\n"
MEMORY = "def hunt(data):\n    blocks = []\n    while True:\n        blocks.append(bytearray(10 ** 7))\n"
CRASH = "def hunt(data):\n    return 1 / 0\n"
BAD_SHAPE = "def hunt(data):\n    return {'not': 'a list'}\n"


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

            _, ds = await _call(session, "lab_list_datasets")
            names = [d["name"] for d in ds.get("datasets", [])]
            counts = ds.get("datasets", [{}])[0].get("records", {}) if names else {}
            _, desc = await _call(session, "lab_describe_dataset", {"name": "logs"})
            _, unknown = await _call(session, "lab_describe_dataset", {"name": "nope"})
            total = sum(counts.values()) if counts else 0
            rows.append(_row("datasets", names == ["logs"] and total > 0 and set(desc.get("sources", {})) == set(counts)
                             and "hunt_script" in desc.get("contract", {}) and "error" in unknown,
                             f"datasets {names}, {total} records; describe has sources and contract; unknown refused"))

            _, screened = await _call(session, "lab_screen", {"kind": "hunt_script", "code": BANNED})
            _, refused = await _call(session, "lab_run_script", {"kind": "hunt_script", "code": BANNED})
            rows.append(_row("banned-not-run", screened.get("ok") is False and screened.get("problems") and refused.get("executed") is False,
                             f"screen problems: {[p['detail'] for p in screened.get('problems', [])]}; executed: {refused.get('executed')}"))

            _, good = await _call(session, "lab_run_script", {"kind": "hunt_script", "code": GOLDEN_HUNT, "timeout_s": 20})
            summary = good.get("summary", {})
            rows.append(_row("golden-hunt-runs", good.get("executed") and good.get("outcome") == "ok" and good.get("exit_code") == 0
                             and summary.get("findings", 0) > 0 and summary.get("unknown_or_malformed") == 0
                             and summary.get("unique_records", 0) <= total and good.get("elapsed_ms", 10 ** 9) < 20000,
                             f"outcome {good.get('outcome')}, exit {good.get('exit_code')}, {summary.get('findings')} findings on "
                             f"{summary.get('unique_records')} records, {good.get('elapsed_ms')} ms; error: {good.get('error')}; stderr: {good.get('stderr_tail', '')[-200:]}"))

            _, ext = await _call(session, "lab_run_script", {"kind": "ioc_extractor", "code": EXTRACTOR})
            rows.append(_row("extractor-runs", ext.get("outcome") == "ok" and ext.get("summary", {}).get("indicators") == counts.get("dns"),
                             f"outcome {ext.get('outcome')}, {ext.get('summary', {}).get('indicators')} indicators (dns records: {counts.get('dns')})"))

            _, spin = await _call(session, "lab_run_script", {"kind": "hunt_script", "code": SPIN, "timeout_s": 2})
            rows.append(_row("spin-killed", spin.get("timed_out") is True and spin.get("outcome") == "timed_out" and spin.get("elapsed_ms", 10 ** 9) < 12000,
                             f"timed_out {spin.get('timed_out')} after {spin.get('elapsed_ms')} ms"))

            _, mem = await _call(session, "lab_run_script", {"kind": "hunt_script", "code": MEMORY, "timeout_s": 10})
            rows.append(_row("memory-bomb-dies", mem.get("executed") and mem.get("outcome") in ("error", "timed_out") and mem.get("exit_code") != 0,
                             f"outcome {mem.get('outcome')}, exit {mem.get('exit_code')}, error: {str(mem.get('error'))[:80]}"))

            _, crash = await _call(session, "lab_run_script", {"kind": "hunt_script", "code": CRASH})
            _, shape = await _call(session, "lab_run_script", {"kind": "hunt_script", "code": BAD_SHAPE})
            rows.append(_row("errors-reported", crash.get("outcome") == "error" and "ZeroDivisionError" in str(crash.get("error"))
                             and crash.get("traceback_tail") and shape.get("outcome") == "error" and "list of dicts" in str(shape.get("error")),
                             f"crash: {str(crash.get('error'))[:60]}; bad shape: {str(shape.get('error'))[:60]}"))

            _, tested = await _call(session, "lab_test_rule", {"rule_yaml": RULE})
            _, invalid = await _call(session, "lab_test_rule", {"rule_yaml": "title: x\nlogsource: {service: dns}\ndetection:\n  s:\n    q|re: a\n  condition: s\n"})
            rows.append(_row("rule-test", tested.get("valid") and tested.get("matched", 0) > 0 and tested.get("sample_ids") and tested.get("sample_records")
                             and invalid.get("valid") is False and invalid.get("errors"),
                             f"golden rule matched {tested.get('matched')} ({tested.get('by_source')}); invalid rule errors: {invalid.get('errors')}"))

            _, hist = await _call(session, "lab_history")
            used = hist.get("budget", {}).get("used")
            rows.append(_row("history-and-budget", used == 9 and len(hist.get("runs", [])) == 7 and len(hist.get("rule_tests", [])) == 2
                             and all("code" not in r and "content" not in r for r in hist.get("runs", [])),
                             f"budget used {used}; runs {len(hist.get('runs', []))}; rule tests {len(hist.get('rule_tests', []))}"))

    base_url = mcp_url.removesuffix("/").removesuffix("/mcp")
    async with httpx.AsyncClient() as client:
        response = await client.post(f"{base_url}/agentenv", json={"jsonrpc": "2.0", "id": 1, "method": "data/get", "params": {}}, timeout=30)
    parts = response.json().get("result", {}).get("parts", [])
    state = next((p.get("data") for p in parts if p.get("data")), {})
    runs = state.get("runs", [])
    audit = state.get("audit_log", [])
    rows.append(_row("data-get", state.get("datasets") == ["logs"] and len(runs) == 7 and state.get("budget", {}).get("used") == 9
                     and all("code" not in e.get("args", {}) and "rule_yaml" not in e.get("args", {}) for e in audit)
                     and sum(1 for r in runs if r.get("outcome") == "ok") == 2,
                     f"datasets {state.get('datasets')}; {len(runs)} runs ({[r.get('outcome') for r in runs]}); audit args carry no code"))
    return rows
