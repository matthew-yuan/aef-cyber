"""run_code script for the scorebox smoke: submits the project's own golden fixtures to the soc env over MCP, standing
in for the analyst, so the scoring chain can be proven without a model. Trusted code; it only forwards fixture text.
"""
import asyncio
import json
from pathlib import Path

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

HERE = Path(__file__).resolve().parent
RULES = {'c2_beacon_dns': 'title: DNS query for updatesvc.example\nlevel: critical\ntags: [attack.command_and_control, attack.t1071.004]\nlogsource: {category: dns_query}\ndetection:\n  selection:\n    QueryName|endswith: .updatesvc.example\n  condition: selection\n', 'c2_beacon_proxy': 'title: Beacon to the ODSH C2 endpoint\nlevel: critical\ntags: [attack.command_and_control, attack.t1071.001]\nlogsource: {service: proxy}\ndetection:\n  domain:\n    url|contains: updatesvc.example\n  ping:\n    url|endswith: /api/v1/ping\n  condition: domain and ping\n', 'exfil_upload': "title: Large single POST to an external host\nlevel: high\ntags: [attack.exfiltration, attack.t1041]\nlogsource: {service: proxy}\ndetection:\n  selection:\n    method: POST\n    bytes_out|gt: 10000000\n  internal:\n    dest_ip|startswith:\n      - '192.0.2.'\n      - '198.51.100.'\n  condition: selection and not internal\n", 'lateral_wmi': "title: Remote process creation over WMI\nlevel: high\ntags: [attack.lateral_movement, attack.t1047]\nlogsource: {category: process_creation}\ndetection:\n  selection:\n    process: wmic.exe\n    command_line|contains: '/node:'\n  condition: selection\n", 'persistence_task': 'title: Scheduled task created from a user-writable path\nlevel: high\ntags: [attack.persistence, attack.t1053.005]\nlogsource: {category: process_creation}\ndetection:\n  selection:\n    Image|endswith: schtasks.exe\n    CommandLine|contains|all:\n      - /Create\n      - \\Users\\Public\\\n  condition: selection\n', 'service_install_decommissioned': 'title: Service installed from the Temp folder\nlevel: high\ntags: [attack.persistence, attack.t1543.003]\nlogsource: {category: service_installation}\ndetection:\n  selection:\n    event: service_install\n    path|contains: \\Temp\\\n  condition: selection\n', 'svc_backup_spray': 'title: Network logon failures for a service account\nlevel: medium\ntags: [attack.credential_access, attack.t1110.003]\nlogsource: {category: authentication}\ndetection:\n  selection:\n    user: svc_*\n    logon_type: network\n    result: failure\n  condition: selection\n', 'vpn_foreign_logon': 'title: VPN logon from the CINDER KESTREL source range\nid: 7a0c1b2e-0001-4c3d-9e8f-000000000001\nlevel: high\ntags: [attack.initial_access, attack.t1133]\nlogsource: {service: auth}\ndetection:\n  selection:\n    event: vpn_logon\n    result: success\n    src|cidr: 203.0.113.0/24\n  condition: selection\n'}
BANNED = 'import socket\ndef hunt(data):\n    socket.create_connection(("203.0.113.1", 80))\n    return []\n'
SUBMITTED_RULES = ["vpn_foreign_logon", "svc_backup_spray", "c2_beacon_dns", "c2_beacon_proxy", "exfil_upload", "persistence_task"]


async def _call(session, name, args):
    result = await session.call_tool(name, args)
    text = "".join(getattr(part, "text", "") for part in result.content)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"_text": text}


async def _submit(mcp_url, which):
    receipts = {}
    async with streamable_http_client(mcp_url) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            receipts["banned"] = await _call(session, "soc_submit_artifact", {"kind": "hunt_script", "name": "banned", "content": BANNED})
            receipts["hunt"] = await _call(session, "soc_submit_artifact", {"kind": "hunt_script", "name": "golden-hunt", "content": (HERE / "hunt.py").read_text()})
            receipts["extract"] = await _call(session, "soc_submit_artifact", {"kind": "ioc_extractor", "name": "golden-extract", "content": (HERE / "extract.py").read_text()})
            for name in SUBMITTED_RULES:
                receipts[name] = await _call(session, "soc_submit_artifact", {"kind": "sigma_rule", "name": name.replace("_", "-"), "content": RULES[name]})
    return receipts


def run(input):
    which = (input.get("args") or {}).get("set", "golden")
    receipts = asyncio.run(_submit(input["env"]["mcp_url"], which))
    statuses = {k: v.get("status") or v.get("error") for k, v in receipts.items()}
    if statuses["banned"] != "rejected" or any(s != "accepted" for k, s in statuses.items() if k != "banned"):
        raise RuntimeError(f"unexpected receipts: {statuses}")
    return {"set": which, "statuses": statuses}
