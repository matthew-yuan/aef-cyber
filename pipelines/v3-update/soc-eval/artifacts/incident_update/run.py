"""Issue trusted scenario data without resetting submissions or the audit log."""
import httpx


def run(input):
    update = input["args"]["update"]
    base = input["env"]["mcp_url"].removesuffix("/").removesuffix("/mcp")
    response = httpx.post(f"{base}/agentenv", timeout=30, json={
        "jsonrpc": "2.0", "id": 1, "method": "data/add",
        "params": {"parts": [{"kind": "data", "data": update}]},
    })
    response.raise_for_status()
    reply = response.json()
    if "error" in reply:
        raise RuntimeError(f"data/add refused the incident update: {reply['error']}")
    return {"issued": update["inject"]["id"], "reply": reply}
