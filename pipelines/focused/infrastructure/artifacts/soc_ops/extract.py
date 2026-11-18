"""Reference IOC extractor (trusted fixture)."""
import re

C2_SUFFIX = ".updatesvc.example"
ACTOR_NET = "203.0.113."
BENIGN_HOSTS = {"ws-g6-021", "srv-vscan-01", "srv-dc-01"}


def extract(data):
    found = {}

    def add(kind, value, context):
        key = (kind, value.lower())
        if key not in found:
            found[key] = {"type": kind, "value": value, "context": context}

    for r in data.get("dns", []):
        q = str(r.get("query", ""))
        if q.lower().endswith(C2_SUFFIX):
            add("domain", q, f"queried by {r.get('host')} ({r.get('id')})")
            if str(r.get("answer", "")).startswith(ACTOR_NET):
                add("ipv4", r["answer"], f"resolution of {q}")
    for r in data.get("auth", []):
        if r.get("event") == "vpn_logon" and str(r.get("src", "")).startswith(ACTOR_NET):
            add("ipv4", r["src"], f"VPN logon source for {r.get('user')} ({r.get('id')})")
            add("account", str(r.get("user")), "account used for the foreign VPN logon")
        if r.get("result") == "failure" and r.get("logon_type") == "network":
            add("account", str(r.get("user")), f"sprayed service account ({r.get('id')})")
    for r in data.get("proxy", []):
        url = str(r.get("url", ""))
        if C2_SUFFIX in url.lower():
            m = re.match(r"https?://[^/]+(/.*)$", url)
            if m:
                add("url_path", m.group(1), f"C2 path seen from {r.get('host')} ({r.get('id')})")
            if str(r.get("dest_ip", "")).startswith(ACTOR_NET):
                add("ipv4", r["dest_ip"], "C2 server")
    for r in data.get("endpoint", []):
        cmd = str(r.get("command_line") or r.get("path") or "")
        if str(r.get("host", "")).lower() in BENIGN_HOSTS:
            continue
        for name in re.findall(r"[\w-]+\.exe", cmd, re.IGNORECASE):
            if name.lower() in ("odsh.exe",):
                add("file", name, f"implant binary ({r.get('id')})")
        m = re.search(r"/TN\s+(\S+)", cmd)
        if m:
            add("scheduled_task", m.group(1), f"persistence task ({r.get('id')})")
        m = re.search(r"Service '([^']+)' installed", str(r.get("detail", "")))
        if m:
            add("service", m.group(1), f"service persistence on {r.get('host')} ({r.get('id')})")
        m = re.search(r"(bk_\d+\.7z)", cmd)
        if m:
            add("file", m.group(1), f"staging archive ({r.get('id')})")
    return {"indicators": list(found.values())}
