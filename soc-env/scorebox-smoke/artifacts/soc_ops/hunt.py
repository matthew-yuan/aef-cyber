"""Reference hunt script for INC-26-1107 (trusted fixture, written by the project, not by an agent)."""
import ipaddress
from collections import defaultdict

C2_SUFFIX = ".updatesvc.example"
C2_IP = "203.0.113.154"
FOREIGN = ipaddress.ip_network("203.0.113.0/24")
IMPLANT_WORDS = ("odsh.exe", "onedrivesynchelper", "updatesvchelper")


def _finding(record, behavior, reason):
    return {"source": record["source"], "id": record["id"], "behavior": behavior, "host": record.get("host", ""), "reason": reason}


def hunt(data):
    findings = []
    # auth: foreign VPN logons, password sprays and what they led to
    failures = defaultdict(list)
    for r in data.get("auth", []):
        if r.get("event") == "vpn_logon" and r.get("result") == "success":
            try:
                if ipaddress.ip_address(r.get("src", "")) in FOREIGN:
                    findings.append(_finding(r, "vpn_foreign_logon", "VPN logon from the actor's range"))
            except ValueError:
                pass
        if r.get("result") == "failure" and r.get("logon_type") == "network":
            failures[(r.get("host"), r.get("user"), r.get("src"))].append(r)
    sprayed = {k for k, v in failures.items() if len(v) >= 5}
    for key in sprayed:
        for r in failures[key]:
            findings.append(_finding(r, "svc_backup_spray", f"{len(failures[key])} failed network logons for {key[1]} from {key[2]}"))
    for r in data.get("auth", []):
        key = (r.get("host"), r.get("user"), r.get("src"))
        if key in sprayed and r.get("result") == "success":
            findings.append(_finding(r, "svc_backup_success", "success after a spray from the same source"))
        if r.get("result") == "success" and r.get("logon_type") == "remote_interactive" and str(r.get("src", "")).startswith("192.0.2.2"):
            findings.append(_finding(r, "rdp_from_vpn", "RDP from the VPN pool"))
        if r.get("user") == "svc_backup" and r.get("host") == "SRV-WEB-02":
            findings.append(_finding(r, "lateral_wmi", "service account used on a decommissioned host"))
    # dns and proxy: command and control, download, exfiltration
    for r in data.get("dns", []):
        if str(r.get("query", "")).lower().endswith(C2_SUFFIX):
            findings.append(_finding(r, "c2_beacon_dns", "query for the C2 domain"))
    for r in data.get("proxy", []):
        url = str(r.get("url", "")).lower()
        if C2_SUFFIX not in url and r.get("dest_ip") != C2_IP:
            continue
        if r.get("method") == "POST" and int(r.get("bytes_out") or 0) > 10_000_000:
            findings.append(_finding(r, "exfil_upload", "large POST to the C2 server"))
        elif url.endswith("/api/v1/ping"):
            findings.append(_finding(r, "c2_beacon_proxy", "beacon to the C2 server"))
        else:
            findings.append(_finding(r, "payload_download", "download from the C2 server"))
    # endpoint: cradle, persistence, collection, lateral movement, service install
    for r in data.get("endpoint", []):
        cmd = str(r.get("command_line") or r.get("path") or "").lower()
        detail = str(r.get("detail", "")).lower()
        proc = str(r.get("process", "")).lower()
        if proc == "schtasks.exe" and "/create" in cmd:
            findings.append(_finding(r, "persistence_task", "scheduled task created"))
        elif proc == "wmic.exe" and "/node:" in cmd:
            findings.append(_finding(r, "lateral_wmi", "remote process creation over WMI"))
        elif r.get("event") == "service_install" and "\\temp\\" in cmd:
            findings.append(_finding(r, "service_install_decommissioned", "service installed from Temp"))
        elif proc == "7z.exe" or "bk_2026.7z" in cmd:
            findings.append(_finding(r, "collection_archive", "archive of the plans share"))
        elif "updatesvc.example" in detail or "download cradle" in detail:
            findings.append(_finding(r, "download_cradle", "encoded download cradle"))
        elif "svc_backup" in detail and "password" in detail:
            findings.append(_finding(r, "svc_backup_spray", "spray script"))
        elif any(w in cmd for w in IMPLANT_WORDS) and r.get("event") == "file_create":
            findings.append(_finding(r, "payload_download", "implant written to disk"))
    return findings
