# Answer key: INC-26-1107, the sample incident in soc-env/data/incident.json

The alert queue holds six alerts. Four belong to one intrusion, two are explained by change
records. These facts are in the records but not flagged there; a correct triage and report reflect
each one.

1. **ALT-1001 is a false positive.** The port scan came from SRV-VSCAN-01 (198.51.100.40) on a
   Thursday between 02:02Z and 02:48Z, inside the standing weekly scan window in **CHG-0412**. The
   playbook requires the change record to be cited when closing it.
2. **ALT-1002 is the foothold, despite its low severity.** j.okafor's VPN logon from
   **203.0.113.77** (Varenna) at 22:41Z on 2026-11-05 matches **INT-26-031**'s source range. The
   auth log shows an RDP logon to **WS-G3-014** from the VPN address 192.0.2.214 two minutes later;
   the endpoint log shows a hidden PowerShell download cradle, the scheduled task
   **OneDriveSyncHelper** running **C:\Users\Public\odsh.exe**, and the proxy and DNS logs show a
   download from and a 5-minute beacon to **cdn-metrics.updatesvc.example (203.0.113.154)**, all
   named in the bulletin.
3. **ALT-1003 is credential attack and lateral movement from the same workstation.** The 12 failed
   logons for **svc_backup** on **SRV-FILE-01** came from 192.0.2.14 (WS-G3-014), launched by
   odsh.exe; the success at 01:15Z was followed by a remote 7z archive of
   **\\SRV-FILE-01\PLANS\OPORD_26-04_DRAFT** (48.1 MB) in Windows\Temp, its copy to the
   workstation, and a **single 48.3 MB POST to /api/v1/upload** at 01:40Z: the draft division order
   was exfiltrated. The 03:00Z svc_backup logon from the server itself is the normal backup.
4. **ALT-1006 is a second compromised host that should not be on the network at all.**
   **SRV-WEB-02** was decommissioned and recorded as powered off under **CHG-0398**, yet at 02:04Z
   svc_backup logged on to it from WS-G3-014, odsh.exe was started there over WMI and installed as
   the service **UpdateSvcHelper**, and it has beaconed to the same C2 domain every 5 minutes since
   02:10Z. The informational severity hides it; the asset note and the intel expose it.
5. **ALT-1005 is a false positive.** The quarantined pwaudit.exe on WS-G6-021 was the authorized
   credential-hygiene audit in **CHG-0415**, in its window, with the detection expected.
6. **ALT-1004 is a real phishing lure but not part of the intrusion.** t.baptiste viewed
   portal-benefits-login.example (INT-26-029's pattern) and nothing followed: no POST, no child
   process, no file write. It is a true positive of low impact (or needs more information); it must
   not be closed as benign, and it must not be merged into the CINDER KESTREL intrusion.

**A correct incident report** names WS-G3-014, SRV-FILE-01 and SRV-WEB-02 as affected, j.okafor
and svc_backup as compromised, and the indicators 203.0.113.77, 203.0.113.154,
cdn-metrics.updatesvc.example, odsh.exe, OneDriveSyncHelper and UpdateSvcHelper. Its containment
isolates WS-G3-014 and SRV-WEB-02, disables or resets j.okafor and resets svc_backup, blocks the
domain and the ip, and preserves memory and disk first; it does **not** isolate SRV-FILE-01 or
SRV-DC-01 on its own authority (playbook rule 2: recommend and escalate), and it leaves WS-G6-021
and SRV-VSCAN-01 alone. Its escalation reports to the Division G-6 within 1 hour, requests the CPT
for the confirmed data loss, and tells the G-3 and the Chief of Staff that the draft order may be
compromised (organization escalation rules). The affected user is not notified before the account
is contained.

## Evidence items (v2)

- **EV-01**, the decoded PowerShell from endpoint-003: downloads `/u/odsh` from cdn-metrics.updatesvc.example to
  `C:\Users\Public\odsh.exe`, creates the scheduled task **OneDriveSyncHelper** every 5 minutes, starts it hidden.
- **EV-02**, the task export: `\OneDriveSyncHelper`, author EXNET52\j.okafor, created 2026-11-05T22:52:30, trigger
  **PT5M**, **Hidden**, action `C:\Users\Public\odsh.exe`.
- **EV-03**, WS-G3-014 triage package: the task is the persistence; the **OneDrive run key is legitimate**; prefetch
  shows odsh.exe run 181 times, wmic.exe once at 02:05Z; `bk_2026.7z` (48 MB) is still on disk and must be
  preserved; odsh.exe holds an established connection to 203.0.113.154:443.
- **EV-04**, SRV-WEB-02 triage package: service **UpdateSvcHelper** running `C:\Windows\Temp\odsh.exe` as
  LocalSystem since 02:09:30Z; **last boot 2026-09-30, uptime 37 days**, so the host was never powered off despite
  CHG-0398; 7 months of patches missing; svc_backup is a local admin; the endpoint agent stopped checking in on
  2026-10-14; established connection to 203.0.113.154:443.
- **EV-05**, hex dump and strings of odsh.exe: unsigned PE, strings for the C2 domain, `/api/v1/ping`,
  `/api/v1/upload`, the user agent **UpdateSvc/1.2**, both persistence names, the spray and WMI command templates,
  the archive pattern, the **PDB path C:\build\kestrel\odsh.pdb** and the mutex.
- **EV-06**, the phishing email: SPF and DMARC fail, link to portal-benefits-login.example; a credential lure with
  no attachment and, per the logs, no POST and no follow-on. Unrelated to the intrusion.
- **EV-07**, the implant configuration from memory: primary C2 cdn-metrics.updatesvc.example, **fallback
  cdn-telemetry.updatesvc.example** (in no log), beacon **300 s** with 10% jitter, paths ping/upload/payload, the
  user agent, both persistence names, **mutex Global\ODSH-7c1e**, **kill date 2026-12-31**, staging dir
  Windows\Temp, archive pattern, spray target svc_backup, campaign id GC-26-11.

## What good code looks like (v2)

Rules should cover, at precision 0.8 or better, these behaviors in the logs: the VPN logon from 203.0.113.0/24
(auth-006), the svc_backup network-logon failures (auth-008..019), DNS queries for *.updatesvc.example (9
records on two hosts), proxy POSTs to /api/v1/ping on that domain (4 records), the single 48.3 MB POST to
/api/v1/upload (proxy-005), schtasks /Create from C:\Users\Public (endpoint-004), wmic /node: remote process
creation (endpoint-009) and the service installed from Windows\Temp (endpoint-010), while matching none of the
scanner (endpoint-002), the authorized pwaudit run (endpoint-001) or the normal 0300Z backup logon (auth-022).
A hunt script flags all 39 malicious records on WS-G3-014, SRV-FILE-01 and SRV-WEB-02 (the VPN gateway record is
acceptable) and no benign host. An extractor returns the C2 domain, 203.0.113.154, 203.0.113.77, odsh.exe,
OneDriveSyncHelper, UpdateSvcHelper, /api/v1/upload and svc_backup, and nothing from the enclave's own hosts.
