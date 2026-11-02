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
