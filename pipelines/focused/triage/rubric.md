# Evaluation rubric

This reference describes the configured task, including component weights and acceptance thresholds.

## LLM judge: judge-triage

Judge model: `openai/openai/gpt-6-sol`

### tr-verdicts

Verdict accuracy. Each alert gets the right verdict: the authorized scan and the authorized credential-audit test are false positives explained by change records; the low-severity VPN logon, the failed logons on the file server and the decommissioned host's DNS anomaly are true positives of one intrusion; the phishing page view is not merged into that intrusion.

**Weight:** 0.3333333333333333

| Score | Outcome |
| --- | --- |
| 1.0 | 5 - Every verdict is right, including the low-severity foothold and the decommissioned host, and nothing authorized is escalated. |
| 0.75 | 4 - Between 5 and 3: meets the 3 anchor and most of the 5 anchor. |
| 0.5 | 3 - Most verdicts are right, but one true positive is missed or one authorized activity is called malicious. |
| 0.25 | 2 - Between 3 and 1: meets part of the 3 anchor. |
| 0.0 | 1 - Verdicts follow the alerts' severities rather than the evidence, or most are wrong. |

### tr-evidence

Evidence. Each rationale cites the specific records that decide it: the change record for a false positive, and the log entries (logons, DNS, proxy, endpoint) and intelligence indicators for a true positive. Nothing cited is invented.

**Weight:** 0.3333333333333333

| Score | Outcome |
| --- | --- |
| 1.0 | 5 - Every rationale names its records (ids, hosts, times, entries) and they match the environment. |
| 0.75 | 4 - Between 5 and 3: meets the 3 anchor and most of the 5 anchor. |
| 0.5 | 3 - Rationales are plausible but generic, or cite records loosely. |
| 0.25 | 2 - Between 3 and 1: meets part of the 3 anchor. |
| 0.0 | 1 - Rationales restate the alert text, or cite records that do not exist. |

### tr-correlation

Correlation. The triage links the VPN logon, the file-server logons and the decommissioned host into one intrusion through the shared workstation, account and command-and-control indicators, and keeps the unrelated phishing click apart.

**Weight:** 0.3333333333333333

| Score | Outcome |
| --- | --- |
| 1.0 | 5 - The intrusion's alerts are linked with the evidence that joins them, and the unrelated alert is kept separate. |
| 0.75 | 4 - Between 5 and 3: meets the 3 anchor and most of the 5 anchor. |
| 0.5 | 3 - Some links are made, but one intrusion alert is treated in isolation or the unrelated alert is pulled in. |
| 0.25 | 2 - Between 3 and 1: meets part of the 3 anchor. |
| 0.0 | 1 - Each alert is assessed alone, with no correlation. |

## Deterministic checks: facts

Text-based checks are scenario-specific heuristics; read judge feedback alongside them.

| Check | Requirement |
| --- | --- |
| triage-1001-fp | ALT-1001 (authorized scan, CHG-0412) is a false positive |
| triage-1002-tp | ALT-1002 (the low-severity VPN logon) is a true positive |
| triage-1003-tp | ALT-1003 (svc_backup logons on SRV-FILE-01) is a true positive |
| triage-1004-not-fp | ALT-1004 (the phishing page view) is not closed as a false positive |
| triage-1005-fp | ALT-1005 (authorized credential audit, CHG-0415) is a false positive |
| triage-1006-tp | ALT-1006 (the decommissioned host's DNS anomaly) is a true positive |
| triage-linked | ALT-1002 and ALT-1003 are linked through WS-G3-014 / j.okafor |
| triage-1004-separate | ALT-1004 is not merged into the CINDER KESTREL intrusion |
| process-read-intel | The analyst read INT-26-031 before triage |
| process-read-changes | The analyst read the change records before triage |
| process-searched-ws-logs | The analyst searched the logs for WS-G3-014 / 192.0.2.14 / j.okafor before triage |
| process-read-web02-asset | The analyst read SRV-WEB-02's asset record |

## Aggregate: focused-triage

- Aggregation: **weighted_average**.
- Components: judge-triage, facts.
- AEF weights verifier rows; normalized groups contribute equally where configured. See component weights below.
