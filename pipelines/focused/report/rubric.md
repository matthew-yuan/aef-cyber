# Evaluation rubric

This reference describes the configured task, including component weights and acceptance thresholds.

## LLM judge: judge-report

Judge model: `openai/openai/gpt-6-sol`

### ir-scope

Scope and narrative. The report names every affected host and compromised account, states that the PLANS share's draft order was staged and exfiltrated, and gives a timed narrative from the VPN logon through persistence, command and control, credential attack, collection, lateral movement and exfiltration.

**Weight:** 0.3333333333333333

| Score | Outcome |
| --- | --- |
| 1.0 | 5 - Complete scope (all three hosts, both accounts, the data loss) and an accurate, timed narrative. |
| 0.75 | 4 - Between 5 and 3: meets the 3 anchor and most of the 5 anchor. |
| 0.5 | 3 - The main host and account are covered, but a host, the data loss or key steps of the narrative are missing. |
| 0.25 | 2 - Between 3 and 1: meets part of the 3 anchor. |
| 0.0 | 1 - Scope is wrong or the narrative contradicts the records. |

### ir-containment

Containment and playbook compliance. Actions are appropriate and use playbook options: isolate the beaconing hosts, disable or reset the compromised accounts, block the indicators, preserve evidence first; the crown-jewel file server is not isolated without G-6 approval; benign hosts are left alone.

**Weight:** 0.3333333333333333

| Score | Outcome |
| --- | --- |
| 1.0 | 5 - Every needed action is present, correctly targeted, in playbook terms, and every playbook rule is respected. |
| 0.75 | 4 - Between 5 and 3: meets the 3 anchor and most of the 5 anchor. |
| 0.5 | 3 - The core actions are present but one is missing, one rule is broken, or a benign host is contained. |
| 0.25 | 2 - Between 3 and 1: meets part of the 3 anchor. |
| 0.0 | 1 - Actions are missing, misdirected or violate the playbook. |

### ir-escalation

Indicators and escalation. The indicators are complete and precise (domain, both ips, implant file, task and service names), and the escalation tells the G-6 within an hour, the CPT about the data loss, and the G-3 about the compromised plans.

**Weight:** 0.3333333333333333

| Score | Outcome |
| --- | --- |
| 1.0 | 5 - Complete, precise indicators and an escalation that names every required recipient and the timing. |
| 0.75 | 4 - Between 5 and 3: meets the 3 anchor and most of the 5 anchor. |
| 0.5 | 3 - Most indicators and the G-6 report are there, but a recipient or an indicator is missing. |
| 0.25 | 2 - Between 3 and 1: meets part of the 3 anchor. |
| 0.0 | 1 - Indicators are vague or invented, or escalation is missing. |

## Deterministic checks: facts

Text-based checks are scenario-specific heuristics; read judge feedback alongside them.

| Check | Requirement |
| --- | --- |
| report-host-ws-g3-014 | The report lists WS-G3-014 as affected |
| report-host-srv-file-01 | The report lists SRV-FILE-01 as affected |
| report-host-srv-web-02 | The report lists SRV-WEB-02 as affected |
| report-no-benign-hosts | The report doesn't list WS-G6-021 or SRV-VSCAN-01 as affected |
| report-account-okafor | The report names j.okafor as compromised |
| report-account-svc-backup | The report names svc_backup as compromised |
| report-ioc-domain | The indicators include the C2 domain |
| report-ioc-c2-ip | The indicators include 203.0.113.154 |
| report-ioc-vpn-source | The indicators include the VPN source 203.0.113.77 |
| report-exfiltration | The narrative states that the PLANS / OPORD data was staged and exfiltrated |
| report-persistence | The narrative names the persistence (OneDriveSyncHelper / odsh.exe / UpdateSvcHelper) |
| contain-isolate-ws | Containment isolates WS-G3-014 |
| contain-isolate-web02 | Containment isolates or removes SRV-WEB-02 |
| contain-okafor | Containment disables or resets j.okafor |
| contain-svc-backup | Containment resets svc_backup |
| contain-block-c2 | Containment blocks the C2 domain or ip |
| contain-crown-jewel-rule | No crown-jewel server is isolated without G-6 approval (playbook rule 2) |
| contain-preserve-evidence | Evidence is preserved (memory / disk) before reimaging |
| contain-escalation | Escalation names the G-6 within 1 hour and the G-3 or CPT |

## Aggregate: focused-report

- Aggregation: **weighted_average**.
- Components: judge-report, facts.
- AEF weights verifier rows; normalized groups contribute equally where configured. See component weights below.
