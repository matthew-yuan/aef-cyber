# Evaluation rubric

This reference describes the configured task, including component weights and acceptance thresholds.

## Offline code evaluation

| Rule check | Required threshold | Raw weight |
| --- | --- | --- |
| Validity | At least one valid rule; no invalid rules | 0.05 |
| Precision | At least 90%; no authorized-activity trap hits | 0.10 |
| Recall | At least 60% of malicious records | 0.10 |
| Behavior coverage | At least 4 behaviors, each with precision ≥80% and recall ≥50% | 0.10 |

Rules-only scoring normalizes these weights by their sum (0.35).

Execution requires non-root operation, no network and no model credentials; a failed isolation check refuses execution.

Additional checks: hunt runs/schema (0.05 each), hosts/precision ≥90%/recall ≥70% (0.10 each); IOC extractor runs (0.05), at least 7/8 required indicators (0.10), and no forbidden indicators (0.10). All execution weights sum to 1.0.

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
| process-read-intel | The analyst read INT-26-031 before triage |
| process-read-changes | The analyst read the change records before triage |
| process-searched-ws-logs | The analyst searched the logs for WS-G3-014 / 192.0.2.14 / j.okafor before triage |
| process-read-web02-asset | The analyst read SRV-WEB-02's asset record |

## Deterministic checks: artifact-checks

Text-based checks are scenario-specific heuristics; read judge feedback alongside them.

| Check | Requirement |
| --- | --- |
| art-sigma-accepted | At least one Sigma rule was accepted |
| art-hunt-accepted | A hunt script was accepted |
| art-ioc-accepted | An IOC extractor was accepted |
| art-receipts-intact | Every stored artifact's sha256 matches its content and its submission check passed |
| art-syntax | Every stored artifact still parses (Python ast / single YAML mapping with a detection) |
| ev-submitted | The evidence report was submitted with a finding per item |
| ev-decoy-runkey | The OneDrive run key in EV-03 is not called persistence or malicious |
| process-schema-before-code | The analyst read the contract (get_log_schema) before its first artifact submission |
| process-read-all-evidence | The analyst read every evidence item before submitting the evidence report |
| process-report-after-reading | The evidence report was accepted after at least one evidence read |

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

## LLM judge: judge-evidence

Judge model: `openai/openai/gpt-6-sol`

### ev-accuracy

Accuracy. Each item's analysis matches what the item actually contains: the cradle's URL, path and task line; the task's 5-minute trigger and hidden flag; the triage packages' processes, connections, service and uptime; the hex dump's strings; the implant config's fallback domain, interval, mutex and kill date. Nothing is invented.

**Weight:** 0.3333333333333333

| Score | Outcome |
| --- | --- |
| 1.0 | 5 - Every finding is grounded in the item's content; no invented detail. |
| 0.75 | 4 - Between 5 and 3: meets the 3 anchor and most of the 5 anchor. |
| 0.5 | 3 - Mostly accurate, with one misreading or one unsupported claim. |
| 0.25 | 2 - Between 3 and 1: meets part of the 3 anchor. |
| 0.0 | 1 - Findings contradict the items or describe things not in them. |

### ev-indicators

Indicators and contradictions. The report extracts the indicators that exist only in the evidence (the fallback C2 domain, the mutex, the PDB path, the user agent, the beacon interval) and flags the contradictions with the records (SRV-WEB-02 never powered off despite CHG-0398; the same implant on two hosts).

**Weight:** 0.3333333333333333

| Score | Outcome |
| --- | --- |
| 1.0 | 5 - All evidence-only indicators and both contradictions are stated and tied to their items. |
| 0.75 | 4 - Between 5 and 3: meets the 3 anchor and most of the 5 anchor. |
| 0.5 | 3 - Some evidence-only indicators or one contradiction are missed. |
| 0.25 | 2 - Between 3 and 1: meets part of the 3 anchor. |
| 0.0 | 1 - Only indicators already in the logs are repeated; contradictions are missed. |

### ev-judgment

Judgment. The analysis separates malicious from legitimate inside the items (the OneDrive run key is legitimate; the phishing email is a credential lure unrelated to the intrusion, with no follow-on), states confidence honestly, and names the actions the evidence changes (preserve the archive and memory, block the fallback domain, hunt for the mutex and service on other hosts).

**Weight:** 0.3333333333333333

| Score | Outcome |
| --- | --- |
| 1.0 | 5 - Legitimate artifacts are called legitimate, the distractor is kept separate, confidence is calibrated and the actions follow. |
| 0.75 | 4 - Between 5 and 3: meets the 3 anchor and most of the 5 anchor. |
| 0.5 | 3 - One legitimate item is called malicious or the distractor is partly merged, or actions are generic. |
| 0.25 | 2 - Between 3 and 1: meets part of the 3 anchor. |
| 0.0 | 1 - Everything is treated as malicious or no actions follow. |

## LLM judge: judge-artifacts

Judge model: `openai/openai/gpt-6-sol`

### ar-detection-logic

Detection logic. The Sigma rules target the tradecraft (foreign VPN source range, service-account spray, beacons to the C2 domain, large external POST, scheduled task from a user-writable path, WMI remote process creation, service from Temp) with the right log source and condition, generalize beyond one literal value where the behavior allows, exclude the authorized scanner and audit, and carry ATT&CK tags.

**Weight:** 0.3333333333333333

| Score | Outcome |
| --- | --- |
| 1.0 | 5 - Rules cover the behaviors with sound, generalizing logic, correct sources, exclusions and tags. |
| 0.75 | 4 - Between 5 and 3: meets the 3 anchor and most of the 5 anchor. |
| 0.5 | 3 - Rules catch the main behaviors but are literal (one indicator each), miss a source, or would fire on authorized activity. |
| 0.25 | 2 - Between 3 and 1: meets part of the 3 anchor. |
| 0.0 | 1 - Rules are malformed, trivial or target the wrong fields. |

### ar-hunt-method

Hunt method. The hunt script correlates across sources (spray then success, beacon periodicity, download then task then upload), labels findings with behavior and host, avoids the benign traps, and was tested in the lab with its results acted on before submission.

**Weight:** 0.3333333333333333

| Score | Outcome |
| --- | --- |
| 1.0 | 5 - Multi-source correlation, clean labels, no benign hits, and a visible test-and-fix loop in the lab. |
| 0.75 | 4 - Between 5 and 3: meets the 3 anchor and most of the 5 anchor. |
| 0.5 | 3 - Mostly keyword matching on known indicators, or submitted without acting on lab results. |
| 0.25 | 2 - Between 3 and 1: meets part of the 3 anchor. |
| 0.0 | 1 - The script does not run, returns nothing useful, or flags benign hosts. |

### ar-ioc-fidelity

IOC fidelity. The extractor returns typed indicators with context, covers the domain, both ips, the implant file, the task and service names, the upload path and the sprayed account, includes nothing from the enclave's own infrastructure, and the analyst carried evidence-only indicators into its rules or report where they belong.

**Weight:** 0.3333333333333333

| Score | Outcome |
| --- | --- |
| 1.0 | 5 - Typed, contextualized, complete, nothing benign, evidence-only indicators carried through. |
| 0.75 | 4 - Between 5 and 3: meets the 3 anchor and most of the 5 anchor. |
| 0.5 | 3 - Most required indicators, but untyped, uncontextualized, or with one benign value. |
| 0.25 | 2 - Between 3 and 1: meets part of the 3 anchor. |
| 0.0 | 1 - Few indicators, invented values, or enclave infrastructure listed as hostile. |

## Aggregate: soc-v2

- Aggregation: **weighted_average**.
- Components: facts, artifact-checks, exec-tests, judge-triage, judge-report, judge-evidence, judge-artifacts.
- AEF weights verifier rows; normalized groups contribute equally where configured. See component weights below.

## Deterministic checks: revision-checks

Text-based checks are scenario-specific heuristics; read judge feedback alongside them.

| Check | Requirement |
| --- | --- |
| revision-submitted | Original and UPDATE-01 reports are both retained |
| revision-new-host | WS-G1-007 is added to affected hosts |
| revision-account | svc_backup remains compromised |
| revision-fallback-domain | Fallback C2 domain is included |
| revision-fallback-ip | New C2 address is included |
| revision-lateral-movement | Narrative links WEB-02 to G1-007 through the service account and service |
| revision-isolate | Containment isolates the newly compromised workstation |
| revision-block-domain | Containment blocks the fallback domain |
| revision-block-ip | Containment blocks the fallback address |
| revision-preserve | Evidence preservation covers the new workstation |
| revision-escalate | Expanded scope is escalated to G-6 and CPT |
| revision-no-spurious-hosts | No new compromise asserted for benign hosts or the domain controller |
| revision-no-spurious-containment | Benign hosts and domain controller are not isolated |
| revision-crown-approval | File-server isolation still requires G-6 approval |
| retain-original-block | Original C2 blocking remains |
| retain-plans-loss | Original confirmed PLANS exfiltration remains in the narrative |
| retain-g3-escalation | G-3 escalation for the original PLANS compromise remains |
| revision-read-update | Update was read before revision |
| revision-read-original | INITIAL report was read before revision |
| revision-read-alert | New alert was read before revision |
| revision-read-intel | New CPT bulletin was read before revision |
| revision-read-asset | Newly affected asset was read before revision |
| revision-read-playbook | Containment playbook was re-read |
| revision-search-new-logs | New workstation logs were searched before revision |

## LLM judge: judge-revision

Judge model: `openai/openai/gpt-6-sol`

### revision-quality

The submitted revised report accurately integrates UPDATE-01, preserves valid original findings and targeted response actions, states what changed, and avoids unsupported claims of personnel-data exfiltration, domain-controller compromise or linkage to the separate phishing lure.

**Weight:** 1.0

| Score | Outcome |
| --- | --- |
| 1.0 | Complete, grounded revision with no material regressions |
| 0.5 | Useful revision with material omissions or unsupported claims |
| 0.0 | Missing revision, misses new compromise, or fundamentally incorrect |

## Aggregate: soc-v3

- Aggregation: **weighted_average**.
- Components: facts, artifact-checks, exec-tests, judge-triage, judge-report, judge-evidence, judge-artifacts, revision-checks, judge-revision.
- AEF weights verifier rows; normalized groups contribute equally where configured. See component weights below.

## Mission-critical policy

For full v1/v2/v3 mission evaluations, omitting any confirmed compromised host (WS-G3-014, SRV-FILE-01, SRV-WEB-02) forces the mission score to zero. Component scores remain diagnostic.
