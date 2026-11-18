# Evaluation rubric

This reference describes the configured task, including component weights and acceptance thresholds.

## LLM judge: judge-rules

Judge model: `openai/openai/gpt-6-sol`

### ar-detection-logic

Detection logic. The Sigma rules target the tradecraft (foreign VPN source range, service-account spray, beacons to the C2 domain, large external POST, scheduled task from a user-writable path, WMI remote process creation, service from Temp) with the right log source and condition, generalize beyond one literal value where the behavior allows, exclude the authorized scanner and audit, and carry ATT&CK tags.

**Weight:** 1.0

| Score | Outcome |
| --- | --- |
| 1.0 | 5 - Rules cover the behaviors with sound, generalizing logic, correct sources, exclusions and tags. |
| 0.75 | 4 - Between 5 and 3: meets the 3 anchor and most of the 5 anchor. |
| 0.5 | 3 - Rules catch the main behaviors but are literal (one indicator each), miss a source, or would fire on authorized activity. |
| 0.25 | 2 - Between 3 and 1: meets part of the 3 anchor. |
| 0.0 | 1 - Rules are malformed, trivial or target the wrong fields. |

## Offline code evaluation

| Rule check | Required threshold | Raw weight |
| --- | --- | --- |
| Validity | At least one valid rule; no invalid rules | 0.05 |
| Precision | At least 90%; no authorized-activity trap hits | 0.10 |
| Recall | At least 60% of malicious records | 0.10 |
| Behavior coverage | At least 4 behaviors, each with precision ≥80% and recall ≥50% | 0.10 |

Rules-only scoring normalizes these weights by their sum (0.35).

Execution requires non-root operation, no network and no model credentials; a failed isolation check refuses execution.

## Aggregate: focused-rules

- Aggregation: **weighted_average**.
- Components: judge-rules, exec-tests.
- AEF weights verifier rows; normalized groups contribute equally where configured. See component weights below.
