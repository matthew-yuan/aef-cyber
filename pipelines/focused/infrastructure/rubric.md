# Evaluation rubric

This reference describes the configured task, including component weights and acceptance thresholds.

## Deterministic checks: soc-check

Text-based checks are scenario-specific heuristics; read judge feedback alongside them.

Tool behavior, submission contracts and sandbox invariants are checked by the model-free verifier.

Required SOC behaviors:

- Expose all read/submission tools and load the incident.
- Resolve alerts, assets, intelligence and evidence; reject unknown ids.
- Filter/page logs and evidence correctly.
- Reject unsafe artifacts and incomplete submissions.
- Accept valid triage, reports and artifacts once; retain state, receipts and audit history.

## Deterministic checks: lab-check

Text-based checks are scenario-specific heuristics; read judge feedback alongside them.

Tool behavior, submission contracts and sandbox invariants are checked by the model-free verifier.

Required lab behaviors:

- List and describe the loaded log dataset; reject unknown datasets.
- Refuse banned imports before execution.
- Execute the golden hunt and IOC extractor with valid output schemas.
- Kill infinite loops at the deadline and memory bombs under the resource limit.
- Report crashes and invalid output shapes as errors.
- Test valid Sigma rules; reject unsupported rule syntax.
- Retain run history and budget counters without storing submitted code in audit entries.

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

## Functionality-check interpretation

All SOC, lab-safety and golden-scorebox checks should pass. These fixed fixtures check pipeline operation, not model reasoning.
