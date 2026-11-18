# Focused evaluation scenarios

Build with `uv run python pipelines/focused/build.py` after rebuilding v2's source contexts.
The dashboard rebuilds these bundles when launching them with the selected analyst and judge models.

| Scenario | Product | Deterministic grade | LLM grade |
| --- | --- | --- | --- |
| rules | Model-generated Sigma rules, tested in lab | Offline rule validity, precision, recall and behavior coverage, normalized over Sigma checks only | Detection logic rubric only |
| triage | Model's alert assessments | Triage verdict/correlation and investigation-process checks only | Verdict accuracy, evidence and correlation |
| report | Independently investigated incident report | Report and containment checks only | Scope/narrative, containment and escalation |
| infrastructure | Fixed smoke fixtures; no model | SOC tools/submissions, lab sandbox checks and golden offline scoring | None |

Each focused model scenario has exactly one generation phase, a final snapshot, two equally weighted
verifier groups and an aggregate. Missing unrelated products are not penalized. Reports investigate
the environment without assuming that a prior triage phase ran. Rules generate only Sigma YAML;
missing Python hunt/IOC artifacts are not scored. The trusted Sigma evaluator runs in the offline
scorebox with networking disabled and credentials blanked.

The infrastructure scenario runs all three former smoke checks in one AEF task; it resets/reseeds
the SOC only after its smoke submissions have been checked, before submitting golden scorebox fixtures.
Existing standalone smoke bundles remain available through the CLI for debugging.

Focused results are exported under `runs/<scenario>/<instance>/`, including a Markdown scorecard,
submitted product, verifier JSON and state snapshot. Rules are exported with non-executable `.yml.txt`
extensions as well as a Markdown reading view. These scenarios reuse the same incident, not held-out data.
