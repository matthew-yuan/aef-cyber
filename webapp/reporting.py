"""Human-readable Markdown projections of stored evaluation evidence; never execute agent content."""
import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def cell(value):
    return str(value if value is not None else "—").replace("|", "\\|").replace("\n", "<br>")


def percent(value):
    return f"{float(value):.1%}" if isinstance(value, (int, float)) else "—"


def table(headers, rows):
    return ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |", *[
        "| " + " | ".join(cell(v) for v in row) + " |" for row in rows], ""]


def scorebox(verification):
    return next((v for k, v in verification.get("extracted_files", {}).items()
                 if k.endswith("results.json") and isinstance(v, dict)), {})


def scorecard(title, verifications):
    lines = [f"# {title}", "", "Scores range from 0 to 1; higher is better. Execution success and evaluation quality are separate.", ""]
    lines += table(["Grading component", "Score"], [(k.replace("-", " ").title(), f"{v.get('score', 0):.3f}") for k, v in verifications.items()])
    for name, verification in verifications.items():
        box = scorebox(verification)
        rows = box.get("rows", []) if box else verification.get("results", [])
        if not rows:
            continue
        lines += [f"## {name.replace('-', ' ').title()}", ""]
        if box.get("refused"):
            lines += [f"**Execution refused:** {box['refused']}", ""]
        judges = [r for r in rows if "criterion" in r]
        if judges:
            for row in judges:
                lines += [f"### {row.get('id', 'Criterion')}", "", f"**Score: {row.get('score', 0):.2f} / 1.00**", "",
                          row.get("criterion", ""), "", "**Judge feedback**", "",
                          next((row[k] for k in ("justification", "reasoning", "explanation", "rationale") if row.get(k)), "No feedback recorded."), ""]
        else:
            lines += table(["Check", "Result", "What was observed"], [
                (r.get("id", "Check").replace("-", " "), "PASS" if r.get("result") else "FAIL",
                 r.get("description") or r.get("message") or "No description recorded") for r in rows])
        if box:
            lab = box.get("lab_testing")
            if lab:
                lines += ["### Verified lab use", "", "Exact submitted bytes require a successful lab test before acceptance.", ""]
                lines += table(["Artifact", "Kind", "Test verified"], [
                    (a["name"], a["kind"], "PASS" if a["tested"] else "FAIL — missing, failed, late or different bytes")
                    for a in lab.get("artifacts", [])])
            lines += ["### Isolation checks", ""] + table(["Check", "Result", "Observation"], [
                (r["id"], "PASS" if r["result"] else "FAIL", r.get("description", "")) for r in box.get("sandbox", [])])
            sigma = box.get("details", {}).get("sigma", {})
            union = sigma.get("union", {})
            if sigma:
                lines += ["### Detection performance", "",
                          f"- **Precision:** {percent(union.get('precision'))} — proportion of flagged records that are malicious.",
                          f"- **Recall:** {percent(union.get('recall'))} — proportion of malicious records detected.",
                          "- Precision and recall are measured across the union of all submitted rules.", ""]
                lines += table(["Rule", "Log source", "Matches", "True positives", "False positives", "Precision"], [
                    (r.get("title"), r.get("source"), r.get("matched"), r.get("tp"), r.get("fp"), percent(r.get("precision"))) for r in sigma.get("rules", [])])
                lines += ["### Behavior coverage", ""] + table(["Behavior", "Covered", "Recall", "Best matching rule"], [
                    (k.replace("_", " "), "Yes" if v.get("detected") else "No", percent(v.get("recall")), v.get("best_rule"))
                    for k, v in sigma.get("behaviors", {}).items()])
    return "\n".join(lines) + "\n"


def product(kind, data):
    if not data:
        return f"# {kind.title()}\n\nNot submitted.\n"
    if kind == "triage":
        return "\n".join(["# Alert triage", ""] + table(["Alert", "Verdict", "Rationale", "Related hosts"], [
            (a.get("alert_id"), a.get("verdict", "").replace("_", " "), a.get("rationale"), ", ".join(a.get("related_hosts", [])))
            for a in data.get("assessments", [])]))
    lines = ["# Incident report", ""]
    for field, title in (("summary", "Summary"), ("affected_hosts", "Affected hosts"), ("compromised_accounts", "Compromised accounts"),
                         ("indicators", "Indicators"), ("attack_narrative", "Attack narrative"), ("containment_actions", "Containment actions"),
                         ("escalation", "Escalation"), ("evidence_preserved", "Evidence preservation")):
        value = data.get(field)
        lines += [f"## {title}", ""]
        if field == "containment_actions":
            lines += table(["Action", "Target", "Rationale"], [(a.get("action"), a.get("target"), a.get("rationale")) for a in value or []])
        elif isinstance(value, list):
            lines += [f"- {item}" for item in value] + [""]
        else:
            lines += [str(value or "Not provided."), ""]
    return "\n".join(lines)


def deterministic_checks(path):
    """Extract documented check descriptions without loading or running verifier code."""
    if not path.exists():
        return []
    tree = ast.parse(path.read_text())
    checks = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Tuple) and len(node.elts) >= 3 and all(isinstance(x, ast.Constant) and isinstance(x.value, str) for x in node.elts[:2]):
            key, description = (x.value for x in node.elts[:2])
            if key.startswith(("triage-", "report-", "contain-", "process-", "revision-", "retain-", "art-", "ev-")):
                checks.append((key, description))
    return list(dict.fromkeys(checks))


def rubric(steps, bundle):
    lines = ["# Evaluation rubric", "", "This reference describes the configured task, including component weights and acceptance thresholds.", ""]
    for step in steps:
        if step["type"] == "aggregate_verifiers":
            lines += [f"## Aggregate: {step.get('verifier_id', step['id'])}", "",
                      f"- Aggregation: **{step.get('score_aggregator', 'weighted average')}**.",
                      "- Components: " + ", ".join(step.get("verifier_ids", [])) + ".",
                      "- AEF weights verifier rows; normalized groups contribute equally where configured. See component weights below.", ""]
        if step["type"] == "rubrics_verifier":
            lines += [f"## LLM judge: {step['id']}", "", f"Judge model: `{step.get('default_model', 'configured model')}`", ""]
            for c in step.get("criteria", []):
                lines += [f"### {c['id']}", "", c["criterion"], "", f"**Weight:** {c.get('weight', 1)}", ""]
                lines += table(["Score", "Outcome"], [(o.get("score"), o.get("label")) for o in c.get("outcomes", [])])
        if step["type"] == "env_outcome_verifier":
            checks = deterministic_checks(bundle / "artifacts" / step["file_artifact_id"] / "verify.py")
            if bundle.name in ("triage", "report"):
                prefixes = ("triage-", "process-") if bundle.name == "triage" else ("report-", "contain-")
                checks = [c for c in checks if c[0].startswith(prefixes)]
            lines += [f"## Deterministic checks: {step['id']}", "", "Text-based checks are scenario-specific heuristics; read judge feedback alongside them.", ""]
            lines += table(["Check", "Requirement"], checks) if checks else ["Tool behavior, submission contracts and sandbox invariants are checked by the model-free verifier.", ""]
            if step.get("file_artifact_id") == "check_lab":
                lines += ["Required lab behaviors:", "", "- List and describe the loaded log dataset; reject unknown datasets.",
                          "- Refuse banned imports before execution.", "- Execute the golden hunt and IOC extractor with valid output schemas.",
                          "- Kill infinite loops at the deadline and memory bombs under the resource limit.",
                          "- Report crashes and invalid output shapes as errors.",
                          "- Test valid Sigma rules; reject unsupported rule syntax.",
                          "- Retain run history and budget counters without storing submitted code in audit entries.", ""]
            if step.get("file_artifact_id") == "check_soc":
                lines += ["Required SOC behaviors:", "", "- Expose all read/submission tools and load the incident.",
                          "- Resolve alerts, assets, intelligence and evidence; reject unknown ids.",
                          "- Filter/page logs and evidence correctly.", "- Reject unsafe artifacts and incomplete submissions.",
                          "- Accept valid triage, reports and artifacts once; retain state, receipts and audit history.", ""]
        if step["type"] == "run_container_unit_tests_verifier":
            lines += ["## Offline code evaluation", "",
                      "| Rule check | Required threshold | Raw weight |", "| --- | --- | --- |",
                      "| Validity | At least one valid rule; no invalid rules | 0.05 |",
                      "| Precision | At least 90%; no authorized-activity trap hits | 0.10 |",
                      "| Recall | At least 60% of malicious records | 0.10 |",
                      "| Behavior coverage | At least 4 behaviors, each with precision ≥80% and recall ≥50% | 0.10 |", "",
                      "Rules-only scoring normalizes these weights by their sum (0.35).", "",
                      "Execution requires non-root operation, no network and no model credentials; a failed isolation check refuses execution.", ""]
            if "--only sigma" not in step.get("command", ""):
                lines += ["Additional checks: hunt runs/schema (0.05 each), hosts/precision ≥90%/recall ≥70% (0.10 each); "
                          "IOC extractor runs (0.05), at least 7/8 required indicators (0.10), and no forbidden indicators (0.10). "
                          "All execution weights sum to 1.0.", ""]
            if "--require-lab" in step.get("command", ""):
                lines += ["**Verified action credit:** execution reward = 80% functional tests + 20% successful exact-hash "
                          "lab tests before accepted submission. Claims, screening, failed tests and tests of different bytes earn no lab credit.", ""]
    if bundle.name == "infrastructure":
        lines += ["## Functionality-check interpretation", "", "All SOC, lab-safety and golden-scorebox checks should pass. "
                  "These fixed fixtures check pipeline operation, not model reasoning.", ""]
    if bundle.name == "soc-eval":
        lines += ["## Mission-critical policy", "", "For full v1/v2/v3 mission evaluations, omitting any confirmed compromised host "
                  "(WS-G3-014, SRV-FILE-01, SRV-WEB-02) forces the mission score to zero. Component scores remain diagnostic.", ""]
    return "\n".join(lines)


def write_rubric(pipeline, out, root=None):
    from webapp.store import PIPELINES
    bundle = (root or ROOT) / PIPELINES[pipeline]["bundle"]
    steps = [s for path in sorted((bundle / "tasks").glob("*.json")) for s in json.loads(path.read_text())]
    text = rubric(steps, bundle)
    out.mkdir(parents=True, exist_ok=True)
    (out / "rubric.md").write_text(text)
    return text
