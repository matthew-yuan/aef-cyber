"""Export baseline products plus the revision, adaptation checks and regression trace."""
import importlib.util
import json
import sys

import build


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The baseline exporter uses this pipeline's build paths and identical copied check modules.
base = load("v2_export", build.V2 / "export_run.py")
revision = load("revision_checks", build.HERE / "soc-eval/artifacts/check_revision/verify.py")


def export_revision(record, out, models):
    state = base.snapshot(record, "snap-revised", out, "soc") or {}
    base.write_json(out / "revised_state.json", state)
    reports = state.get("reports") or []
    report = next((r for r in reports if r.get("version") == "UPDATE-01"), {})
    (out / "revised_report.md").write_text(base.report_md(report))
    rows = revision.score(state)
    base.write_json(out / "revision_checks.json", rows)
    ver = record["metadata"].get("verifications", {})
    heading = ["# v3 incident update and report revision", "",
               "| Measurement | Score |", "| --- | --- |",
               f"| Overall (nine verifier groups, stored) | {ver.get('soc-v3', {}).get('score', 0):.2f} |",
               f"| Baseline (soc-v2, stored) | {ver.get('soc-v2', {}).get('score', 0):.2f} |",
               f"| Adaptation checks (current) | {base.weighted(rows):.2f} |",
               f"| Revision judge (stored) | {ver.get('judge-revision', {}).get('score', 0):.2f} |", "",
               "Baseline code tests use the original incident. Revision is report-only. Current checks may differ from stored scores.",
               "", "## Adaptation and regression checks", "", "| Check | Result | Description |", "| --- | --- | --- |"]
    # Baseline compromise omissions remain critical even if the later revision
    # recovers them; soc-v3 includes the original facts verifier's penalties.
    baseline_path = out / "end_state.json"
    if baseline_path.exists():
        baseline_state = json.loads(baseline_path.read_text())
        heading[2:2] = base.grading.summary(ver.get("soc-v3", {}).get("score", 0), base.verify_facts.score(baseline_state))
    heading += [f"| `{r['id']}` | {'pass' if r['result'] else 'FAIL'} | {base.cell(r['description'])} |" for r in rows]
    path = out / "scorecard.md"
    path.write_text("\n".join(heading) + "\n\n---\n\n" + path.read_text())


if __name__ == "__main__":
    base.main(sys.argv[1], output_version="v3", task_filename="soc_update.json", extra_export=export_revision)
