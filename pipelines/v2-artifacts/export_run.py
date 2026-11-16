"""Export one v2 artifacts eval run into readable files, with a scorecard for human review.

    uv run python pipelines/v2-artifacts/export_run.py <task instance id>

Writes runs/v2/<instance>/ with:
  scorecard.md          scores per verifier, trap trace, code checks, the scorebox rows, judge grades
  triage.md, incident_report.md, evidence_report.md   the analyst's submissions
  artifacts/            every accepted artifact, QUARANTINED: Python saved as <name>.py.txt with a banner, rules as .yml.txt
  lab_history.md        what the analyst ran and tested in the lab
  verifications.json    every verifier's rows as the run stored them (the scorebox's results.json included)
  run_record.json       the run's TaskStepContext (agent-env task get-instance)
  end_state.json        the soc env's final state; lab_state.json the lab's
  trajectories/         each phase's trajectory, as JSON and as a Markdown transcript
  snapshots/<step>/     each snapshot_env artifact's files as stored

Nothing here imports or runs analyst code: artifacts are written as text with a non-executable suffix.
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import build

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import grading  # noqa: E402


def _load_checks(name: str):
    """This project's own check module (both are called verify.py, so load each by path). Never analyst text."""
    path = build.HERE / "soc-eval" / "artifacts" / name / "verify.py"
    spec = importlib.util.spec_from_file_location(f"verify_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verify_facts = _load_checks("check_facts")
verify_artifacts = _load_checks("check_artifacts")

PHASES = [("triage", "Phase 1: alert triage"), ("report", "Phase 2: incident report"), ("evidence", "Phase 3: evidence analysis"),
          ("artifacts", "Phase 4: detection and response code")]
BANNER = "# AGENT-GENERATED CODE, exported for reading only. Never import or run it on this machine.\n"
SUFFIX = {"hunt_script": ".py.txt", "ioc_extractor": ".py.txt", "sigma_rule": ".yml.txt"}


def agent_env(*args: str) -> str:
    return subprocess.run(["agent-env", *args], check=True, capture_output=True, text=True).stdout


def expand(value):
    if isinstance(value, dict):
        return {k: expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand(v) for v in value]
    if isinstance(value, str) and value.lstrip()[:1] in ("{", "["):
        try:
            return expand(json.loads(value))
        except json.JSONDecodeError:
            pass
    return value


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(expand(value), indent=2, ensure_ascii=False) + "\n")


def block(value) -> str:
    value = expand(value)
    return f"```text\n{value}\n```" if isinstance(value, str) else f"```json\n{json.dumps(value, indent=2, ensure_ascii=False)}\n```"


def transcript(prompt_id: str, model: str, steps: list[dict]) -> str:
    lines = [f"# Trajectory: {prompt_id}", "", f"Model: `{model}`", ""]
    calls = 0
    for step in steps:
        kind = step.get("type")
        if kind == "message":
            lines += ["## Prompt", "", step.get("text", ""), ""]
        elif kind == "thought":
            lines += ["### Model note", "", step.get("text", ""), ""]
        elif kind == "tool_call":
            calls += 1
            lines += [f"## {calls}. `{step.get('tool')}`", "", "Input:", "", block(step.get("input")), "", "Result:", "", block(step.get("output")), ""]
        elif kind == "answer":
            lines += ["## Final answer", "", step.get("text", ""), ""]
        else:
            lines += [f"## {kind}", "", block(step), ""]
    return "\n".join(lines)


def snapshot(record: dict, step_id: str, out: Path, env_name: str) -> dict | None:
    snap = record["metadata"].get("env_snapshotted_universes", {}).get(step_id)
    if not snap:
        return None
    dest = out / "snapshots" / step_id
    agent_env("artifact", "environment-universe", "get", "--id", snap["id"], "--version", str(snap["version"]), "--output-dir", str(dest))
    data = json.loads(next((dest / env_name).glob("*.json")).read_text())
    if isinstance(data, dict) and "parts" in data:
        data = next(p["data"] for p in data["parts"] if p.get("data"))
    elif isinstance(data, list):
        data = next(p["data"] for p in data if isinstance(p, dict) and p.get("data"))
    return data


def cell(text) -> str:
    return " ".join(str(text or "").split()).replace("|", "\\|")


def triage_md(triage: dict) -> str:
    if not triage:
        return "# Triage\n\nNot submitted.\n"
    lines = ["# Triage", "", "| Alert | Verdict | Related hosts | Related alerts | Rationale |", "| --- | --- | --- | --- | --- |"]
    for a in triage.get("assessments") or []:
        lines.append(f"| {cell(a.get('alert_id'))} | {cell(a.get('verdict'))} | {cell(', '.join(map(str, a.get('related_hosts') or [])))} "
                     f"| {cell(', '.join(map(str, a.get('related_alerts') or [])))} | {cell(a.get('rationale'))} |")
    return "\n".join(lines) + "\n"


def report_md(report: dict) -> str:
    if not report:
        return "# Incident report\n\nNot submitted.\n"
    lines = [f"# Incident report ({report.get('version', 'INITIAL')})", "", "## Summary", "", report.get("summary", ""), ""]
    for key, title in [("affected_hosts", "Affected hosts"), ("compromised_accounts", "Compromised accounts"), ("indicators", "Indicators"), ("evidence_preserved", "Evidence preserved")]:
        lines += [f"## {title}", ""] + [f"- {item}" for item in report.get(key) or ["(none)"]] + [""]
    lines += ["## Attack narrative", "", report.get("attack_narrative", ""), "", "## Containment actions", "", "| Action | Target | Rationale |", "| --- | --- | --- |"]
    lines += [f"| {cell(a.get('action'))} | {cell(a.get('target'))} | {cell(a.get('rationale'))} |" for a in report.get("containment_actions") or [] if isinstance(a, dict)]
    lines += ["", "## Escalation", "", report.get("escalation", ""), ""]
    return "\n".join(lines)


def evidence_md(report: dict) -> str:
    if not report:
        return "# Evidence report\n\nNot submitted.\n"
    lines = ["# Evidence report", "", f"**Verdict.** {report.get('verdict', '')}", "", report.get("summary", ""), "",
             "| Item | Confidence | Finding |", "| --- | --- | --- |"]
    lines += [f"| {cell(f.get('evidence_id'))} | {cell(f.get('confidence'))} | {cell(f.get('finding'))} |" for f in report.get("findings") or [] if isinstance(f, dict)]
    for key, title in [("indicators", "Indicators"), ("recommended_actions", "Recommended actions")]:
        lines += ["", f"## {title}", ""] + [f"- {item}" for item in report.get(key) or ["(none)"]]
    return "\n".join(lines) + "\n"


def write_artifacts(state: dict, out: Path) -> list[str]:
    folder = out / "artifacts"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "QUARANTINE.md").write_text("# Quarantined analyst code\n\nThese files were written by the model under evaluation. They are saved "
                                          "with a `.txt` suffix and a banner so nothing treats them as modules. Read them; never run them here. "
                                          "Their execution results are in `../scorecard.md` (scorebox rows).\n")
    written = []
    for kind, items in (state.get("artifacts") or {}).items():
        for name, rec in (items or {}).items():
            safe = "".join(ch for ch in str(name) if ch.isalnum() or ch in "-_") or "artifact"
            path = folder / f"{kind}__{safe}{SUFFIX.get(kind, '.txt')}"
            path.write_text(BANNER + str(rec.get("content", "")))
            written.append(path.name)
    return written


def lab_md(lab: dict | None) -> str:
    if not lab:
        return "# Lab history\n\nNo lab snapshot.\n"
    lines = ["# Lab history", "", f"Budget used: {lab.get('budget', {}).get('used')} of {lab.get('budget', {}).get('limit')}", "",
             "## Script runs", "", "| # | Kind | Outcome | Exit | ms | Findings / indicators | Hosts |", "| --- | --- | --- | --- | --- | --- | --- |"]
    for i, r in enumerate(lab.get("runs") or [], 1):
        s = r.get("summary") or {}
        lines.append(f"| {i} | {r.get('kind')} | {r.get('outcome')} | {r.get('exit_code')} | {r.get('elapsed_ms')} | "
                     f"{s.get('findings', s.get('indicators', ''))} | {cell(', '.join((s.get('by_host') or {}).keys()))} |")
    lines += ["", "## Rule tests", "", "| # | Title | Valid | Source | Matched |", "| --- | --- | --- | --- | --- |"]
    for i, t in enumerate(lab.get("rule_tests") or [], 1):
        lines.append(f"| {i} | {cell(t.get('title'))} | {t.get('valid')} | {t.get('source')} | {t.get('matched')} |")
    return "\n".join(lines) + "\n"


def level(score: float) -> int:
    return round(1 + 4 * score)


def weighted(rows: list[dict]) -> float:
    scored = [r for r in rows if r.get("weight", 0) > 0]
    return sum(r["weight"] for r in scored if r["result"]) / sum(r["weight"] for r in scored) if scored else 0.0


def scorebox_results(verification: dict) -> dict | None:
    for path, content in (verification.get("extracted_files") or {}).items():
        if str(path).endswith("results.json"):
            return content if isinstance(content, dict) else None
    return None


def scorecard(instance_id: str, record: dict, models: dict, facts_rows: list[dict], artifact_rows: list[dict]) -> str:
    ver = record["metadata"].get("verifications", {})
    overall = ver.get("soc-v2", {})
    box = scorebox_results(ver.get("exec-tests", {})) or {}
    lines = ["# Scorecard: v2 triage, report, evidence analysis and response code", "", f"Run `{instance_id}`", "",
             f"Analyst model `{models['analyst']}`; judge model `{models['judge']}`.", "", "| Verifier | Score |", "| --- | --- |",
             f"| **Overall (mean of 7 verifiers, as stored)** | {overall.get('score', 0):.2f} |",
             f"| Code checks: triage and report (`facts`, current checks) | {weighted(facts_rows):.2f} |",
             f"| Code checks: artifacts and evidence (`artifact-checks`, current checks) | {weighted(artifact_rows):.2f} |",
             f"| Scorebox execution tests (`exec-tests`) | {ver.get('exec-tests', {}).get('score', 0):.2f}{' (refused: ' + str(box.get('refused')) + ')' if box.get('refused') else ''} |"]
    for step, title in [("judge-triage", "Judge: triage"), ("judge-report", "Judge: incident report"), ("judge-evidence", "Judge: evidence"), ("judge-artifacts", "Judge: code")]:
        lines.append(f"| {title} | {ver.get(step, {}).get('score', 0):.2f} |")
    lines.append("")
    failed_actions = [r for r in facts_rows + artifact_rows if r.get("action_gate") and not r.get("result")]
    if failed_actions:
        lines += ["**Action verification failure: mission score 0.00.** " + "; ".join(r["description"] for r in failed_actions), ""]
    lines += grading.summary(overall.get("score", 0), facts_rows)
    if models["analyst"] == models["judge"]:
        lines += ["**Self-grading caveat.** The analyst and the judge are the same model, which tends to grade its own output generously. "
                  "This affects the four judge scores, not the code checks or the scorebox.", ""]
    lines += ["## Scorebox (offline execution tests)", ""]
    if box:
        lines += ["| Check | Weight | Result | Description |", "| --- | --- | --- | --- |"]
        lines += [f"| `{r['id']}` | {r.get('weight', 0):.2f} | {'pass' if r['result'] else 'FAIL'} | {cell(r.get('description'))} |" for r in box.get("sandbox", []) + box.get("rows", [])]
        lines += ["", f"- **Execution reward:** {box.get('reward')}", f"- **Grader duration:** {box.get('elapsed_ms')} ms", "- **Artifacts graded:**"]
        lines += [f"  - {kind.replace('_', ' ')}: {', '.join(names) or 'None'}" for kind, names in box.get("artifacts", {}).items()]
    else:
        lines.append("No scorebox results were recorded.")
    lines += ["", "## Trap trace (triage and report)", "", "| Trap | In triage | In report | Diagnosis |", "| --- | --- | --- | --- |"]
    lines += [f"| {cell(r['description'].split(':')[0])} | {'yes' if r.get('in_triage') else 'no'} | {'yes' if r.get('in_report') else 'no'} | {cell(r.get('diagnosis'))} |"
              for r in facts_rows if r["id"].startswith("trace-")]
    for title, rows in [("Code checks: triage and report", facts_rows), ("Code checks: artifacts and evidence", artifact_rows)]:
        lines += ["", f"## {title}", "", "| Check | Result | Description |", "| --- | --- | --- |"]
        lines += [f"| `{r['id']}` | {'pass' if r['result'] else 'FAIL'} | {cell(r['description'])} |" for r in rows if r.get("weight", 0) > 0]
    for step, title in [("judge-triage", "Judge: triage"), ("judge-report", "Judge: incident report"), ("judge-evidence", "Judge: evidence"), ("judge-artifacts", "Judge: code")]:
        rows = ver.get(step, {}).get("results", [])
        if rows:
            lines += ["", f"## {title}", "", "| Criterion | Score | Level | Justification |", "| --- | --- | --- | --- |"]
            for r in rows:
                sc = float(r.get("score") or 0)
                reason = next((r[k] for k in ("justification", "reasoning", "rationale", "explanation") if r.get(k)), "")
                lines.append(f"| `{r.get('id', '')}` | {sc:.2f} | {level(sc)} | {cell(reason)} |")
    return "\n".join(lines) + "\n"


def main(instance_id: str, output_version="v2", task_filename="soc_artifacts.json", extra_export=None) -> None:
    out_text = agent_env("task", "get-instance", "--id", instance_id)
    record = json.loads(out_text[out_text.find("{"):])
    out = Path("runs") / output_version / instance_id.rsplit("/", 1)[-1]
    (out / "trajectories").mkdir(parents=True, exist_ok=True)
    write_json(out / "run_record.json", record)
    write_json(out / "verifications.json", record["metadata"].get("verifications", {}))
    for step in ("snap-triage", "snap-report", "snap-evidence"):
        snapshot(record, step, out, "soc")
    state = snapshot(record, "snap-final", out, "soc") or {}
    lab = snapshot(record, "snap-lab", out, "lab")
    write_json(out / "end_state.json", state)
    write_json(out / "lab_state.json", lab or {})
    (out / "triage.md").write_text(triage_md(state.get("triage") or {}))
    (out / "incident_report.md").write_text(report_md(state.get("report") or {}))
    (out / "evidence_report.md").write_text(evidence_md(state.get("evidence_report") or {}))
    (out / "lab_history.md").write_text(lab_md(lab))
    written = write_artifacts(state, out)
    analyst_model = None
    for pr in record.get("prompt_responses", []):
        analyst_model = analyst_model or pr.get("model")
        steps = json.loads(Path(pr["agent_trajectory_s3_uri"].removeprefix("file://")).read_text())
        write_json(out / "trajectories" / f"{pr['prompt_id']}.json", steps)
        (out / "trajectories" / f"{pr['prompt_id']}.md").write_text(transcript(pr["prompt_id"], pr.get("model"), steps))
    judge_model = next((s.get("default_model") for s in json.loads((build.HERE / "soc-eval/tasks" / task_filename).read_text()) if s["type"] == "rubrics_verifier"), None)
    models = {"analyst": analyst_model or build.ANALYST_MODEL, "judge": judge_model or build.JUDGE_MODEL}
    (out / "scorecard.md").write_text(scorecard(instance_id, record, models, verify_facts.score(state), verify_artifacts.score(state)))
    if extra_export:
        extra_export(record, out, models)
    print(f"{out}: see scorecard.md ({len(written)} quarantined artifacts)")


if __name__ == "__main__":
    main(sys.argv[1])
