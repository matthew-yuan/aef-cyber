"""Export one v1 triage eval run into readable files, with a scorecard for human review.

    uv run python pipelines/v1-triage/export_run.py <task instance id>

Writes runs/v1/<instance>/ with:
  scorecard.md          scores, trap trace, code checks and judge grades
  triage.md             the analyst's triage (phase 1)
  incident_report.md    the analyst's incident report (phase 2)
  verifications.json    every verifier's rows as the run stored them
  run_record.json       the run's TaskStepContext (agent-env task get-instance)
  end_state.json        the env's final state (triage, report, role-tagged audit log)
  trajectories/         each phase's trajectory, as JSON and as a Markdown transcript
  snapshots/<step>/     each snapshot_env artifact's files as stored

The code checks are re-run on the saved end state with the current check_facts/verify.py, so a fix to
a check shows up without rerunning the eval.
"""
import json
import subprocess
import sys
from pathlib import Path

import build

sys.path.insert(0, str(build.HERE / "soc-eval" / "artifacts" / "check_facts"))
import verify  # noqa: E402  (check_facts/verify.py, the code checks)

PHASES = [("triage", "Phase 1: alert triage"), ("report", "Phase 2: incident report")]


def agent_env(*args: str) -> str:
    return subprocess.run(["agent-env", *args], check=True, capture_output=True, text=True).stdout


def expand(value):
    """value with every string that holds a JSON object or array replaced by what it parses to."""
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
    if isinstance(value, str):
        return f"```text\n{value}\n```"
    return f"```json\n{json.dumps(value, indent=2, ensure_ascii=False)}\n```"


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
            lines += [f"## {calls}. `{step.get('tool')}`", "", "Input:", "", block(step.get("input")), "",
                      "Result:", "", block(step.get("output")), ""]
        elif kind == "answer":
            lines += ["## Final answer", "", step.get("text", ""), ""]
        else:
            lines += [f"## {kind}", "", block(step), ""]
    return "\n".join(lines)


def snapshot(record: dict, step_id: str, out: Path) -> dict | None:
    """Download one snapshot_env artifact and return the env state it holds."""
    snap = record["metadata"].get("env_snapshotted_universes", {}).get(step_id)
    if not snap:
        return None
    dest = out / "snapshots" / step_id
    agent_env("artifact", "environment-universe", "get", "--id", snap["id"], "--version", str(snap["version"]),
              "--output-dir", str(dest))
    data = json.loads(next((dest / "soc").glob("*.json")).read_text())
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
    for key, title in [("affected_hosts", "Affected hosts"), ("compromised_accounts", "Compromised accounts"),
                       ("indicators", "Indicators"), ("evidence_preserved", "Evidence preserved")]:
        lines += [f"## {title}", ""] + [f"- {item}" for item in report.get(key) or ["(none)"]] + [""]
    lines += ["## Attack narrative", "", report.get("attack_narrative", ""), ""]
    lines += ["## Containment actions", "", "| Action | Target | Rationale |", "| --- | --- | --- |"]
    lines += [f"| {cell(a.get('action'))} | {cell(a.get('target'))} | {cell(a.get('rationale'))} |"
              for a in report.get("containment_actions") or [] if isinstance(a, dict)]
    lines += ["", "## Escalation", "", report.get("escalation", ""), ""]
    return "\n".join(lines)


def level(score: float) -> int:
    """A rubric_partial score (0.0-1.0) back on the 1-5 outcome scale."""
    return round(1 + 4 * score)


def weighted(rows: list[dict]) -> float:
    scored = [r for r in rows if r.get("weight")]
    return sum(r["weight"] for r in scored if r["result"]) / sum(r["weight"] for r in scored) if scored else 0.0


def scorecard(instance_id: str, record: dict, models: dict, current_rows: list[dict]) -> str:
    verifications = record["metadata"].get("verifications", {})
    facts = verifications.get("facts", {})
    overall = verifications.get("soc-v1", {})
    stored_rows = facts.get("results", [])
    rescored = [(r["id"], r["result"]) for r in stored_rows] != [(r["id"], r["result"]) for r in current_rows]
    scored = [r for r in current_rows if r.get("weight")]
    lines = ["# Scorecard: v1 alert triage and incident report", "", f"Run `{instance_id}`", "",
             f"Analyst model `{models['analyst']}`; judge model `{models['judge']}`.", "",
             "| Score | Value |", "| --- | --- |",
             f"| Overall (as stored by the run) | {overall.get('score', 0):.2f} |",
             f"| Code checks, current `check_facts/verify.py` | {weighted(current_rows):.2f} ({sum(r['result'] for r in scored)} of {len(scored)}) |"]
    for step, title in [("judge-triage", "Judge: triage"), ("judge-report", "Judge: incident report")]:
        lines.append(f"| {title} | {verifications.get(step, {}).get('score', 0):.2f} |")
    lines.append("")
    if rescored:
        lines += ["The current code checks score differently from the ones the run stored; the tables below use the current checks.", ""]
    if models["analyst"] == models["judge"]:
        lines += ["**Self-grading caveat.** The analyst and the judge are the same model, which tends to grade its own output "
                  "generously. This affects the two judge scores, not the code checks.", ""]
    lines += ["## Trap trace", "", "| Trap | In triage | In report | Diagnosis |", "| --- | --- | --- | --- |"]
    for r in current_rows:
        if r["id"].startswith("trace-"):
            lines.append(f"| {cell(r['description'].split(':')[0])} | {'yes' if r.get('in_triage') else 'no'} "
                         f"| {'yes' if r.get('in_report') else 'no'} | {cell(r.get('diagnosis'))} |")
    calls = next((r for r in current_rows if r["id"] == "tool-calls"), None)
    if calls:
        lines += ["", f"Tool calls: {calls['description']}: `{', '.join(calls.get('tools', []))}`"]
    lines += ["", "## Code checks", "", "| Check | Result | Description |", "| --- | --- | --- |"]
    lines += [f"| `{r['id']}` | {'pass' if r['result'] else 'FAIL'} | {cell(r['description'])} |" for r in scored]
    for step, title in [("judge-triage", "Judge: triage"), ("judge-report", "Judge: incident report")]:
        rows = verifications.get(step, {}).get("results", [])
        if not rows:
            continue
        lines += ["", f"## {title}", "", "| Criterion | Score | Level | Reasoning |", "| --- | --- | --- | --- |"]
        for r in rows:
            reasoning = next((r[k] for k in ("reasoning", "rationale", "explanation", "justification") if r.get(k)), "")
            sc = float(r.get("score") or 0)
            lines.append(f"| `{r.get('id') or r.get('criterion_id') or ''}` | {sc:.2f} | {level(sc)} | {cell(reasoning)} |")
    return "\n".join(lines) + "\n"


def main(instance_id: str) -> None:
    out_text = agent_env("task", "get-instance", "--id", instance_id)
    record = json.loads(out_text[out_text.find("{"):])
    out = Path("runs") / "v1" / instance_id.rsplit("/", 1)[-1]
    (out / "trajectories").mkdir(parents=True, exist_ok=True)
    write_json(out / "run_record.json", record)
    write_json(out / "verifications.json", record["metadata"].get("verifications", {}))

    snapshot(record, "snap-triage", out)
    state = snapshot(record, "snap-final", out) or {}
    write_json(out / "end_state.json", state)
    (out / "triage.md").write_text(triage_md(state.get("triage") or {}))
    (out / "incident_report.md").write_text(report_md(state.get("report") or {}))

    analyst_model = None
    for pr in record.get("prompt_responses", []):
        analyst_model = analyst_model or pr.get("model")
        steps = json.loads(Path(pr["agent_trajectory_s3_uri"].removeprefix("file://")).read_text())
        write_json(out / "trajectories" / f"{pr['prompt_id']}.json", steps)
        (out / "trajectories" / f"{pr['prompt_id']}.md").write_text(transcript(pr["prompt_id"], pr.get("model"), steps))

    judge_model = next((s.get("default_model") for s in json.loads(
        (build.HERE / "soc-eval/tasks/soc_triage.json").read_text()) if s["type"] == "rubrics_verifier"), None)
    models = {"analyst": analyst_model or build.ANALYST_MODEL, "judge": judge_model or build.JUDGE_MODEL}
    current_rows = verify.score(state)
    (out / "scorecard.md").write_text(scorecard(instance_id, record, models, current_rows))
    print(f"{out}: see scorecard.md")


if __name__ == "__main__":
    main(sys.argv[1])
