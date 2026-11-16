"""One process per evaluation: AEF owns execution, signal handling and sandbox teardown."""
import json
import os
import re
import subprocess
import sys
import traceback
from threading import Event, Thread
from datetime import datetime, timezone
from pathlib import Path

from webapp.store import PIPELINES, ROOT, STATE, read, save
from webapp.workflow import workflow
from grading import assess


def now():
    return datetime.now(timezone.utc).isoformat()


def main(run_id):
    from agent_env.bundle.run import run_bundle

    folder = STATE / run_id
    record = read(folder)
    pipeline = PIPELINES[record["pipeline"]]
    workspace = Path(record["workspace_path"]) if record.get("workspace_path") else ROOT
    if record.get("workspace_path"):
        # Config resolution and exporter imports must use this frozen batch, not
        # task files another worker or the user might rebuild in the checkout.
        os.chdir(workspace)
    record.update(status="running", started_at=now(), steps={}, pid=os.getpid())
    save(folder, record)
    stopped = Event()

    def heartbeat():
        while not stopped.wait(3):
            (folder / "heartbeat").write_text(now())

    (folder / "heartbeat").write_text(now())
    heartbeat_thread = Thread(target=heartbeat, daemon=True)
    heartbeat_thread.start()

    def progress(line):
        print(line, flush=True)
        record["message"] = line
        match = re.search(r"step (\d+)/(\d+) (\S+) (.*)", line)
        if match:
            number, total, step, detail = match.groups()
            record["total_steps"] = int(total)
            previous = record["steps"].get(step, {})
            record["steps"][step] = {"number": int(number), "status": "completed" if detail.startswith("done") else "running", "detail": detail,
                                      "started_at": previous.get("started_at", now())}
            record["last_progress_at"] = now()
        save(folder, record)

    try:
        if pipeline["model"]:
            if not os.getenv("LITELLM_BASE_URL") or not os.getenv("LITELLM_API_KEY"):
                raise ValueError("Export LITELLM_BASE_URL and LITELLM_API_KEY in the dashboard server's shell first")
            model = record.get("model") or os.getenv("CYBER_ANALYST_MODEL", "openai/openai/gpt-5")
            judge = record.get("judge_model") or os.getenv("CYBER_JUDGE_MODEL", "openai/openai/gpt-6-sol")
            os.environ.update(CYBER_ANALYST_MODEL=model, CYBER_JUDGE_MODEL=judge)
            record.update(model=model, judge_model=judge)
            # Rebuild sequentially so generated task prompts, model ids and copied contexts stay consistent.
            versions = ["v1-triage"] if record["pipeline"] == "v1" else ["v2-artifacts"]
            if record["pipeline"] == "v3":
                versions.append("v3-update")
            if not record.get("workspace_path"):
                for version in versions:
                    subprocess.run([sys.executable, f"pipelines/{version}/build.py"], cwd=ROOT, check=True, timeout=60)
        if pipeline.get("build") and not record.get("workspace_path"):
            subprocess.run([sys.executable, pipeline["build"]], cwd=ROOT, check=True, timeout=60)
        record["workflow"] = workflow(record["pipeline"], workspace) if record.get("workspace_path") else workflow(record["pipeline"])
        from webapp.inputs import scenario_inputs
        inputs = scenario_inputs(record["pipeline"], workspace)
        inputs["source"] = "Scenario inputs captured before this run; records are retrieved through tools, not all sent in the prompt"
        (folder / "inputs.json").write_text(json.dumps(inputs, indent=2))
        save(folder, record)
        result = run_bundle(Path(record["bundle_path"]) if record.get("bundle_path") else workspace / pipeline["bundle"],
                            model=record.get("model") or None, on_progress=progress)
        runs = []
        for run in result.runs:
            context = run.context.to_safe_dict()
            verifications = context.get("metadata", {}).get("verifications", {})
            facts_rows = verifications.get("facts", {}).get("results", [])
            scores = dict(run.scores)
            # AEF run.scores uses step IDs; retain named verifier scores as well
            # so batch reliability can unambiguously select the final aggregate.
            for verifier_id, verification in verifications.items():
                if "score" in verification:
                    scores[verifier_id] = verification["score"]
            grades = {}
            for score_id in ("soc-v1", "soc-v2", "soc-v3"):
                if score_id in scores or score_id in verifications:
                    raw = verifications.get(score_id, {}).get("score", scores.get(score_id, 0))
                    grades[score_id] = assess(raw, facts_rows)
                    scores[score_id] = grades[score_id]["score"]
            runs.append({"instance_id": run.instance_id, "outcome": run.outcome.value,
                         "scores": scores, "grading": grades, "duration": run.duration, "context": context})
            if run.error:
                record["error"] = str(run.error)
            if pipeline.get("focused") and run.error is None and not run.failed_steps:
                from webapp.focused_export import export_focused
                record["export_path"] = export_focused(record["pipeline"], run.instance_id, context)
            if pipeline.get("export") and run.instance_id and run.error is None and not run.failed_steps:
                record["message"] = "Exporting scorecards and reports"
                save(folder, record)
                exported = subprocess.run([sys.executable, str(workspace / pipeline["export"]), run.instance_id], cwd=ROOT,
                                          capture_output=True, text=True, timeout=180)
                print(exported.stdout, exported.stderr, flush=True)
                if exported.returncode:
                    record["export_error"] = exported.stderr[-3000:]
                else:
                    record["export_path"] = str((ROOT / "runs" / record["pipeline"] / run.instance_id.rsplit("/", 1)[-1]).relative_to(ROOT))
            from webapp.reporting import write_rubric, scorecard
            if not record.get("export_path"):
                out = ROOT / "runs" / record["pipeline"] / run.instance_id.rsplit("/", 1)[-1]
                out.mkdir(parents=True, exist_ok=True)
                (out / "scorecard.md").write_text(scorecard(record["name"], verifications))
                record["export_path"] = str(out.relative_to(ROOT))
            write_rubric(record["pipeline"], ROOT / record["export_path"], workspace)
            (ROOT / record["export_path"] / "grading_details.md").write_text(scorecard("Detailed grading evidence", verifications))
        (folder / "results.json").write_text(json.dumps(runs, indent=2, default=str))
        record.update(status="failed" if result.failed else "completed", results=[{k: v for k, v in r.items() if k != "context"} for r in runs])
    except BaseException as exc:
        record.update(status="failed", error=f"{type(exc).__name__}: {exc}")
        traceback.print_exc()
    finally:
        stopped.set()
        heartbeat_thread.join(timeout=4)
        record["message"] = "Evaluation completed; results ready" if record.get("status") == "completed" else "Evaluation failed; inspect the execution log"
        record["finished_at"] = now()
        save(folder, record)


if __name__ == "__main__":
    main(sys.argv[1])
