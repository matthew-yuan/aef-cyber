"""Durable, bounded trial batches; each child remains a normal dashboard run."""
import json
import math
import os
import subprocess
import sys

import uuid

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from webapp.store import PIPELINES, ROOT, STATE, read, save

TERMINAL = {"completed", "failed", "interrupted"}


def now():
    return datetime.now(timezone.utc).isoformat()


def write_batch(folder, record):
    folder.mkdir(parents=True, exist_ok=True)
    temp = folder / f"batch.{os.getpid()}.tmp"
    temp.write_text(json.dumps(record, indent=2))
    temp.replace(folder / "batch.json")


def alive(pid):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def create_batch(pipelines, k, concurrency, model, judge_model, success_threshold, *, state=None, root=None, custom_rubric=None):
    state, root = state or STATE, root or ROOT
    batch_id = uuid.uuid4().hex
    folder = state / "batches" / batch_id
    batch = {"id": batch_id, "pipelines": pipelines, "k": k, "concurrency": concurrency,
             "model": model, "judge_model": judge_model, "success_threshold": success_threshold,
             "status": "queued", "created_at": now(), "run_ids": []}
    if custom_rubric:
        batch["custom_rubric"] = custom_rubric
    for trial in range(1, k + 1):
        for pipeline in pipelines:
            run_id = uuid.uuid4().hex
            batch["run_ids"].append(run_id)
            save(state / run_id, {"id": run_id, "batch_id": batch_id, "trial": trial,
                 "pipeline": pipeline, "name": PIPELINES[pipeline]["name"], "model": model,
                 "judge_model": judge_model, "status": "queued", "created_at": now(), "steps": {},
                 "message": "Queued in batch"})
    write_batch(folder, batch)
    try:
        with (folder / "output.log").open("w") as log:
            process = subprocess.Popen([sys.executable, "-u", "-m", "webapp.batch_worker", batch_id],
                                       cwd=root, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        (folder / "pid").write_text(str(process.pid))
    except Exception as exc:
        batch.update(status="failed", error=f"Coordinator could not start: {type(exc).__name__}", finished_at=now())
        write_batch(folder, batch)
        for run_id in batch["run_ids"]:
            child = read(state / run_id)
            child.update(status="failed", error=batch["error"], finished_at=now())
            save(state / run_id, child)
        raise
    return batch


def trial_success(record, threshold):
    if record["status"] != "completed" or record.get("export_error"):
        return False
    results = record.get("results") or []
    if not results:
        return False
    for result in results:
        if result.get("outcome") in ("failed", "cancelled", "unscored"):
            return False
        if any(g.get("critical_failure") for g in result.get("grading", {}).values()):
            return False
        verifications = result.get("context", {}).get("metadata", {}).get("verifications", {})
        for verification in verifications.values():
            for value in verification.get("extracted_files", {}).values():
                if isinstance(value, dict) and value.get("refused"):
                    return False
        scores = dict(result.get("scores") or {})
        scores = {**{key: value.get("score") for key, value in verifications.items()}, **scores}
        if record.get("custom_rubric"):
            custom_score = scores.get("custom-rubric")
            if not isinstance(custom_score, (int, float)) or not math.isfinite(custom_score) or custom_score <= 0 or custom_score < threshold:
                return False
        # Step-ID keyed AEF scores are supplemented with verifier-ID scores.
        if any(row.get("critical") and row.get("result") is not True
               for verification in verifications.values() for row in verification.get("results", [])):
            return False
        primary = next((s for s in ("soc-v3", "soc-v2", "soc-v1", "focused-rules", "focused-triage", "focused-report") if s in scores), None)
        values = [scores[primary]] if primary else [scores.get(s, scores.get(alias)) for s, alias in
                    (("soc-smoke", "soc-check"), ("lab-smoke", "lab-check"), ("exec-tests", "scorebox-exec-tests"))]
        if any(not isinstance(v, (int, float)) or not math.isfinite(v) or v <= 0 or v < threshold for v in values):
            return False
    return True


def wilson(successes, total):
    if not total:
        return None
    z = 1.96
    p = successes / total
    denominator = 1 + z*z / total
    center = (p + z*z / (2*total)) / denominator
    half = z * math.sqrt(p*(1-p)/total + z*z/(4*total*total)) / denominator
    return [max(0, center-half), min(1, center+half)]


def batch_detail(folder, *, state=None):
    state = state or STATE
    batch = json.loads((folder / "batch.json").read_text())
    children = [read(state / run_id) for run_id in batch["run_ids"]]
    for child in children:
        worker_pid = state / child["id"] / "pid"
        if child["status"] not in TERMINAL and worker_pid.exists() and not alive(int(worker_pid.read_text())):
            child.update(status="interrupted", error="Trial worker exited without recording completion", finished_at=now())
            save(state / child["id"], child)
        results_path = state / child["id"] / "results.json"
        if child["status"] in TERMINAL and results_path.exists():
            child["results"] = json.loads(results_path.read_text())
    pid_file = folder / "pid"
    launching = not pid_file.exists() and (datetime.now(timezone.utc) - datetime.fromisoformat(batch["created_at"])).total_seconds() < 10
    coordinator_alive = launching or (alive(int(pid_file.read_text())) if pid_file.exists() else False)
    # A dead coordinator cannot schedule queued work. Active child processes may
    # finish; don't mistake their disappearance for successful completion.
    if batch["status"] not in TERMINAL and not coordinator_alive:
        for child in children:
            child_pid = state / child["id"] / "pid"
            if child["status"] not in TERMINAL and not (child_pid.exists() and alive(int(child_pid.read_text()))):
                child.update(status="interrupted", error="Batch coordinator exited", finished_at=now())
                save(state / child["id"], child)
        batch.update(status="interrupted", finished_at=now(), error="Batch coordinator exited; active children may still be finishing")
        write_batch(folder, batch)
    batch["counts"] = dict(Counter(c["status"] for c in children))
    batch["scenarios"] = []
    for pipeline in batch["pipelines"]:
        trials = [c for c in children if c["pipeline"] == pipeline]
        finished = [c for c in trials if c["status"] in TERMINAL]
        successes = sum(trial_success(c, batch["success_threshold"]) for c in finished)
        total = len(trials)
        batch["scenarios"].append({"pipeline": pipeline, "total": total, "completed": len(finished),
            "failed": sum(c["status"] in ("failed", "interrupted") for c in finished), "successes": successes,
            "success_rate": successes/len(finished) if finished else None,
            "confidence_interval_95": wilson(successes, len(finished)),
            "all_trials_passed": successes == total if len(finished) == total else None,
            "any_trial_passed": successes > 0 if len(finished) == total else None})
    start = batch.get("started_at") or batch["created_at"]
    end = batch.get("finished_at") or now()
    batch["elapsed_seconds"] = max(0, (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds())
    return batch
