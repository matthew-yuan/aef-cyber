"""A process coordinator: immutable task inputs, bounded subprocesses, clean trials."""
import fcntl
import json
import hashlib
import os
import shutil
import signal
import subprocess
import sys
from threading import Event

from webapp.batches import now, write_batch, TERMINAL
from webapp.store import ROOT, STATE, PIPELINES, read, save


def prepare_workspace(folder, batch, *, root=None):
    root = root or ROOT
    workspace = folder / "workspace"
    workspace.mkdir(exist_ok=True)
    for directory in ("pipelines", "soc-env", "agents", ".agentenv"):
        shutil.copytree(root / directory, workspace / directory, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy2(root / "grading.py", workspace / "grading.py")
    env = {**os.environ, "CYBER_ANALYST_MODEL": batch["model"], "CYBER_JUDGE_MODEL": batch["judge_model"]}
    # Build once in this snapshot, never concurrently in the source checkout.
    for version in ("v1-triage", "v2-artifacts", "v3-update", "focused"):
        subprocess.run([sys.executable, str(workspace / "pipelines" / version / "build.py")],
                       cwd=workspace, env=env, check=True, timeout=120)
    # Freeze external registry references so a re-registration cannot change later trials.
    from agent_env.env import Env
    from agent_env.artifact import Artifact
    for pipeline in batch["pipelines"]:
        for task in (workspace / PIPELINES[pipeline]["bundle"] / "tasks").glob("*.json"):
            steps = json.loads(task.read_text())
            for step in steps:
                if step["type"] == "deploy_env" and not step.get("env_version"):
                    step["env_version"] = Env.get(step["env_id"]).version
                if step["type"] == "load_artifact" and step.get("artifact_id") and not step.get("artifact_version"):
                    step["artifact_version"] = Artifact.get(step["artifact_id"]).version
            task.write_text(json.dumps(steps, indent=2) + "\n")
    digest = hashlib.sha256()
    for path in sorted(workspace.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            digest.update(str(path.relative_to(workspace)).encode())
            digest.update(path.read_bytes())
    batch["input_sha256"] = digest.hexdigest()
    return workspace


def prepare_trial(folder, workspace, pipeline):
    """A separate bundle namespace and instance-derived snapshot IDs per trial."""
    bundle = folder / "bundle"
    shutil.copytree(workspace / PIPELINES[pipeline]["bundle"], bundle, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for path in (bundle / "tasks").glob("*.json"):
        steps = json.loads(path.read_text())
        for step in steps:
            if step["type"] == "snapshot_env":
                step.pop("snapshot_id", None)  # AEF derives it from the unique run instance.
        path.write_text(json.dumps(steps, indent=2) + "\n")
    return bundle


def coordinate(batch_id):
    folder = STATE / "batches" / batch_id
    batch = json.loads((folder / "batch.json").read_text())
    children = {}
    stopped = False

    def stop(signum, frame):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    # Also guard against separate dashboard server processes racing a launch.
    with (STATE / "batch-execution.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            batch.update(status="failed", error="Another batch coordinator is active", finished_at=now())
            write_batch(folder, batch)
            for run_id in batch["run_ids"]:
                rec = read(STATE / run_id)
                rec.update(status="failed", error=batch["error"], finished_at=now())
                save(STATE / run_id, rec)
            return
        try:
            batch.update(status="running", started_at=now(), message="Freezing and building scenario inputs")
            write_batch(folder, batch)
            workspace = prepare_workspace(folder, batch)
            batch["workspace_path"] = str(workspace)
            batch["message"] = "Running bounded, isolated trials"
            write_batch(folder, batch)
            pending = list(batch["run_ids"])
            stop_sent = False
            while pending or children:
                while pending and len(children) < batch["concurrency"] and not stopped:
                    run_id = pending.pop(0)
                    rec = read(STATE / run_id)
                    bundle = prepare_trial(STATE / run_id, workspace, rec["pipeline"])
                    rec.update(workspace_path=str(workspace), bundle_path=str(bundle), message="Starting isolated trial")
                    save(STATE / run_id, rec)
                    log = (STATE / run_id / "output.log").open("w")
                    try:
                        proc = subprocess.Popen([sys.executable, "-u", "-m", "webapp.worker", run_id],
                            cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                    finally:
                        log.close()
                    (STATE / run_id / "pid").write_text(str(proc.pid))
                    children[run_id] = proc
                if stopped and not stop_sent:
                    stop_sent = True
                    for proc in children.values():
                        if proc.poll() is None:
                            proc.terminate()  # AEF handles graceful sandbox teardown.
                    for run_id in pending:
                        rec = read(STATE / run_id)
                        rec.update(status="interrupted", error="Batch stopped", finished_at=now())
                        save(STATE / run_id, rec)
                    pending.clear()
                for run_id, proc in list(children.items()):
                    if proc.poll() is not None:
                        rec = read(STATE / run_id)
                        if rec["status"] not in TERMINAL:
                            rec.update(status="failed", error=f"Worker exited with code {proc.returncode}", finished_at=now())
                            save(STATE / run_id, rec)
                        del children[run_id]
                if children:
                    # An event wait avoids busy-spinning while retaining responsive cancellation.
                    Event().wait(.2)
            records = [read(STATE / run_id) for run_id in batch["run_ids"]]
            batch.update(status="interrupted" if stopped else "failed" if any(r["status"] != "completed" for r in records) else "completed")
            batch["message"] = "Batch finished; review quality and reliability separately from execution status"
        except Exception as exc:
            batch.update(status="failed", error=f"{type(exc).__name__}: {exc}")
            for proc in children.values():
                if proc.poll() is None:
                    proc.terminate()
            for proc in children.values():
                try:
                    proc.wait(timeout=90)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            for run_id in batch["run_ids"]:
                rec = read(STATE / run_id)
                if rec["status"] not in TERMINAL:
                    rec.update(status="failed", error=batch["error"], finished_at=now())
                    save(STATE / run_id, rec)
            raise
        finally:
            batch["finished_at"] = now()
            write_batch(folder, batch)


if __name__ == "__main__":
    coordinate(sys.argv[1])
