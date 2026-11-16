"""Batch bounds, reliability semantics, immutable inputs and child lifecycle."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from webapp import app as dashboard
from webapp import batches, batch_worker
from webapp.store import read, save


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "STATE", tmp_path)
    monkeypatch.setattr(dashboard.subprocess, "Popen", lambda *a, **kw: SimpleNamespace(pid=12345))
    monkeypatch.setattr(batches, "alive", lambda pid: True)
    monkeypatch.setattr(dashboard, "verified_models", lambda: [
        {"id": "openai/openai/gpt-5"}, {"id": "openai/openai/gpt-6-sol"}])
    return TestClient(dashboard.app)


def test_batch_launch_creates_k_children_and_blocks_competing_launches(client, tmp_path):
    response = client.post("/api/batches", json={"pipelines": ["triage", "report"], "k": 2})
    assert response.status_code == 201
    batch = response.json()
    assert len(batch["run_ids"]) == len(set(batch["run_ids"])) == 4
    assert batch["concurrency"] == 2  # internal scheduling, not a user parameter
    children = [read(tmp_path / i) for i in batch["run_ids"]]
    assert [(c["pipeline"], c["trial"]) for c in children] == [("triage", 1), ("report", 1), ("triage", 2), ("report", 2)]
    assert client.post("/api/batches", json={"pipelines": ["smoke"]}).status_code == 409
    assert client.post("/api/runs", json={"pipeline": "smoke"}).status_code == 409
    detail = client.get("/api/batches").json()[0]
    assert detail["scenarios"][0]["all_trials_passed"] is None
    assert detail["scenarios"][0]["success_rate"] is None


@pytest.mark.parametrize("body", [
    {"pipelines": []}, {"pipelines": ["missing"]}, {"pipelines": ["v1", "v1"]},
    {"pipelines": ["smoke"], "k": 0}, {"pipelines": ["smoke"], "k": 21},
    {"pipelines": ["smoke"], "k": True}, {"pipelines": ["smoke"], "k": 1.1},
    {"pipelines": ["v1", "v2", "v3"], "k": 20}, {"pipelines": ["smoke"], "success_threshold": 1.1},
])
def test_invalid_batch_bounds(client, body):
    assert client.post("/api/batches", json=body).status_code == 422


def trial(scores, **kwargs):
    return {"status": "completed", "results": [{"scores": scores, **kwargs}]}


def test_reliability_uses_primary_aggregate_and_rejects_false_success():
    assert batches.trial_success(trial({"soc-v3": .8, "soc-v2": .5, "judge-artifacts": .1}), .8)
    assert not batches.trial_success(trial({"soc-v2": .9, "soc-v3": .2}), .8)
    assert not batches.trial_success(trial({"soc-v1": 1}, grading={"soc-v1": {"critical_failure": True}}), .8)
    assert not batches.trial_success(trial({"soc-v1": 1}, outcome="failed"), .8)
    assert not batches.trial_success(trial({"soc-v1": float("nan")}), .8)
    assert not batches.trial_success(trial({"soc-v1": 0}), 0)
    assert not batches.trial_success(trial({"judge-triage": 1}), .8)
    assert not batches.trial_success(trial({"soc-smoke": 1}), .8)
    assert batches.trial_success(trial({"soc-smoke": 1, "lab-smoke": 1, "exec-tests": 1}), 1)
    assert batches.trial_success(trial({"soc-check": 1, "lab-check": 1, "scorebox-exec-tests": 1}), 1)
    assert batches.trial_success(trial({"score": .2}, context={"metadata": {"verifications": {
        "focused-triage": {"score": .9}}}}), .8)
    assert not batches.trial_success(trial({"soc-v2": 1}, context={"metadata": {"verifications": {
        "exec-tests": {"extracted_files": {"results.json": {"refused": "isolation failure"}}}}}}), .8)


def test_batch_summary_counts_execution_errors_and_reports_uncertainty(tmp_path):
    batch = {"id": "test", "pipelines": ["v1"], "run_ids": ["a", "b"], "k": 2, "concurrency": 2,
             "status": "completed", "success_threshold": .8, "created_at": batches.now(), "finished_at": batches.now()}
    folder = tmp_path / "batches/test"
    batches.write_batch(folder, batch)
    save(tmp_path / "a", {"id": "a", "pipeline": "v1", **trial({"soc-v1": .9})})
    save(tmp_path / "b", {"id": "b", "pipeline": "v1", "status": "failed", "results": []})
    summary = batches.batch_detail(folder, state=tmp_path)["scenarios"][0]
    assert summary["success_rate"] == .5
    assert summary["failed"] == 1
    assert summary["all_trials_passed"] is False
    assert summary["any_trial_passed"] is True
    assert summary["confidence_interval_95"][0] < .5 < summary["confidence_interval_95"][1]


def test_dead_coordinator_interrupts_queued_trials(tmp_path, monkeypatch):
    monkeypatch.setattr(batches, "alive", lambda pid: False)
    folder = tmp_path / "batches/test"
    batches.write_batch(folder, {"id": "test", "pipelines": ["smoke"], "run_ids": ["a"], "status": "running",
                                "success_threshold": 1, "created_at": batches.now()})
    (folder / "pid").write_text("12345")
    save(tmp_path / "a", {"id": "a", "pipeline": "smoke", "status": "queued"})
    result = batches.batch_detail(folder, state=tmp_path)
    assert result["status"] == "interrupted"
    assert read(tmp_path / "a")["status"] == "interrupted"


def test_build_failure_finishes_every_child(tmp_path, monkeypatch):
    monkeypatch.setattr(batch_worker, "STATE", tmp_path)
    monkeypatch.setattr(batch_worker.signal, "signal", lambda *args: None)
    folder = tmp_path / "batches/test"
    batches.write_batch(folder, {"id": "test", "pipelines": ["smoke"], "run_ids": ["a", "b"], "concurrency": 2})
    for run_id in ("a", "b"):
        save(tmp_path / run_id, {"id": run_id, "pipeline": "smoke", "status": "queued"})
    def broken(*args):
        raise RuntimeError("build failed")
    monkeypatch.setattr(batch_worker, "prepare_workspace", broken)
    with pytest.raises(RuntimeError, match="build failed"):
        batch_worker.coordinate("test")
    assert all(read(tmp_path / i)["status"] == "failed" for i in ("a", "b"))
    assert json.loads((folder / "batch.json").read_text())["status"] == "failed"


def test_trial_bundle_has_unique_snapshot_ids_and_keeps_frozen_source(tmp_path):
    source = tmp_path / "workspace" / batches.PIPELINES["triage"]["bundle"] / "tasks"
    source.mkdir(parents=True)
    definitions = [{"id": "snap-final", "type": "snapshot_env", "snapshot_id": "shared"},
                   {"id": "handoff", "type": "load_artifact", "artifact_from_step_id": "snap-final"}]
    (source / "task.json").write_text(json.dumps(definitions))
    first = batch_worker.prepare_trial(tmp_path / "trial-a", tmp_path / "workspace", "triage")
    second = batch_worker.prepare_trial(tmp_path / "trial-b", tmp_path / "workspace", "triage")
    assert first != second
    steps = json.loads((first / "tasks/task.json").read_text())
    assert "snapshot_id" not in steps[0]
    assert steps[1]["artifact_from_step_id"] == "snap-final"
    assert json.loads((source / "task.json").read_text()) == definitions


def test_prepare_builds_once_and_freezes_versions_models_and_files(tmp_path, monkeypatch):
    from agent_env.env import Env
    from agent_env.artifact import Artifact
    root = tmp_path / "source"
    root.mkdir()
    for directory in ("soc-env", "agents", ".agentenv"):
        (root / directory).mkdir()
    (root / "grading.py").write_text("POLICY_VERSION = 'frozen'\n")
    tasks = root / batches.PIPELINES["triage"]["bundle"] / "tasks"
    tasks.mkdir(parents=True)
    (tasks / "task.json").write_text(json.dumps([
        {"id": "soc", "type": "deploy_env", "env_id": "soc"},
        {"id": "seed", "type": "load_artifact", "artifact_id": "soc-sample"}]))
    builds = []
    def build(args, **kwargs):
        builds.append(args[-1])
        assert kwargs["env"]["CYBER_ANALYST_MODEL"] == "analyst-original"
        assert kwargs["env"]["CYBER_JUDGE_MODEL"] == "judge-original"
    monkeypatch.setattr(batch_worker.subprocess, "run", build)
    monkeypatch.setattr(Env, "get", lambda *args: SimpleNamespace(version=7))
    monkeypatch.setattr(Artifact, "get", lambda *args: SimpleNamespace(version=3))
    folder = tmp_path / "batch"
    folder.mkdir()
    batch = {"model": "analyst-original", "judge_model": "judge-original", "pipelines": ["triage"]}
    workspace = batch_worker.prepare_workspace(folder, batch, root=root)
    assert [Path(p).parent.name for p in builds] == ["v1-triage", "v2-artifacts", "v3-update", "focused"]
    pinned = json.loads((workspace / batches.PIPELINES["triage"]["bundle"] / "tasks/task.json").read_text())
    assert pinned[0]["env_version"] == 7 and pinned[1]["artifact_version"] == 3
    (root / "grading.py").write_text("POLICY_VERSION = 'changed'\n")
    assert "frozen" in (workspace / "grading.py").read_text()
    assert len(batch["input_sha256"]) == 64


def test_coordinator_bounds_concurrency_and_runs_each_trial_once(tmp_path, monkeypatch):
    monkeypatch.setattr(batch_worker, "STATE", tmp_path)
    monkeypatch.setattr(batch_worker.signal, "signal", lambda *args: None)
    monkeypatch.setattr(batch_worker, "prepare_workspace", lambda *args: tmp_path)
    monkeypatch.setattr(batch_worker, "prepare_trial", lambda *args: tmp_path)
    folder = tmp_path / "batches/test"
    ids = ["a", "b", "c", "d"]
    batches.write_batch(folder, {"id": "test", "pipelines": ["smoke"], "run_ids": ids, "concurrency": 2})
    for run_id in ids:
        save(tmp_path / run_id, {"id": run_id, "pipeline": "smoke", "status": "queued"})
    active, launched, peaks = set(), [], []

    class Process:
        returncode = 0
        pid = 12345

        def __init__(self, args, **kwargs):
            self.run_id = args[-1]
            self.polls = 0
            launched.append(self.run_id)
            active.add(self.run_id)
            peaks.append(len(active))

        def poll(self):
            self.polls += 1
            if self.polls == 1:
                return None
            active.discard(self.run_id)
            rec = read(tmp_path / self.run_id)
            rec.update(status="completed")
            save(tmp_path / self.run_id, rec)
            return 0

    monkeypatch.setattr(batch_worker.subprocess, "Popen", Process)
    monkeypatch.setattr(batch_worker.Event, "wait", lambda *args: None)
    batch_worker.coordinate("test")
    assert launched == ids
    assert max(peaks) == 2
    assert json.loads((folder / "batch.json").read_text())["status"] == "completed"
