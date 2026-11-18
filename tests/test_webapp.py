"""Dashboard launch boundaries, persistent progress and safe output access."""
import json
from types import SimpleNamespace

import httpx
from fastapi.testclient import TestClient
import pytest

from webapp import app as dashboard
from webapp.store import save
from webapp import worker


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "STATE", tmp_path / "state")
    monkeypatch.setattr(dashboard, "ROOT", tmp_path)
    monkeypatch.setattr(dashboard.subprocess, "Popen", lambda *a, **kw: SimpleNamespace(pid=12345))
    monkeypatch.setattr(dashboard.os, "kill", lambda *a: None)
    return TestClient(dashboard.app)


def test_launch_progress_and_single_active_run(client):
    assert client.get("/").status_code == 200
    assert client.get("/static/dag.js").headers["cache-control"] == "no-store"
    assert client.get("/api/pipelines/v3/workflow").status_code == 200
    assert len(client.get("/api/pipelines/v3/workflow").json()["steps"]) == 37
    assert client.get("/api/pipelines/missing/workflow").status_code == 404
    assert {p["id"] for p in client.get("/api/pipelines").json()} == set(dashboard.PIPELINES)
    assert client.post("/api/runs", json={"pipeline": "../unknown"}).status_code == 422
    assert client.post("/api/runs", json={"pipeline": "v3", "model": "x; bad"}).status_code == 422
    response = client.post("/api/runs", json={"pipeline": "smoke"})
    assert response.status_code == 201
    run = response.json()
    assert client.post("/api/runs", json={"pipeline": "smoke"}).status_code == 409
    folder = dashboard.STATE / run["id"]
    run.update(status="running", total_steps=3, steps={"env": {"status": "completed", "number": 1}})
    save(folder, run)
    (folder / "output.log").write_text("real worker progress")
    (folder / "heartbeat").write_text("2026-11-06T17:00:00+00:00")
    detail = client.get(f"/api/runs/{run['id']}").json()
    assert detail["steps"]["env"]["status"] == "completed"
    assert detail["log"] == "real worker progress"
    assert detail["heartbeat_at"] == "2026-11-06T17:00:00+00:00"
    assert client.get("/api/runs/not-an-id").status_code == 404


def test_available_models_uses_proxy_ids_and_keeps_credentials_server_side(client, monkeypatch):
    monkeypatch.setenv("LITELLM_BASE_URL", "https://proxy.example/v1/")
    monkeypatch.setenv("LITELLM_API_KEY", "test-secret")

    def model_list(url, **kwargs):
        assert url == "https://proxy.example/v1/models"
        assert kwargs["headers"] == {"Authorization": "Bearer test-secret"}
        return httpx.Response(200, request=httpx.Request("GET", url), json={"data": [
            {"id": "openai/gpt-5"}, {"id": "anthropic/claude"}, {"id": "openai/gpt-5"}, {}, {"id": None}]})

    monkeypatch.setattr(dashboard, "verified_models", lambda: [
        {"id": "openai/openai/gpt-5", "name": "openai/gpt-5"}])
    response = client.get("/api/models")
    assert response.status_code == 200
    assert response.json() == [{"id": "openai/openai/gpt-5", "name": "openai/gpt-5"}]
    assert "test-secret" not in response.text


def test_available_models_reports_missing_config_and_proxy_failure(client, monkeypatch):
    monkeypatch.delenv("LITELLM_API_KEY", raising=False)
    assert client.get("/api/models").status_code == 503
    monkeypatch.setenv("LITELLM_BASE_URL", "https://proxy.example/v1")
    monkeypatch.setenv("LITELLM_API_KEY", "test-secret")

    def unavailable(*args, **kwargs):
        raise httpx.ConnectError("upstream error containing test-secret")

    monkeypatch.setattr(dashboard, "verified_models", lambda: [])
    response = client.get("/api/models")
    assert response.status_code == 200 and response.json() == []
    assert "test-secret" not in response.text


def test_results_are_text_and_confined_to_export_directory(client, tmp_path):
    run_id = "a" * 32
    export = tmp_path / "runs/v3/test"
    export.mkdir(parents=True)
    (export / "scorecard.md").write_text("<script>must remain text</script>")
    (tmp_path / "private.txt").write_text("private")
    (export / "escape.txt").symlink_to(tmp_path / "private.txt")
    save(dashboard.STATE / run_id, {"id": run_id, "status": "completed", "created_at": "now", "export_path": "runs/v3/test"})
    response = client.get(f"/api/runs/{run_id}/files/scorecard.md")
    assert response.headers["content-type"].startswith("text/plain")
    assert "must remain text" in response.text
    rendered = client.get(f"/api/runs/{run_id}/render/scorecard.md").json()["html"]
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    (export / "pretty.md").write_text("# Report\n\n**Confirmed**\n\n| Host | State |\n| --- | --- |\n| WS-01 | Affected |\n\n[bad](javascript:alert(1))")
    pretty = client.get(f"/api/runs/{run_id}/render/pretty.md").json()["html"]
    assert "<h1>Report</h1>" in pretty and "<strong>Confirmed</strong>" in pretty and "<table>" in pretty
    assert 'href="javascript:' not in pretty
    assert client.get(f"/api/runs/{run_id}/render/escape.md").status_code == 404
    assert client.get(f"/api/runs/{run_id}/files/escape.txt").status_code == 404
    assert client.post("/api/runs", headers={"origin": "https://other.example"}, json={}).status_code == 403
    assert client.get("/api/runs", headers={"host": "other.example"}).status_code == 403


def test_launch_uses_same_saved_models_for_both_roles(client, monkeypatch):
    monkeypatch.setattr(dashboard, "verified_models", lambda: [
        {"id": "openai/openai/gpt-5", "name": "openai/gpt-5", "roles": ["analyst"]},
        {"id": "openai/openai/gpt-6-sol", "name": "openai/gpt-6-sol", "roles": ["judge"]}])
    assert client.post("/api/runs", json={"pipeline": "v3", "model": "openai/openai/gpt-4o-2024-05-13"}).status_code == 422
    assert client.post("/api/runs", json={"pipeline": "v3", "model": "openai/openai/gpt-6-sol", "judge_model": "openai/openai/gpt-5"}).status_code == 201


def test_worker_persists_progress_scores_and_namespaced_export(tmp_path, monkeypatch):
    import agent_env.bundle.run as runner
    monkeypatch.setattr(worker, "STATE", tmp_path / "state")
    monkeypatch.setattr(worker, "ROOT", tmp_path)
    monkeypatch.setattr(worker, "workflow", lambda pipeline: [{"id": "facts", "type": "env_outcome_verifier", "depends_on": []}])
    from webapp import inputs
    monkeypatch.setattr(inputs, "scenario_inputs", lambda *args: {"items": []})
    monkeypatch.setenv("LITELLM_BASE_URL", "https://proxy.example/v1")
    monkeypatch.setenv("LITELLM_API_KEY", "test-only")
    folder = worker.STATE / ("b" * 32)
    save(folder, {"id": folder.name, "pipeline": "v3", "model": "", "status": "queued"})
    context = SimpleNamespace(to_safe_dict=lambda: {"metadata": {"verifications": {"facts": {"score": .75}}}})
    run = SimpleNamespace(instance_id="@local/project/soc_update-abc", context=context,
                          scores={"facts": .75}, duration=1.2, outcome=SimpleNamespace(value="scored below 1"),
                          error=None, failed_steps=[])

    def execute(*args, **kwargs):
        kwargs["on_progress"]("[tasks/soc_update.json] step 1/1 facts (env_outcome_verifier)")
        kwargs["on_progress"]("[tasks/soc_update.json] step 1/1 facts done in 1.2s")
        return SimpleNamespace(runs=[run], failed=False)

    monkeypatch.setattr(runner, "run_bundle", execute)
    monkeypatch.setattr(worker.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout="", stderr=""))
    worker.main(folder.name)
    record = json.loads((folder / "run.json").read_text())
    assert record["status"] == "completed"
    assert record["steps"]["facts"]["status"] == "completed"
    assert record["steps"]["facts"]["started_at"]
    assert (folder / "heartbeat").read_text()
    assert record["message"] == "Evaluation completed; results ready"
    assert record["export_path"] == "runs/v3/soc_update-abc"
    assert record["results"][0]["scores"]["facts"] == .75
    assert json.loads((folder / "results.json").read_text())[0]["context"]["metadata"]["verifications"]
