import json
import httpx
from types import SimpleNamespace
from webapp import models


def test_saved_models_shared_and_no_network_on_reads(tmp_path, monkeypatch):
    monkeypatch.setenv("LITELLM_BASE_URL", "https://proxy.example/v1")
    monkeypatch.setenv("LITELLM_API_KEY", "secret")
    monkeypatch.setattr(models, "STATE", tmp_path)
    _, _, path = models.coordinates()
    models.save_catalog(path, {"checks": {"openai/gpt-5": True, "deprecated": False, "openai/gpt-6-sol": True}})
    monkeypatch.setattr(models.httpx, "get", lambda *a, **k: (_ for _ in ()).throw(AssertionError("network")))
    assert models.verified_models() == [
        {"id": "openai/openai/gpt-5", "name": "openai/gpt-5"},
        {"id": "openai/openai/gpt-6-sol", "name": "openai/gpt-6-sol"}]
    assert "secret" not in path.read_text()


def test_coordinates_use_agentenv_config_when_endpoint_env_is_absent(tmp_path, monkeypatch):
    import agent_env.config

    monkeypatch.delenv("LITELLM_BASE_URL", raising=False)
    monkeypatch.setattr(models, "STATE", tmp_path)
    monkeypatch.setattr(agent_env.config, "get_config", lambda: SimpleNamespace(
        get_litellm_base_url=lambda: "https://configured.example/v1/",
        get_litellm_api_key=lambda: "configured-secret"))
    endpoint, key, path = models.coordinates()
    assert endpoint == "https://configured.example/v1"
    assert key == "configured-secret"
    assert path.parent == tmp_path / "models"


def test_scan_resumes_and_excludes_non_chat(tmp_path, monkeypatch):
    monkeypatch.setenv("LITELLM_BASE_URL", "https://proxy.example/v1")
    monkeypatch.setenv("LITELLM_API_KEY", "secret")
    monkeypatch.setattr(models, "STATE", tmp_path)
    _, _, path = models.coordinates()
    models.save_catalog(path, {"checks": {"existing": True}})
    monkeypatch.setattr(models.httpx, "get", lambda *a, **k: httpx.Response(200,
        request=httpx.Request("GET", "https://proxy.example/model/info"), json={"data": [
            {"model_name": "existing", "model_info": {"mode": "chat"}},
            {"model_name": "new", "model_info": {"mode": "chat"}},
            {"model_name": "image", "model_info": {"mode": "image_generation"}}]}))
    calls = []
    monkeypatch.setattr(models, "working_model", lambda e, k, a: calls.append(a) or True)
    models.scan_models()
    assert calls == ["new"]
    assert json.loads(path.read_text())["checks"] == {"existing": True, "new": True}
