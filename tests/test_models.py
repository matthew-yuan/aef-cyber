"""Model routing remains proxy-only for analysts and every judge, including revisions."""
import ast
import importlib.util
from pathlib import Path

from conftest import REPO


def test_agent_removes_exactly_one_routing_prefix():
    tree = ast.parse((REPO / "agents/sgp-agent/agent.py").read_text())
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "sgp_model_name")
    namespace = {}
    exec(compile(ast.Module(body=[function], type_ignores=[]), "trusted-model-routing", "exec"), namespace)
    route = namespace["sgp_model_name"]
    assert route("openai/openai/gpt-5") == "openai/gpt-5"
    assert route("openai/gpt-5") == "gpt-5"
    assert route("openai/anthropic/claude-sonnet") == "anthropic/claude-sonnet"


def test_all_pipeline_model_defaults(monkeypatch):
    monkeypatch.delenv("CYBER_ANALYST_MODEL", raising=False)
    monkeypatch.delenv("CYBER_JUDGE_MODEL", raising=False)
    for version in ("v1-triage", "v2-artifacts", "v3-update"):
        path = REPO / "pipelines" / version / "build.py"
        spec = importlib.util.spec_from_file_location(version.replace("-", "_"), path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        steps = module.task()
        assert all(s["model"] == "openai/openai/gpt-5" for s in steps if s["type"] == "prompt_agent")
        assert all(s["default_model"] == "openai/openai/gpt-6-sol" for s in steps if s["type"] == "rubrics_verifier")
