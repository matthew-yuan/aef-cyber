"""Distinguish captured inputs, current definitions and actual retrieved evidence."""
import json

from webapp.inputs import scenario_inputs, run_inputs


def test_inputs_include_prompts_and_records_but_not_grading_material():
    payload = scenario_inputs("v3")
    names = [item["name"] for item in payload["items"]]
    assert "System prompt" in names
    assert names.count("Task prompt") == 5
    assert "Late telemetry (available after injection)" in names
    assert "Scenario records available through tools" in names
    assert not any("grading_policy_prompt" in item["content"] for item in payload["items"])
    assert "historical" in payload["source"]


def test_saved_inputs_take_precedence_and_tool_responses_are_included(tmp_path):
    folder = tmp_path / "state"
    folder.mkdir()
    (folder / "inputs.json").write_text(json.dumps({"source": "Captured at launch", "items": [
        {"name": "System prompt", "phase": "analyst", "content": "Original instructions"}]}))
    trajectories = tmp_path / "runs/example/trajectories"
    trajectories.mkdir(parents=True)
    (trajectories / "triage.json").write_text(json.dumps([
        {"type": "message", "text": "Investigate this incident"},
        {"type": "tool_call", "tool": "soc_get_alert", "input": {"id": "ALT-1001"},
         "output": "<script>display as text</script>"}]))
    payload = run_inputs(folder, {"pipeline": "v1", "export_path": "runs/example"}, tmp_path)
    assert payload["items"][0]["content"] == "Original instructions"
    assert payload["items"][1]["content"] == "Investigate this incident"
    assert "display as text" in payload["items"][2]["content"]
    assert len(run_inputs(folder, {"pipeline": "v1", "export_path": "../outside"}, tmp_path)["items"]) == 1
