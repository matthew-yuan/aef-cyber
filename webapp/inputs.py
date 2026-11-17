"""Agent-facing inputs only: never include grader labels or credentials."""
import json

from webapp.store import ROOT, PIPELINES


def scenario_inputs(pipeline, root=None):
    root = root or ROOT
    items = []
    for path in sorted((root / PIPELINES[pipeline]["bundle"] / "tasks").glob("*.json")):
        for step in json.loads(path.read_text()):
            if step["type"] == "deploy_agent":
                items.append({"name": "System prompt", "phase": step["id"],
                              "content": step.get("system_prompt", "")})
            elif step["type"] == "prompt_agent":
                items.append({"name": "Task prompt", "phase": step["id"], "content": step.get("prompt", "")})
    incident = root / "soc-env/data/incident.json"
    if incident.exists():
        items.append({"name": "Scenario records available through tools", "phase": "SOC / lab",
                      "content": incident.read_text()})
    if pipeline == "v3":
        update = root / "pipelines/v3-update/update_01.json"
        items.append({"name": "Late telemetry (available after injection)", "phase": "revision",
                      "content": update.read_text()})
    return {"source": "Current scenario definition (not a historical run snapshot)", "items": items}


def run_inputs(folder, record, root):
    saved = folder / "inputs.json"
    payload = json.loads(saved.read_text()) if saved.exists() else scenario_inputs(record["pipeline"])
    payload["items"] = list(payload["items"])
    if record.get("custom_rubric"):
        payload["items"].append({"name": "Uploaded supplemental rubric (grader only; not sent to agents or LLM judges)",
                                 "phase": "custom-rubric", "content": json.dumps(record["custom_rubric"], indent=2)})
    export = (root / record.get("export_path", "")).resolve()
    if record.get("export_path") and export.is_relative_to((root / "runs").resolve()):
        for path in sorted((export / "trajectories").glob("*.json")):
            if not path.resolve().is_relative_to(export):
                continue
            steps = json.loads(path.read_text())
            observations = [{"tool": s.get("tool"), "arguments": s.get("input"), "response": s.get("output")}
                            for s in steps if s.get("type") == "tool_call"]
            messages = [s.get("text", "") for s in steps if s.get("type") == "message"]
            if messages:
                payload["items"].append({"name": "Recorded task prompt", "phase": path.stem,
                                          "content": "\n\n".join(messages)})
            if observations:
                payload["items"].append({"name": "Actual tool calls and responses", "phase": path.stem,
                                          "content": json.dumps(observations, indent=2, ensure_ascii=False)})
    return payload
