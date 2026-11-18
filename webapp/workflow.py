"""Read actual AEF dependencies for the dashboard, without executing task code."""
import json

from webapp.store import PIPELINES, ROOT


def workflow(pipeline, root=None):
    steps = []
    for path in sorted(((root or ROOT) / PIPELINES[pipeline]["bundle"] / "tasks").glob("*.json")):
        definitions = json.loads(path.read_text())
        if not isinstance(definitions, list):
            raise ValueError(f"Expected a task step list: {path}")
        prior = []
        for step in definitions:
            dependencies = step.get("depends_on")
            steps.append({"id": step["id"], "type": step["type"],
                          "depends_on": prior.copy() if dependencies is None else [d["task_step_id"] for d in dependencies]})
            prior.append(step["id"])
    return steps
