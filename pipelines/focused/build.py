"""Build focused model evaluations and a consolidated model-free infrastructure check."""
import importlib.util
import json
import shutil
from copy import deepcopy
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load("focused_v2", HERE.parent / "v2-artifacts/build.py")


def focused(kind):
    source = {s["id"]: deepcopy(s) for s in base.task()}
    steps = [source[k] for k in ("soc", "seed", "analyst")]
    steps[-1]["env_ids"] = ["soc"]
    steps[-1]["depends_on"] = base.dep("soc")
    phase = "artifacts" if kind == "rules" else kind
    generation = source[phase]
    generation["depends_on"] = base.dep("seed", "analyst")
    if kind == "report":
        generation["prompt"] = "Independently investigate the SOC records, then submit a complete incident report with soc_submit_incident_report. No prior triage has been supplied. " + base.prompt("report_user")
    if kind == "rules":
        steps.insert(1, source["lab"])
        steps.append(source["seed-lab"])
        steps[3]["env_ids"] = ["soc", "lab"]
        steps[3]["depends_on"] = base.dep("soc", "lab")
        generation["depends_on"] = base.dep("seed", "seed-lab", "analyst")
        generation["prompt"] = ("Investigate the incident records and intelligence. Read soc_get_log_schema. Generate up to eight Sigma rules covering malicious behaviors while excluding authorized activity. "
                                "Use lab_test_rule to test and refine each rule, then submit each via soc_submit_artifact(kind='sigma_rule'). "
                                "Use ATT&CK tags and behavior-based logic. Submit rules only; no hunt script, IOC extractor, triage or report is required.")
    steps.append(generation)
    snapshot = source["snap-final"]
    snapshot["depends_on"] = base.dep(phase)
    steps.append(snapshot)
    rubric = json.loads((base.HERE / "rubrics.json").read_text())["artifacts" if kind == "rules" else kind]
    if kind == "rules":
        rubric["criteria"] = rubric["criteria"][:1]
    judge = base.judge("judge-" + kind, phase, rubric, phase)
    steps.append(judge)
    verifiers = [judge["id"]]
    if kind == "rules":
        steps.extend(source[k] for k in ("scorebox-vm", "scorebox-ctr", "handoff", "exec-tests"))
        steps[-1]["command"] += " --only sigma"
        verifiers.append("exec-tests")
    else:
        facts = source["facts"]
        facts["depends_on"] = base.dep(phase)
        steps.append(facts)
        verifiers.append("facts")
    steps.append({"id": "score", "type": "aggregate_verifiers", "verifier_id": "focused-" + kind,
                  "verifier_ids": verifiers, "score_aggregator": "weighted_average", "depends_on": base.dep(*verifiers, "snap-final")})
    return steps


def main():
    for kind in ("rules", "triage", "report"):
        bundle = HERE / kind
        (bundle / "tasks").mkdir(parents=True, exist_ok=True)
        (bundle / "tasks/task.json").write_text(json.dumps(focused(kind), indent=2) + "\n")
        if kind == "rules":
            shutil.copytree(base.HERE / "soc-eval/artifacts/scorebox_context", bundle / "artifacts/scorebox_context", dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns("__pycache__"))
        else:
            text = (base.HERE / "soc-eval/artifacts/check_facts/verify.py").read_text()
            text = text.replace("def score(state: dict)", "def baseline_score(state: dict)")
            prefixes = '("triage-", "process-")' if kind == "triage" else '("report-", "contain-")'
            text += '\n\ndef score(state):\n    rows = [r for r in baseline_score(state) if r["id"].startswith(' + prefixes + ')]\n    for row in rows:\n        row["weight"] = 1.0 / len(rows)\n    return rows\n'
            path = bundle / "artifacts/check_facts/verify.py"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
    bundle = HERE / "infrastructure"
    (bundle / "tasks").mkdir(parents=True, exist_ok=True)
    combined = []
    for label, folder in (("soc", "smoke"), ("lab", "lab-smoke"), ("scorebox", "scorebox-smoke")):
        original = REPO / "soc-env" / folder
        for artifact in (original / "artifacts").iterdir():
            if artifact.is_dir() and artifact.name != "__pycache__":
                shutil.copytree(artifact, bundle / "artifacts" / artifact.name, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__"))
        definitions = json.loads(next((original / "tasks").glob("*.json")).read_text())
        ids = {s["id"]: label + "-" + s["id"] for s in definitions}
        for step in definitions:
            if label == "scorebox" and step["id"] == "soc":
                continue  # Reuse the SOC deployment; reseed clears smoke submissions before golden artifacts.
            step["id"] = ids[step["id"]]
            for dep in step.get("depends_on", []):
                dep["task_step_id"] = "soc-check" if label == "scorebox" and dep["task_step_id"] == "soc" else ids[dep["task_step_id"]]
            if step.get("artifact_from_step_id"):
                step["artifact_from_step_id"] = ids[step["artifact_from_step_id"]]
            combined.append(step)
    (bundle / "tasks/task.json").write_text(json.dumps(combined, indent=2) + "\n")
    print("Built infrastructure, rules, triage and report scenarios")


if __name__ == "__main__":
    main()
