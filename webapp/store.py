"""Small durable dashboard index, separate from AEF's own run store."""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".dashboard"
PIPELINES = {
    "v3": {"name": "Incident update & revision", "bundle": "pipelines/v3-update/soc-eval", "export": "pipelines/v3-update/export_run.py", "description": "37 steps · verified actions, late telemetry and report revision", "model": True},
    "v2": {"name": "Evidence & code artifacts", "bundle": "pipelines/v2-artifacts/soc-eval", "export": "pipelines/v2-artifacts/export_run.py", "description": "30 steps · forensic evidence, verified lab use and offline execution", "model": True},
    "smoke": {"name": "Pipeline functionality check", "bundle": "pipelines/focused/infrastructure", "description": "Model-free · SOC tools, lab safety and offline scoring in one run", "model": False, "build": "pipelines/focused/build.py"},
    "v1": {"name": "Alert triage & incident report", "bundle": "pipelines/v1-triage/soc-eval", "export": "pipelines/v1-triage/export_run.py", "description": "Quick analyst scenario · authorized scan, stolen VPN login and PLANS exfiltration", "model": True},
    "rules": {"name": "Rules generation & grading", "bundle": "pipelines/focused/rules", "description": "Code · generate Sigma rules, test in lab and grade precision/recall plus logic", "model": True, "build": "pipelines/focused/build.py", "focused": True},
    "triage": {"name": "Triage process & grading", "bundle": "pipelines/focused/triage", "description": "Reasoning · investigate alerts, submit verdicts and grade evidence/correlation/process", "model": True, "build": "pipelines/focused/build.py", "focused": True},
    "report": {"name": "Report generation & grading", "bundle": "pipelines/focused/report", "description": "Artifacts · investigate and write an incident report; grade content and response quality", "model": True, "build": "pipelines/focused/build.py", "focused": True},
}


def save(folder, record):
    folder.mkdir(parents=True, exist_ok=True)
    temporary = folder / f"run.{os.getpid()}.tmp"
    temporary.write_text(json.dumps(record, indent=2, default=str))
    temporary.replace(folder / "run.json")


def read(folder):
    return json.loads((folder / "run.json").read_text())
