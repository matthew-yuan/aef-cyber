"""Compose v2's baseline with a non-resetting incident update, report revision and adaptation grading."""
import importlib.util
import json
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
V2 = HERE.parent / "v2-artifacts"
spec = importlib.util.spec_from_file_location("v2_build", V2 / "build.py")
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)
ANALYST_MODEL = baseline.ANALYST_MODEL
JUDGE_MODEL = baseline.JUDGE_MODEL
VERIFIERS = baseline.VERIFIERS + ["revision-checks", "judge-revision"]


def task():
    steps = baseline.task()
    analyst = next(s for s in steps if s["id"] == "analyst")
    analyst["system_prompt"] += "\n\n" + (HERE / "prompts/analyst_update_system.md").read_text().strip()
    steps[-1]["id"] = "baseline-score"  # Preserve soc-v2 as a separate comparable measurement.
    steps += [
        {"id": "issue-update", "type": "run_code", "env_id": "soc", "script_artifact_id": "incident_update",
         "args": {"update": json.loads((HERE / "update_01.json").read_text())},
         "depends_on": baseline.dep("baseline-score", "snap-final", "snap-lab")},
        {"id": "revision", "type": "prompt_agent", "agent_name": "analyst", "prompt_id": "revision",
         "context_id": baseline.CONVERSATION, "model": ANALYST_MODEL, "timeout_seconds": 1800,
         "prompt": (HERE / "prompts/revision_user.md").read_text().strip(), "depends_on": baseline.dep("issue-update")},
        {"id": "snap-revised", "type": "snapshot_env", "env_id": "soc", "snapshot_id": "soc-v3-revised",
         "depends_on": baseline.dep("revision")},
        {"id": "revision-checks", "type": "env_outcome_verifier", "env_id": "soc", "file_artifact_id": "check_revision",
         "verifier_id": "revision-checks", "score_aggregator": "weighted_average", "depends_on": baseline.dep("snap-revised")},
        {"id": "judge-revision", "type": "rubrics_verifier", "verifier_id": "judge-revision", "prompt_id": "revision",
         "use_agent_judge": False, "default_model": JUDGE_MODEL, "output_format": "rubric_partial",
         "score_aggregator": "weighted_average", "depends_on": baseline.dep("revision"),
         "criteria": [{"id": "revision-quality", "weight": 1.0,
                       "criterion": "The submitted revised report accurately integrates UPDATE-01, preserves valid original findings and targeted response actions, states what changed, and avoids unsupported claims of personnel-data exfiltration, domain-controller compromise or linkage to the separate phishing lure.",
                       "outcomes": [{"label": "Complete, grounded revision with no material regressions", "score": 1.0},
                                    {"label": "Useful revision with material omissions or unsupported claims", "score": 0.5},
                                    {"label": "Missing revision, misses new compromise, or fundamentally incorrect", "score": 0.0}]}],
         "grading_policy_prompt": "Grade the actual submit_incident_report tool call, not the final chat summary. "
                                  "New scope: WS-G1-007, reached from SRV-WEB-02 as svc_backup at 14:35Z, "
                                  "UpdateSvcHelper at 14:36Z, fallback C2 cdn-telemetry.updatesvc.example / 203.0.113.155. "
                                  "Require isolation, preservation and expanded blocks/escalation. No new exfiltration is established. "
                                  "Preserve original scope, accounts, PLANS loss and response. Original answer key:\n\n"
                                  + (V2 / "answer_key.md").read_text()},
        {"id": "score", "type": "aggregate_verifiers", "verifier_id": "soc-v3", "verifier_ids": VERIFIERS,
         "score_aggregator": "weighted_average", "depends_on": baseline.dep(*VERIFIERS, "snap-revised")},
    ]
    return steps


def main():
    baseline.check_weights()
    # Reuse the trusted baseline bundle contexts byte-for-byte, retaining its execution boundary.
    for name in ("check_facts", "check_artifacts", "scorebox_context"):
        shutil.copytree(V2 / "soc-eval/artifacts" / name, HERE / "soc-eval/artifacts" / name, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    output = HERE / "soc-eval/tasks/soc_update.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(task(), indent=2) + "\n")
    print(f"wrote {output} ({len(task())} steps)")


if __name__ == "__main__":
    main()
