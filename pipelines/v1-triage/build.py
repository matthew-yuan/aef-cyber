"""Build the v1 triage eval task from its sources.

    uv run python pipelines/v1-triage/build.py

Writes pipelines/v1-triage/soc-eval/tasks/soc_triage.json from prompts/, rubrics.json and answer_key.md.
The analyst works the soc env in one conversation: it triages the alert queue, then writes the
incident report. snapshot_env saves the end state after each phase. Grading: code checks on the end
state (env_outcome_verifier), a direct LLM judge per phase (rubrics_verifier), and one aggregate score.
"""
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent

SOC_VERSION = None         # soc-env/soc/: None deploys the latest registered version; set a number to pin one
SEED_ARTIFACT = "soc-sample"  # soc-env/data/incident.json as a universe
AGENT_VERSION = 1          # agents/sgp-agent
ANALYST_MODEL = "openai/openai/gpt-4o"  # same model as the judge: the scorecard flags the self-grading caveat
JUDGE_MODEL = "openai/openai/gpt-4o"    # the direct judge needs json_schema output, which SGP serves for gpt-4o
CONVERSATION = "analyst"   # both prompts share it, so the analyst carries its triage into the report


def prompt(name: str) -> str:
    return (HERE / "prompts" / f"{name}.md").read_text().strip()


def dep(*ids: str) -> list[dict]:
    return [{"task_step_id": i} for i in ids]


def judge(step_id: str, prompt_id: str, rubric: dict, after: str) -> dict:
    return {
        "id": step_id, "type": "rubrics_verifier", "verifier_id": step_id, "prompt_id": prompt_id,
        "use_agent_judge": False, "default_model": JUDGE_MODEL, "output_format": "rubric_partial",
        "score_aggregator": "weighted_average", "criteria": rubric["criteria"],
        "grading_policy_prompt": (
            f"You are grading a cyber defense analyst's {rubric['title']}. The scenario is a division exercise "
            "network with a confirmed intrusion and two authorized activities that look suspicious. Judge what the "
            "analyst actually submitted (its submit tool call in the trajectory), not its summary of it. The answer "
            "key below lists the facts in the records that a correct product reflects.\n\n" + (HERE / "answer_key.md").read_text()
        ),
        "depends_on": dep(after),
    }


def task() -> list[dict]:
    rubrics = json.loads((HERE / "rubrics.json").read_text())
    return [
        {"id": "soc", "type": "deploy_env", "env_id": "soc", "sandbox_type": "local", "depends_on": [],
         **({"env_version": SOC_VERSION} if SOC_VERSION else {})},
        {"id": "seed", "type": "load_artifact", "env_id": "soc", "artifact_id": SEED_ARTIFACT, "depends_on": dep("soc")},
        {"id": "analyst", "type": "deploy_agent", "a2a_agent_id": "sgp-agent", "a2a_agent_version": AGENT_VERSION,
         "agent_name": "analyst", "env_ids": ["soc"], "role": "analyst", "system_prompt": prompt("analyst_system"),
         "depends_on": dep("soc")},
        {"id": "triage", "type": "prompt_agent", "agent_name": "analyst", "prompt_id": "triage",
         "context_id": CONVERSATION, "prompt": prompt("triage_user"), "model": ANALYST_MODEL, "timeout_seconds": 1800,
         "depends_on": dep("seed", "analyst")},
        {"id": "snap-triage", "type": "snapshot_env", "env_id": "soc", "snapshot_id": "soc-v1-after-triage",
         "depends_on": dep("triage")},
        {"id": "report", "type": "prompt_agent", "agent_name": "analyst", "prompt_id": "report",
         "context_id": CONVERSATION, "prompt": prompt("report_user"), "model": ANALYST_MODEL, "timeout_seconds": 1800,
         "depends_on": dep("snap-triage")},
        {"id": "snap-final", "type": "snapshot_env", "env_id": "soc", "snapshot_id": "soc-v1-final",
         "depends_on": dep("report")},
        {"id": "facts", "type": "env_outcome_verifier", "env_id": "soc", "file_artifact_id": "check_facts",
         "verifier_id": "facts", "score_aggregator": "weighted_average", "depends_on": dep("report")},
        judge("judge-triage", "triage", rubrics["triage"], "triage"),
        judge("judge-report", "report", rubrics["report"], "report"),
        {"id": "score", "type": "aggregate_verifiers", "verifier_id": "soc-v1",
         "verifier_ids": ["facts", "judge-triage", "judge-report"], "score_aggregator": "weighted_average",
         "depends_on": dep("facts", "judge-triage", "judge-report")},
    ]


def check_weights() -> None:
    """Code checks and judge criteria must weigh the same in the aggregate."""
    rubrics = json.loads((HERE / "rubrics.json").read_text())
    judge_total = sum(c["weight"] for key in ("triage", "report") for c in rubrics[key]["criteria"])
    spec = importlib.util.spec_from_file_location("check_facts", HERE / "soc-eval/artifacts/check_facts/verify.py")
    facts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(facts)
    if facts.FACTS_WEIGHT_TOTAL != judge_total:
        raise SystemExit(f"FACTS_WEIGHT_TOTAL is {facts.FACTS_WEIGHT_TOTAL}; the judge criteria total {judge_total}")


def main() -> None:
    check_weights()
    path = HERE / "soc-eval" / "tasks" / "soc_triage.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(task(), indent=2) + "\n")
    print(f"wrote {path.relative_to(REPO)}")


if __name__ == "__main__":
    main()
