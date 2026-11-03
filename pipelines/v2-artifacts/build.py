"""Build the v2 artifacts eval task from its sources.

    uv run python pipelines/v2-artifacts/build.py

Writes pipelines/v2-artifacts/soc-eval/tasks/soc_artifacts.json from prompts/, rubrics.json and answer_key.md, and
syncs the pieces this bundle copies from elsewhere: soc-eval/artifacts/check_facts/verify.py (v1's code checks with
their total weight set to 1.0) and soc-eval/artifacts/scorebox_context/ (the offline scoring image, from
soc-env/scorebox/). The analyst works the soc and lab envs in one conversation: triage, incident report, evidence
analysis, then detection and response code. Grading: v1's code checks, the v2 artifact and evidence checks (both
parse-only, on the host), four direct LLM judges, and the execution tests that run only inside the network-less
scorebox container. Every verifier's rows total 1.0, so the aggregate is their mean.
"""
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
V1 = REPO / "pipelines" / "v1-triage"

SOC_VERSION = None          # None deploys the latest registered soc (v3 or later is required: artifact and evidence tools)
LAB_VERSION = None          # None deploys the latest registered lab
SEED_ARTIFACT = "soc-sample"      # soc-env/data/incident.json as the soc universe
LAB_SEED_ARTIFACT = "lab-sample"  # the same incident, registered for environment_name lab
AGENT_VERSION = 1           # agents/sgp-agent
ANALYST_MODEL = "openai/openai/gpt-4o"
JUDGE_MODEL = "openai/openai/gpt-4o"  # same model as the analyst: the scorecard flags the self-grading caveat
CONVERSATION = "analyst"    # all four prompts share it
SCOREBOX_ENV = {"LITELLM_API_KEY": "", "ANTHROPIC_API_KEY": "", "LITELLM_BASE_URL": "", "ANTHROPIC_BASE_URL": "", "LITELLM_EXTRA_HEADERS": "{}"}
GRADER = "python3 -I /harness/run_tests.py --handoff /handoff --data /harness/data --out /work/out --work /work/runs"
VERIFIERS = ["facts", "artifact-checks", "exec-tests", "judge-triage", "judge-report", "judge-evidence", "judge-artifacts"]


def prompt(name: str) -> str:
    return (HERE / "prompts" / f"{name}.md").read_text().strip()


def dep(*ids: str) -> list[dict]:
    return [{"task_step_id": i} for i in ids]


def judge(step_id: str, prompt_id: str, rubric: dict, after: str) -> dict:
    total = sum(c["weight"] for c in rubric["criteria"])
    criteria = [{**c, "weight": c["weight"] / total} for c in rubric["criteria"]]
    return {
        "id": step_id, "type": "rubrics_verifier", "verifier_id": step_id, "prompt_id": prompt_id,
        "use_agent_judge": False, "default_model": JUDGE_MODEL, "output_format": "rubric_partial",
        "score_aggregator": "weighted_average", "criteria": criteria,
        "grading_policy_prompt": (
            f"You are grading a cyber defense analyst's {rubric['title']}. The scenario is a division exercise "
            "network with a confirmed intrusion and two authorized activities that look suspicious. Judge what the "
            "analyst actually submitted (its submit tool calls in the trajectory), not its summary of it. For code, "
            "judge the submitted text and how the analyst used the lab; execution results are scored separately. The "
            "answer key below lists the facts in the records that a correct product reflects.\n\n" + (HERE / "answer_key.md").read_text()
        ),
        "depends_on": dep(after),
    }


def task() -> list[dict]:
    rubrics = json.loads((HERE / "rubrics.json").read_text())
    env = lambda i: {"env_version": i} if i else {}
    return [
        {"id": "soc", "type": "deploy_env", "env_id": "soc", "sandbox_type": "local", "depends_on": [], **env(SOC_VERSION)},
        {"id": "lab", "type": "deploy_env", "env_id": "lab", "sandbox_type": "local", "depends_on": [], **env(LAB_VERSION)},
        {"id": "seed", "type": "load_artifact", "env_id": "soc", "artifact_id": SEED_ARTIFACT, "depends_on": dep("soc")},
        {"id": "seed-lab", "type": "load_artifact", "env_id": "lab", "artifact_id": LAB_SEED_ARTIFACT, "depends_on": dep("lab")},
        {"id": "analyst", "type": "deploy_agent", "a2a_agent_id": "sgp-agent", "a2a_agent_version": AGENT_VERSION,
         "agent_name": "analyst", "env_ids": ["soc", "lab"], "role": "analyst", "system_prompt": prompt("analyst_system"),
         "depends_on": dep("soc", "lab")},
        {"id": "triage", "type": "prompt_agent", "agent_name": "analyst", "prompt_id": "triage", "context_id": CONVERSATION,
         "prompt": prompt("triage_user"), "model": ANALYST_MODEL, "timeout_seconds": 1800, "depends_on": dep("seed", "seed-lab", "analyst")},
        {"id": "snap-triage", "type": "snapshot_env", "env_id": "soc", "snapshot_id": "soc-v2-after-triage", "depends_on": dep("triage")},
        {"id": "report", "type": "prompt_agent", "agent_name": "analyst", "prompt_id": "report", "context_id": CONVERSATION,
         "prompt": prompt("report_user"), "model": ANALYST_MODEL, "timeout_seconds": 1800, "depends_on": dep("snap-triage")},
        {"id": "snap-report", "type": "snapshot_env", "env_id": "soc", "snapshot_id": "soc-v2-after-report", "depends_on": dep("report")},
        {"id": "evidence", "type": "prompt_agent", "agent_name": "analyst", "prompt_id": "evidence", "context_id": CONVERSATION,
         "prompt": prompt("evidence_user"), "model": ANALYST_MODEL, "timeout_seconds": 1800, "depends_on": dep("snap-report")},
        {"id": "snap-evidence", "type": "snapshot_env", "env_id": "soc", "snapshot_id": "soc-v2-after-evidence", "depends_on": dep("evidence")},
        {"id": "artifacts", "type": "prompt_agent", "agent_name": "analyst", "prompt_id": "artifacts", "context_id": CONVERSATION,
         "prompt": prompt("artifacts_user"), "model": ANALYST_MODEL, "timeout_seconds": 2400, "max_turns": 60,
         "depends_on": dep("snap-evidence")},
        {"id": "snap-final", "type": "snapshot_env", "env_id": "soc", "snapshot_id": "soc-v2-final", "depends_on": dep("artifacts")},
        {"id": "snap-lab", "type": "snapshot_env", "env_id": "lab", "snapshot_id": "lab-v2-final", "depends_on": dep("artifacts")},
        # The offline scoring lane: the final soc snapshot is staged into a network-less container and graded there.
        {"id": "scorebox-vm", "type": "deploy_sandbox", "sandbox_name": "scorebox", "sandbox_mode": "vm", "ttl_seconds": 3600, "depends_on": []},
        {"id": "scorebox-ctr", "type": "run_docker_container", "sandbox_name": "scorebox", "docker_context_artifact_id": "scorebox_context",
         "container_name": "scorebox", "network": "none", "env_vars": {}, "depends_on": dep("scorebox-vm")},
        {"id": "handoff", "type": "load_artifact", "sandbox_name": "scorebox", "container_name": "scorebox", "artifact_from_step_id": "snap-final",
         "destination_path": "/handoff", "depends_on": dep("snap-final", "scorebox-ctr")},
        {"id": "exec-tests", "type": "run_container_unit_tests_verifier", "verifier_id": "exec-tests", "sandbox_name": "scorebox",
         "container_name": "scorebox", "user": "runner", "command": GRADER, "timeout_sec": 600, "env_vars": SCOREBOX_ENV,
         "result_paths": ["/work/out/results.json"], "reward_path": "/work/out/reward.txt", "depends_on": dep("handoff")},
        # Host-side, parse-only checks and the judges.
        {"id": "facts", "type": "env_outcome_verifier", "env_id": "soc", "file_artifact_id": "check_facts", "verifier_id": "facts",
         "score_aggregator": "weighted_average", "depends_on": dep("artifacts")},
        {"id": "artifact-checks", "type": "env_outcome_verifier", "env_id": "soc", "file_artifact_id": "check_artifacts",
         "verifier_id": "artifact-checks", "score_aggregator": "weighted_average", "depends_on": dep("artifacts")},
        judge("judge-triage", "triage", rubrics["triage"], "triage"),
        judge("judge-report", "report", rubrics["report"], "report"),
        judge("judge-evidence", "evidence", rubrics["evidence"], "evidence"),
        judge("judge-artifacts", "artifacts", rubrics["artifacts"], "artifacts"),
        {"id": "score", "type": "aggregate_verifiers", "verifier_id": "soc-v2", "verifier_ids": VERIFIERS,
         "score_aggregator": "weighted_average", "depends_on": dep(*VERIFIERS)},
    ]


def sync() -> None:
    """Regenerate the pieces copied from elsewhere."""
    v1 = (V1 / "soc-eval" / "artifacts" / "check_facts" / "verify.py").read_text()
    assert v1.count("FACTS_WEIGHT_TOTAL = 6\n") == 1, "v1 verify.py changed its weight constant"
    (HERE / "soc-eval" / "artifacts" / "check_facts" / "verify.py").write_text(
        v1.replace("FACTS_WEIGHT_TOTAL = 6\n", "FACTS_WEIGHT_TOTAL = 1.0  # v2: every verifier totals 1.0 (generated from v1 by build.py)\n", 1))
    spec = importlib.util.spec_from_file_location("scorebox_sync", REPO / "soc-env" / "scorebox" / "sync.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if mod.main() != 0:
        raise SystemExit("scorebox sync failed")


def _load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem + "_" + path.parent.name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def check_weights() -> None:
    """Every verifier must total 1.0: the two code-check modules by constant, the rubrics by normalization in judge()."""
    facts = _load(HERE / "soc-eval" / "artifacts" / "check_facts" / "verify.py")
    artifacts = _load(HERE / "soc-eval" / "artifacts" / "check_artifacts" / "verify.py")
    if float(facts.FACTS_WEIGHT_TOTAL) != 1.0 or float(artifacts.ARTIFACT_WEIGHT_TOTAL) != 1.0:
        raise SystemExit(f"weights: facts {facts.FACTS_WEIGHT_TOTAL}, artifacts {artifacts.ARTIFACT_WEIGHT_TOTAL}; both must be 1.0")
    grader = (REPO / "soc-env" / "scorebox" / "harness" / "run_tests.py").read_text()
    weights = json.loads("{" + grader.split("WEIGHTS = {", 1)[1].split("}", 1)[0].replace("\n", "").replace('"', '"') + "}") if False else None
    rows = _load(REPO / "soc-env" / "scorebox" / "harness" / "run_tests.py").WEIGHTS
    if round(sum(rows.values()), 6) != 1.0:
        raise SystemExit(f"scorebox WEIGHTS total {sum(rows.values())}; must be 1.0")


def main() -> None:
    sync()
    check_weights()
    path = HERE / "soc-eval" / "tasks" / "soc_artifacts.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(task(), indent=2) + "\n")
    print(f"wrote {path.relative_to(REPO)} ({len(task())} steps)")


if __name__ == "__main__":
    main()
