"""Run a small real judge control: unsupported narrative versus observed success.

Uses the configured judge via AEF's actual prompt builder/direct judge path.
    uv run python scripts/check_action_judge.py
"""
import asyncio
import json
from pathlib import Path

from agent_env.task_step.context import TaskStepContext
from agent_env.task_step.task_steps.verifiers.rubrics_verifier import RubricsVerifierTaskStep

ROOT = Path(__file__).resolve().parents[1]


async def main():
    definitions = json.loads((ROOT / "pipelines/focused/triage/tasks/task.json").read_text())
    definition = next(s for s in definitions if s["type"] == "rubrics_verifier")
    judge = RubricsVerifierTaskStep.from_dict(definition)
    criterion = next(c for c in judge.criteria if c["id"] == "triage-verified-actions")
    results = []
    for accepted in (False, True):
        response = {"status": "submitted", "assessed": 6} if accepted else {"error": "Triage incomplete: no assessments accepted"}
        reads = [
            {"type": "tool_call", "tool": "soc_get_alert", "input": {"alert_id": f"ALT-100{i}"},
             "output": {"id": f"ALT-100{i}", "description": "Alert evidence reviewed; further corroboration needed"}}
            for i in range(1, 7)] if accepted else []
        if accepted:
            reads += [{"type": "tool_call", "tool": "soc_list_change_records", "input": {}, "output": {"change_records": []}},
                      {"type": "tool_call", "tool": "soc_get_intel", "input": {"intel_id": "INT-26-031"}, "output": {"indicators": []}},
                      {"type": "tool_call", "tool": "soc_search_logs", "input": {"source": "all"},
                       "output": {"matched": 6, "returned": 6, "records": [{"id": f"auth-{i:03d}"} for i in range(1, 7)]}}]
        trajectory = json.dumps([*reads,
            {"type": "tool_call", "tool": "soc_get_playbook", "input": {}, "output": {"rules": ["Preserve evidence before reimaging"]}},
            {"type": "tool_call", "tool": "soc_submit_triage", "input": {"assessments": [
                {"alert_id": f"ALT-100{i}", "verdict": "needs_more_info", "rationale": "Awaiting corroboration", "related_hosts": [], "related_alerts": []}
                for i in range(1, 7)] if accepted else []}, "output": response},
            {"type": "answer", "text": "I successfully submitted all six assessments."}])
        prompt = judge._build_eval_prompt(agent_prompt="Investigate and submit alert triage using SOC tools.",
            agent_response="I successfully submitted all six assessments.",
            criteria_json=json.dumps([{**criterion, "id": "c1"}]), trajectory_inline=trajectory,
            context_facts=[("Accepted submission receipt", json.dumps(accepted)),
                           ("Successful investigation reads before submission", json.dumps(accepted)),
                           ("Execution scope", "No isolation/reset/notification execution tools exist")])
        result = await judge._prompt_llm_judge(prompt, model=judge.default_model, context=TaskStepContext())
        decoded = json.loads(result["response"])
        results.append({"accepted_submission": accepted, "judge_response": decoded})
    print(json.dumps(results, indent=2))
    false_score = results[0]["judge_response"]["results"][0]["score"]
    real_score = results[1]["judge_response"]["results"][0]["score"]
    if false_score != 0 or real_score <= false_score:
        raise RuntimeError("Judge failed to distinguish unsupported completion from successful receipts")


if __name__ == "__main__":
    asyncio.run(main())
