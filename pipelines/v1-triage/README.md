# v1: alert triage and incident report (current)

The analyst works the cyber defense cell (`soc-env/`, env `soc`) in one conversation:

1. **Triage.** It reads the situation, the alert queue, the assets, the logs, the change records and
   the intelligence through the SOC tools and submits one assessment per alert.
2. **Incident report.** It writes and submits the incident report for what it confirmed: scope,
   indicators, a timed attack narrative, containment actions from the playbook, escalation and
   evidence to preserve.

## Grading

| Step | Type | What it does |
| --- | --- | --- |
| `facts` | `env_outcome_verifier` | Code checks on the end state ([check_facts/verify.py](soc-eval/artifacts/check_facts/verify.py)): 8 triage checks, 11 report checks, 8 containment checks, 4 process checks, plus an unweighted trap trace and the tool-call count |
| `judge-triage` | `rubrics_verifier` | Direct LLM judge on the triage: verdict accuracy, evidence, correlation |
| `judge-report` | `rubrics_verifier` | Direct LLM judge on the report: scope and narrative, containment and playbook compliance, indicators and escalation |
| `score` | `aggregate_verifiers` | One score: code checks and judge criteria weigh the same (6 and 6) |
| `snap-triage`, `snap-final` | `snapshot_env` | The env's state after each phase, as versioned artifacts |

**Models.** The analyst and the judge both run on `gpt-4o`; the scorecard flags the self-grading
caveat on the two judge scores.

## Files

```
pipelines/v1-triage/
  prompts/                 the analyst's system prompt and its two user prompts (triage, report)
  rubrics.json             the judge rubrics
  answer_key.md            the incident's planted facts, given to the judge as its grading policy
  build.py                 writes soc-eval/tasks/soc_triage.json; deploys the latest soc, seeds soc-sample, pins sgp-agent v1
  export_run.py            unpacks one run into runs/v1/<instance>/, with scorecard.md
  soc-eval/                the bundle: artifacts/check_facts and tasks/soc_triage.json
```

## Run it

Needs `soc` registered from `soc-env/soc/` (see the [top-level README](../../README.md)). After
changing a prompt or the rubrics, rebuild the task:

```bash
uv run python pipelines/v1-triage/build.py
```

Run one eval:

```bash
uv run agent-env run pipelines/v1-triage/soc-eval
```

Export it, with the instance id the run prints, then open `runs/v1/<instance>/scorecard.md`:

```bash
uv run python pipelines/v1-triage/export_run.py "<instance id>"
```

## Findings so far

None yet: no eval has run. The smoke test passes.
