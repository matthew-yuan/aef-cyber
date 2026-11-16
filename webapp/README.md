# Cyber Eval Console

## Batch evaluations and repeated trials

Select multiple scenarios in **Batch evaluations & reliability**, set **Trials per
scenario (k)** (1–20), **Parallel trials** (1–4, default 2), and a success threshold
(default 0.80). Maximum 40 trials per batch. The selected analyst/judge dropdowns
apply to every model-based trial. Children appear in normal run history with
individual Inputs, outputs and logs.

Each batch builds once in a frozen source snapshot, pins external env/data
versions, and records an input SHA-256. Each trial gets a separate bundle namespace,
fresh deployments and instance-derived snapshot IDs. Separate worker processes
avoid model-setting/build races and AEF signal-handler conflicts. One active batch
or single run owns the dashboard launch slot; the batch limits concurrent trials,
while AEF still parallelizes independent DAG steps inside each trial. On the
2-CPU/4-GB Docker runtime, start with concurrency 2. Closing the page does not stop
execution; crashed coordinators/workers are marked interrupted, not passed.

Reliability is successful finished trials / all finished trials, including errors
in the denominator. Success uses the final mission/focused aggregate (all three
expected verifiers for infrastructure), requires a positive score at least the
threshold, and excludes critical failures, refused execution and export errors.
The UI reports a 95% Wilson interval and whether all k succeeded. These are observed
outcomes, not population pass@k estimates; k=2 has wide uncertainty. Keep inputs,
models, budgets and concurrency fixed for comparisons. Runtime agents are unchanged;
coding subagents help independent implementation/review, not the evaluated answers.

API: `POST /api/batches` with
`{"pipelines":["triage","report"],"k":2,"concurrency":2,"success_threshold":0.8}`
and optional `model` / `judge_model`; `GET /api/batches` returns grouped summaries.
Batch manifests/logs live in `.dashboard/batches/<id>/`. Do not edit snapshots
while running. Background runs preserve their usual `runs/<scenario>/...` exports.

Research: installed AEF `bundle/run.py` runs each selected task once and supports
internal dependency parallelism; explicit process scheduling adds repeats and a
global bound. Anthropic's [agent evaluation guidance](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents)
motivates fresh environments and separates any-success capability from all-trial
reliability.

Both model menus show the same saved list of available chat models, with plain model names.
Run `uv run python -m webapp.scan_models` once to discover chat aliases and test each with a small
completion. Results are saved under ignored `.dashboard/models/`, scoped to your endpoint and key
without storing credentials. Page loads, Refresh models, launches and server restarts read this
file without making inference calls. The scan resumes unchecked aliases if interrupted; remove the
saved catalog explicitly to recheck everything. Availability does not guarantee tool-calling or
strict-schema support, so choose a suitable model for each role. Defaults remain GPT-5 / GPT-6-Sol.

Start from the repository root:

```bash
uv sync
uv run python -m webapp.app
```

Open **http://127.0.0.1:8765**. Launch v3 update/revision evaluations, v2 artifact evaluations,
or a model-free SOC smoke test. The console shows AEF step progress, execution logs, verifier
scores/details and exported reports. It refreshes every two seconds.
The left navigation shows the actual AEF dependency DAG, including parallel branches and joins.
Its default Overview groups steps into readable phases with descriptions and progress counts.
Use **Expand graph** to open the full dependency graph in a large dialog. Zoom in/out, reset to
100%, or fit the entire graph; scroll to pan and Ctrl/Command+wheel to zoom. Escape closes it.
Select a phase to list its steps, or switch to Detailed DAG for exact dependencies at full size.
Overview phase ordering is a guide to the evaluation; parallel work is represented exactly in Detailed DAG.
Select a run for live/completed step colors, select a node to inspect dependencies, or change the
scenario / click Preview to explore a workflow before launching it. New runs retain their workflow
definition; older runs fall back to the currently configured task. On narrow screens the graph moves
above the run list, with its own scrollable viewport.

Preview reloads the selected task definition and resets its viewport, independently of the selected
run. Assets and status responses are uncached. During a run, elapsed step time and a three-second
worker heartbeat distinguish a long model phase from an unresponsive worker. A heartbeat proves the
worker process is alive, not that the model has returned; phase completion still comes from AEF.

Analyst-model overrides
change the evaluated model; the separate judge field changes all rubric judges. Full evaluations spend LiteLLM model budget using the
credentials inherited from the server's shell. On this branch inference uses the remote LiteLLM proxy,
GPT-5 analysts and GPT-6-Sol judges, with `LITELLM_API_KEY` and `LITELLM_BASE_URL` exported before startup.
Docker and the main README's registrations are required.

## Test scenarios

Every scenario has a `rubric.md` reference beside its task bundle and in exported run results.
Use “View scenario rubric (.md)” before launch, or select `rubric.md` under a completed run.
Scorecards show component scores, pass/fail observations and judge feedback. `grading_details.md`
adds rule-level precision, recall, behavior coverage and judge reasoning for full workflows too.
Refresh older saved runs without model calls: `uv run python -m webapp.refresh_reports`.

| Scenario | Model calls | What to try |
| --- | --- | --- |
| Pipeline functionality check | None | SOC tools, lab safety and offline scoring in one run |
| Rules generation & grading | Select analyst + judge | Code: model-generated rules, lab tests, precision/recall and detection-logic grade |
| Triage process & grading | Select analyst + judge | Reasoning: alert verdicts, evidence, correlation and investigation process |
| Report generation & grading | Select analyst + judge | Artifacts: independent incident report, containment, escalation and content grade |
| Alert triage & incident report | GPT-5 + GPT-6-Sol | Quick full analyst evaluation: benign traps, VPN foothold, data loss |
| Evidence & code artifacts | GPT-5 + GPT-6-Sol | Inspect forensic analysis, lab iteration and executable detection quality |
| Incident update & revision | GPT-5 + GPT-6-Sol | Inspect late lateral movement, revised scope and regression checks |

All model scenarios share the curated incident; these are different evaluation workflows,
not independent held-out datasets. Both model fields accept AEF-prefixed proxy aliases.

Dashboard runs are indexed under ignored `.dashboard/` and execute in independent worker processes,
so page refreshes or web-server restarts do not stop their AEF execution. One dashboard run is allowed
at a time. AEF tears down sandboxes; workers retain safe contexts and automatically export successful
v2/v3 runs. A below-perfect score is a completed evaluation, not an infrastructure failure. All report
Markdown is rendered with headings, tables, lists and code blocks; raw HTML and unsafe link schemes
are disabled. The report viewer retains its scroll position during polling and workflow updates.
The smoke test shows its verification rows without a report export.

The index covers dashboard-launched runs, not unrelated AEF jobs started elsewhere. This is a local,
single-user console bound to loopback; run only one web-server process. If a worker dies unexpectedly,
inspect its log and Docker resources before starting another evaluation. Frontend assets are plain
HTML/CSS/JavaScript with no build step or external assets. Tests: `uv run pytest`.
