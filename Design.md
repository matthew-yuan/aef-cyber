# Design: code artifacts for incident response, verified without host execution (v2)

**Status:** implemented and smoke-proven on 2026-11-03 (pipeline `pipelines/v2-artifacts/`). No model run yet.
This is the design plan the work followed, updated where the build changed it (marked *as built*).

## Context

aef-cyber evaluates an AI analyst that triages a fictional SOC alert queue and writes an incident report,
using the AgentEnv Framework (AEF) 0.9.1335 locally in Docker. v2 extends it so the analyst also **produces
code** that supports response and triage (detection rules, hunt scripts, IOC extractors) and **analyzes
evidence** (scripts, configs, forensic triage packages) into reports, under one hard rule: **agent-generated
code never executes on the host machine**, while still being tested and verified as far as is reliable.

Decisions taken with the project owner:

- Execution boundary: **both lanes**. A `lab` environment container where the agent can run its own hunt
  script mid-task and iterate (bridge network, no secrets, static pre-screen), plus an **authoritative scoring
  lane in a framework-managed container started with `network="none"`**, non-root, LLM keys stripped.
- Languages: **Python only**.
- Artifacts: Sigma-style detection rules (YAML, evaluated by our trusted evaluator, no agent code runs), hunt
  and log-analysis scripts, IOC extractors, and **evidence analysis reports** over text and structured
  evidence. Disk images are out of scope for this phase.
- v1 stays intact; v2 is a new pipeline following the repo's conventions.

## Framework facts that constrain the design (verified in the installed source)

Where code runs with the local provider (`.venv/lib/python3.12/site-packages/agent_env/`):

| Code | Runs where | Evidence |
| --- | --- | --- |
| `verify.py` of `env_outcome_verifier` | **host, inside the runner's own Python process** (`exec_module` of a temp file, so sibling imports don't resolve) | `task_step/task_steps/verifiers/env_outcome_verifier.py:92-127` |
| `run_code` with `env_id` or a VM-mode `sandbox_name` | **host subprocess** | `run_code.py:402,535`, `local_sandbox.py:332-346` |
| `run_code` on the agent (default) or a container-mode sandbox | that container (`docker exec -u 0`) | `run_code.py:425-460` |
| `run_docker_container` + `run_container_unit_tests_verifier` | a container the framework builds from a file-artifact-universe build context; `network="none"` supported; `user` selectable on the exec; LLM keys (`LITELLM_*`, `ANTHROPIC_*`, `LITELLM_EXTRA_HEADERS`) auto-injected unless overridden in `env_vars` | `run_docker_container.py:33-70,150-225`, `verifiers/run_container_unit_tests_verifier.py:54-117,240+` |
| MCP-server env containers (`soc`, `lab`) | compose stack on a plain bridge (`env-network`) with NAT egress; no `internal`, `user`, `read_only`, `cap_drop` or resource knobs; no LLM keys inside | `providers/env_providers/env_gateway_provider.py:379-553` |
| Agent container | default bridge, full egress, holds `LITELLM_*` keys. Never run untrusted code there. | `a2a_agent/a2a_agent.py:434-470` |

Plumbing facts the design relies on:

- `snapshot_env` persists only `parts[0]` of `data/get`: every artifact lives inside the single DataPart dict.
- `load_artifact(sandbox_name, container_name, artifact_from_step_id=<snapshot step>, destination_path)`
  stages a snapshot universe as files at `<dest>/<environment_name>/<file>.json` by `docker cp`
  (`load_artifact.py:455-490`, `environment_universe.py:227-238`). Its `mkdir -p` runs as the image user.
- `@tool` params: a default makes the param optional; results go out as indent-2 JSON text; no size caps on
  args or results. The agent's `max_tokens` 8000 per model call bounds one submission, so tools return short
  receipts, never echoes.
- `rubrics_verifier` with `use_agent_judge=False` inlines the full trajectory into the judge prompt.
- `aggregate_verifiers` concatenates all child rows into one weighted average, so **each verifier's rows
  must sum to the same total weight**. The unit-test verifier contributes one `reward` row of weight 1.0.
- A bundle `artifacts/<name>/` folder with a `Dockerfile` is inferred as an image to build; an
  `artifact.toml` declaring `type = "file_artifact_universe"` keeps it a file universe with the Dockerfile as
  content (`bundle/parse.py:285-325`). That is how the scoring container's build context ships.
- `agent-env env mcp-server put --dockerfile <path> --context soc-env` lets the env Dockerfiles copy the
  shared trusted modules.

## Invariants (the safety contract)

1. No host-side file (`verify.py`, `build.py`, `export_run.py`, any `run_code` script, tests) ever calls
   `exec`, `eval`, `compile`, `importlib`, `runpy` or `subprocess` on agent content. They may only
   `ast.parse`, `yaml.safe_load`, `json.loads`, hash and regex-match it, under size caps.
   `tests/test_host_inert.py` enforces this by AST scan (the only allowances: `build.py` and
   `export_run.py` load the project's own `verify.py` modules by path, and `export_run.py` calls the
   `agent-env` CLI with a literal argument list).
2. Agent code executes in exactly two places: the `lab` container (interactive, pre-screened, demoted user,
   rlimits, deadline) and the `scorebox` container (`network="none"`, demoted user, LLM variables blanked).
   Neither holds credentials; only the scorebox holds the ground truth, and the agent never reaches it.
3. *As built:* no host script touches the hand-off. The framework stages the final `soc` snapshot into the
   scorebox (`snapshot_env`, then `load_artifact` with `artifact_from_step_id`).
4. `export_run.py` writes agent code under `runs/v2/<instance>/artifacts/` with a `.txt` suffix and a banner.
5. Model-free smoke tasks prove the boundary: a sample that imports `socket` is refused at submission and in
   the lab; a spinning sample is killed at its limit; a memory bomb dies under the address-space limit; a
   crashing sample reports its error; the golden samples return findings; the scoring chain grades them.

## Design

### 1. Data (`soc-env/data/`)

- `incident.json`: every log record has a stable `id` (`auth-001`, `dns-004`, ...). An `evidence` list holds
  seven read-only items `{id, kind: text|json|hexdump, title, source_host, collected_at, content}`: `EV-01`
  decoded PowerShell cradle, `EV-02` scheduled-task XML export, `EV-03` and `EV-04` triage packages for
  WS-G3-014 and SRV-WEB-02, `EV-05` hex dump and strings of the fictional implant, `EV-06` the phishing email
  (the distractor), `EV-07` the implant configuration recovered from memory (fallback C2 domain, beacon
  interval, mutex, kill date: indicators that exist in no log).
- `ground_truth.json` (**never loaded into `soc` or `lab`; ships only in the scorebox image**): 39 malicious
  record ids with behavior tags, 8 scored behaviors, the phishing records as `fp_exempt`, the benign traps as
  `must_not_match`, compromised / neutral / benign hosts, required, evidence-only and forbidden indicators,
  and per-item evidence facts as regex alternations.
- `log_export.json` (generated by `build_exports.py` through `shared/logexport.py`): the exact object analyst
  code receives, `{"incident_id", "sources", "auth": [...], "dns": [...], "proxy": [...], "endpoint": [...]}`,
  every record with `id` and `source`.

### 2. Shared trusted modules (`soc-env/shared/`)

- `codescreen.py`: AST-based screen, pure stdlib, never compiles. Allow-list of stdlib imports plus
  `urllib.parse`; denies `eval exec compile __import__ open globals locals vars breakpoint input ...`,
  3-argument `type`, `getattr`/`setattr`/`hasattr` without a literal non-dunder name, format strings reaching
  dunders, dunder attributes other than `__name__`/`__doc__`, async code, relative and star imports, and any
  top-level statement that is not an import, constant, def, class or `if __name__ == "__main__":` guard.
  Interface rules: `hunt_script` defines `hunt(data)`, `ioc_extractor` defines `extract(data)`. Also holds
  `CONTRACT`, the text shown to the analyst.
- `sigma_lite.py`: the documented Sigma subset. `logsource.service` or a mapped `category`; named selections
  (map = AND, list of maps = OR, list of scalars = keywords); modifiers `contains startswith endswith all cidr
  gt gte lt lte`; wildcards; `null`; conditions with `and or not ( ) 1 of X* all of X* 1 of them all of them`;
  refuses regex, encodings, aggregations, `near`, multi-document files and oversized rules. `score_rules`
  gives per-rule precision, per-behavior recall and behavior coverage against the ground truth.
- `sandboxrun.py` + `bootstrap.py`: the execution recipe used by both the lab and the scorebox. The parent
  writes the code to a private run dir and starts `python3 -I -S -B bootstrap.py` as a demoted uid when it is
  root, with rlimits (cpu, 512 MiB address space, 16 processes, 8 MiB files, 32 fds, no core), a scrubbed
  environment with dead proxies, closed stdin, captured and tail-capped output, and a wall-clock deadline
  (SIGXCPU from the cpu limit counts as a timeout). The child installs an import denier (`sys.modules`
  poisoning plus a meta-path finder) and a reduced `__builtins__` without `open/exec/eval/compile/__import__`,
  executes the module in a fresh namespace, calls the entry function on a deep copy of the data, validates the
  shape and writes `result.json`. This is the one place agent code is compiled and executed.
- `logexport.py`: `build_export(incident)`, the single definition of the data object.
- All copies are made by `soc-env/scorebox/sync.py` (into the scorebox contexts) or by the Docker build
  context (`--context soc-env` for `soc` and `lab`); `tests/test_sync.py` fails on drift. *As built:* the
  host verifier does **not** embed the modules; it is parse-only, and all evaluation runs in the scorebox.

### 3. `soc` env additions (v3, `soc-env/soc/server.py`)

- Read: `soc_get_log_schema` (fields and an example per source, the contract, allowed imports, limits),
  `soc_list_evidence`, `soc_get_evidence(evidence_id, offset, length)` (paged text; never decoded or run).
- Act: `soc_submit_artifact(kind, name, content, notes)` for `sigma_rule | hunt_script | ioc_extractor`,
  screened on submission (`codescreen` or `sigma_lite.validate`) and **rejected with the problem list**;
  64 KB per artifact (16 KB per rule), 8 accepted per run, 12 submissions per kind, unique `(kind, name)`,
  a receipt `{status, sha256, bytes, check}` and never the content; `soc_submit_evidence_report(evidence_ids,
  verdict, summary, findings, indicators, recommended_actions)`, once.
- `data/get` adds `evidence_ids`, `artifacts` (full content, since the snapshot is the durable copy),
  `artifact_attempts`, `evidence_report`. Audit entries for submissions carry kind, name, sha256 and bytes only.

### 4. The `lab` env (`soc-env/lab/`)

- Image from `soc-env/` context: protocol SDK, pyyaml, the shared modules; the server stays root only to
  demote each run to `runner` (uid 10002); `/lab/datasets` and `/lab/runs`; no ground truth.
- *As built:* seeded by `load_artifact` with its own environment artifact (`lab-incident-sample`,
  `environment_name=lab`, universe `lab-sample`); `data/add` builds the export in memory and writes
  `/lab/datasets/logs.json`.
- Tools: `lab_list_datasets`, `lab_describe_dataset`, `lab_screen(kind, code)`, `lab_run_script(kind, code,
  dataset, timeout_s)` (screen first; then `sandboxrun`; returns exit status, tails and a summary of findings
  or indicators), `lab_test_rule(rule_yaml, dataset)` (`sigma_lite`; match counts and samples, no labels),
  `lab_history`. Budget 25 runs and tests per task; runs are recorded by sha256, outcome and counts, never code.
- Network: `unshare` is unavailable without `CAP_SYS_ADMIN`, so the lab's defenses on the bridge are the
  screen, the runtime denier, the scrubbed environment and the absence of secrets. The README says so.

### 5. The scoring lane (`scorebox`), as task steps after the artifact phase (*as built*)

| Step id | Type | Key fields |
| --- | --- | --- |
| `snap-final` | `snapshot_env` | `env_id: soc` |
| `scorebox-vm` | `deploy_sandbox` | `sandbox_name: scorebox`, `sandbox_mode: vm`, `ttl_seconds: 3600` |
| `scorebox-ctr` | `run_docker_container` | `docker_context_artifact_id: scorebox_context`, `container_name: scorebox`, `network: none`, `env_vars: {}` (image CMD `sleep infinity`) |
| `handoff` | `load_artifact` | `sandbox_name: scorebox`, `container_name: scorebox`, `artifact_from_step_id: snap-final`, `destination_path: /handoff` |
| `exec-tests` | `run_container_unit_tests_verifier` | `user: runner`, `command: python3 -I /harness/run_tests.py --handoff /handoff --data /harness/data --out /work/out --work /work/runs`, `timeout_sec: 600`, `env_vars` blanking `LITELLM_API_KEY`, `ANTHROPIC_API_KEY`, both base URLs and `LITELLM_EXTRA_HEADERS` (`"{}"`), `result_paths: [/work/out/results.json]`, `reward_path: /work/out/reward.txt` |

- `soc-env/scorebox/` is the source of the build context: `artifact.toml` (`type = "file_artifact_universe"`),
  `Dockerfile` (python:3.12-slim, `runner` uid 10003, `/handoff` and `/work` owned by it, `USER runner`),
  `harness/run_tests.py` plus synced copies of the shared modules, `data/log_export.json` and
  `data/ground_truth.json`. `sync.py` mirrors it into `soc-env/scorebox-smoke/artifacts/scorebox_context`
  and `pipelines/v2-artifacts/soc-eval/artifacts/scorebox_context`.
- `run_tests.py`: finds the snapshot under `/handoff/soc/*.json`, writes each accepted artifact to a file,
  runs the isolation self-checks (non-root; no TCP connect, no DNS; no credential variables) and **refuses to
  execute anything if one fails** (reward 0, `refused` set). Then: Sigma rules through `sigma_lite`
  (`sigma-valid`, `sigma-precision` union ≥ 0.9 with no trap hits, `sigma-recall` ≥ 0.6, `sigma-coverage` ≥ 4 of
  8 behaviors); hunt scripts through `sandboxrun` (`hunt-runs`, `hunt-schema`, `hunt-hosts` = compromised set
  with the VPN gateway neutral, `hunt-precision` ≥ 0.9, `hunt-recall` ≥ 0.7; best script when several); IOC
  extractors (`ioc-runs`, `ioc-required` ≥ 7 of 8, `ioc-no-forbidden`). Row weights total 1.0; the reward is
  the weighted fraction passed. `results.json` carries every row with details and is stored inline in the
  verifier record, where `export_run.py` reads it.

### 6. v2 pipeline (`pipelines/v2-artifacts/`)

- Prompts: v1's system prompt plus the code contract and the lab; v1's triage and report prompts unchanged;
  `evidence_user.md`; `artifacts_user.md`. Phase order: triage, report, evidence, artifacts (so the artifact
  phase can use the evidence-only indicators). The artifact phase gets `max_turns: 60`.
- `build.py`: the 25-step DAG (two envs, two seeds, the agent on both, four prompts, five snapshots, the
  scoring lane, two host-side verifiers, four judges, the aggregate); regenerates `check_facts/verify.py`
  from v1 with the total weight set to 1.0; runs the scorebox sync; `check_weights()` asserts every
  verifier totals 1.0 (both check modules by constant, the grader's `WEIGHTS`, the rubrics by normalization).
- `check_artifacts/verify.py` (host, parse-only, 18 rows): an artifact of each kind accepted; receipts intact
  (sha256 matches content, submission check passed); everything still parses; rejections bounded; the
  evidence report submitted with a finding per item, stating each item's facts (patterns mirrored from
  `ground_truth.json`, asserted equal by a test), and not calling EV-03's run key malicious; the contract read
  before the first submission; every evidence item read before the report.
- `rubrics.json`: v1's two rubrics plus `evidence` (accuracy; evidence-only indicators and contradictions;
  judgment) and `artifacts` (detection logic; hunt method including the lab loop; IOC fidelity).
- `export_run.py`: v1's structure plus `evidence_report.md`, `lab_history.md` (from `snap-lab`), a
  quarantined `artifacts/` folder and a scorecard with the scorebox rows.

### 7. Weights

Seven verifiers, each worth 1.0 in the aggregate: `facts` (31 rows at 1/31), `artifact-checks` (18 rows at
1/18), four judges (three criteria at 1/3), `exec-tests` (one reward row at 1.0).

## Verification (all model-free; results from the build)

| Check | Result |
| --- | --- |
| `uv run pytest` (screen, evaluator, data, sync, host inertness, v2 consistency) | 37 passed |
| `agent-env run soc-env/smoke` (soc v3 tools and refusals) | pass |
| `agent-env run soc-env/lab-smoke` (banned refused, spin killed, memory bomb dies, crash reported, golden runs, rule test, budget, no code in state) | pass |
| `agent-env run soc-env/scorebox-smoke` (full chain with golden fixtures) | reward 1.0; all sandbox self-checks pass |
| `agent-env run --dry-run pipelines/v2-artifacts/soc-eval` | resolves soc v3, lab v2, soc-sample v2, lab-sample v1, sgp-agent v1 |

Not yet done: a model run (blocked on SGP account access), hand-grading the first scorecard, threshold tuning.

## Spikes, as resolved

- Hand-off into the scoring container: solved by `load_artifact(artifact_from_step_id=snap-final)`; no host
  script, no fixed directory, no concurrency limit.
- `artifact.toml` with `type = "file_artifact_universe"` beside a `Dockerfile`: accepted by the bundle and
  built by `run_docker_container`.
- `docker cp` ownership: files land root-owned and readable; `/handoff` and `/work` are pre-created for `runner`.
- `unshare -rn` in the lab: not available without `CAP_SYS_ADMIN`; dropped.
- Timeouts: the cpu rlimit fires SIGXCPU before the wall-clock deadline; `sandboxrun` treats it as a timeout.
- Poisoning `threading` in the child broke interpreter shutdown; it is excluded from `sys.modules` poisoning
  (the finder still blocks a fresh import).

## Deferred

A second, held-out incident for generalization scoring; a privilege-separated lab server; an sgp-agent with
a larger output budget; a mid-task inject (new alert or bulletin) with a graded revision; disk images and
memory captures parsed by trusted tooling in the scorebox; network policies and resource limits when the
provider supports them; pass@k runs.
