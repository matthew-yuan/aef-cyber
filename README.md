# aef-cyber: agent T&E for cyber defense with AEF and LiteLLM

This project evaluates an AI agent on a cyber defense staff task: triaging a security alert queue
and writing the incident report. It uses Scale's open-source
[AgentEnv Framework](https://www.agentenvframework.com/docs) (`agentenv-framework` 0.9.1335) and
models served by Scale's remote LiteLLM proxy. Execution runs locally in Docker. It is
the cyber counterpart of [aef-toc-environment](https://github.com/cmullen-scale/aef-toc-environment),
and shares its layout, agent and config. **All scenario data is fictional and unclassified.**

## Which pipeline?

| Pipeline | Status | What it is | Run it |
| --- | --- | --- | --- |
| [v3-update](pipelines/v3-update/) | **Current** | v2 plus a mid-task telemetry update, report revision, adaptation/retention checks and a revision judge. Preserves the baseline score. | `uv run agent-env run pipelines/v3-update/soc-eval` |
| [v2-artifacts](pipelines/v2-artifacts/) | Baseline, still runs | v1 plus evidence analysis and detection/response code: the analyst reads forensic evidence, then writes Sigma rules, a hunt script and an IOC extractor, testing them in a lab container. Graded by code checks, four judges and offline execution tests. | `uv run agent-env run pipelines/v2-artifacts/soc-eval` |
| [v1-triage](pipelines/v1-triage/) | Baseline, still runs | The analyst triages the alert queue, then writes the incident report, in one conversation. Graded by code checks on the end state, a direct LLM judge per phase, one aggregate score, and a scorecard for human review. | `uv run agent-env run pipelines/v1-triage/soc-eval` |

Both pipelines use the same world and agent image; v2 adds a lab environment and a scoring container:

- **The cyber defense cell** ([soc-env/](soc-env/)): an MCP server environment where an AI agent
  playing a division cyber defense analyst reads a fictional incident through tools (situation,
  alert queue, asset inventory, auth / DNS / proxy / endpoint logs, threat intelligence, change
  records, playbook) and submits its work.
- **The lab** ([soc-env/lab/](soc-env/lab/)): a second environment where the analyst can run its own
  hunt scripts and test its Sigma rules against the same logs, in a demoted, resource-limited child
  process, with no secrets and no answer key.
- **The scorebox** ([soc-env/scorebox/](soc-env/scorebox/)): the offline container (`network: none`)
  where the analyst's code is executed and graded against the ground truth. See the
  [v2 README](pipelines/v2-artifacts/README.md) for the full boundary.
- **`sgp-agent`** ([agents/sgp-agent/](agents/sgp-agent/)): one tool-using A2A agent that calls SGP
  models in OpenAI format. The pipelines deploy it with its role, prompts and model.

The incident has planted traps for the analyst to find:

- a high-severity port scan and a quarantined credential-dumping tool that are both authorized
  activity under change records
- a low-severity VPN logon that is the intrusion's foothold, with persistence and command and
  control visible only in the logs
- a credential attack on the plans file server that ends in the draft division order being
  exfiltrated
- a server recorded as decommissioned that is online and beaconing
- an unrelated phishing click that must not be merged into the intrusion
- in the evidence (v2): a legitimate run key beside the real persistence, a server whose uptime
  contradicts its decommission record, and indicators that exist only in forensic data

## Layout

```
.agentenv/config.toml        agent-env config: local stores and Docker sandboxes, SGP model endpoint
sgp_smoke_test.py            checks one SGP model call through agent-env's model config
agents/sgp-agent/            the shared agent (registered as sgp-agent)
soc-env/
  soc/                       the SOC server (env soc)
  lab/                       the lab server (env lab)
  scorebox/                  the offline scoring image and grader (synced into bundles as scorebox_context)
  shared/                    trusted modules used by all three: codescreen, sigma_lite, sandboxrun, bootstrap, logexport
  data/                      incident.json, ground_truth.json (scorebox only), log_export.json, build_exports.py
  smoke/, lab-smoke/, scorebox-smoke/   model-free proofs
pipelines/
  v3-update/                 current: new telemetry, report revision and adaptation grading
  v2-artifacts/              current pipeline: triage, report, evidence analysis, code
  v1-triage/                 baseline pipeline
tests/                       pytest: the screen, the Sigma evaluator, the data, sync and host-inertness
runs/
  v2/<instance>/, v1/<instance>/   results, each with scorecard.md
```

Each folder has its own README: [soc-env](soc-env/README.md) for the tools, data format, traps and
registered ids; [v2](pipelines/v2-artifacts/README.md) and [v1](pipelines/v1-triage/README.md) for
the pipelines.

## Setup

You need macOS, [uv](https://docs.astral.sh/uv/), Docker with the Compose plugin (Rancher Desktop
or Colima both work) and access to the remote LiteLLM proxy.

1. **Python environment.** From this folder:

   ```bash
   uv sync
   ```

2. **Docker.** Start your Docker runtime and check Compose:

   ```bash
   docker compose version
   ```

3. **LiteLLM credentials.** Export your key in the server's shell, never in this repo:

   ```bash
   export LITELLM_API_KEY="..."
   export LITELLM_BASE_URL="https://litellm-proxy.ml-serving-internal.scale.com/v1"
   ```

   No SGP account or headers are needed. The proxy model aliases are `openai/gpt-5` (analyst)
   and `openai/gpt-6-sol` (judge). AEF adds one routing prefix, so pipeline configuration uses
   `openai/openai/gpt-5` and `openai/openai/gpt-6-sol`. Set `CYBER_ANALYST_MODEL` and
   `CYBER_JUDGE_MODEL` before rebuilding, or choose both in the dashboard. The updated agent is
   registered as v2; use `CYBER_AGENT_VERSION` if your local registry version differs.

4. **Check it.**

   ```bash
   uv run python model_smoke_test.py --list
   uv run python model_smoke_test.py openai/openai/gpt-5
   ```

## Run it

### Web dashboard

```bash
uv run python -m webapp.app
```

Open **http://127.0.0.1:8765** to launch runs, follow live progress/logs and review results.
Start with the model-free SOC smoke test. See [dashboard instructions](webapp/README.md).

The first time, register the world and the agent. The env images are built with `soc-env/` as the
Docker context so they can copy the shared trusted modules. The first deploy also builds agent-env's
gateway and service-database images, which takes a few minutes:

```bash
uv run agent-env env mcp-server put --id soc --dockerfile soc-env/soc/Dockerfile --context soc-env --platform linux/arm64
```

```bash
uv run agent-env env mcp-server put --id lab --dockerfile soc-env/lab/Dockerfile --context soc-env --platform linux/arm64
```

```bash
uv run agent-env artifact environment put --id soc-incident-sample --environment-name soc --description "INC-26-1107 (fictional)" soc-env/data/incident.json
```

```bash
uv run agent-env artifact environment-universe put --id soc-sample --environment-artifact soc-incident-sample
```

The lab is seeded with the same incident, registered for its own environment name:

```bash
uv run agent-env artifact environment put --id lab-incident-sample --environment-name lab --description "INC-26-1107 logs for the lab (fictional)" soc-env/data/incident.json
```

```bash
uv run agent-env artifact environment-universe put --id lab-sample --environment-artifact lab-incident-sample
```

```bash
uv run agent-env a2a-agent put --id sgp-agent --dockerfile agents/sgp-agent/Dockerfile --platform linux/arm64 --skip-validation
```

Check the world with the model-free smoke tests (the host-side unit tests are `uv run pytest`):

```bash
uv run agent-env run soc-env/smoke
```

```bash
uv run agent-env run soc-env/lab-smoke
```

```bash
uv run agent-env run soc-env/scorebox-smoke
```

The pipelines deploy the latest registered `soc` and `lab` and pin `sgp-agent` version 1. A dry run
checks a bundle against the store and reports any missing id or version without running anything:

```bash
uv run agent-env run --dry-run pipelines/v2-artifacts/soc-eval
```

Then run an eval and export it:

```bash
uv run agent-env run pipelines/v2-artifacts/soc-eval
```

```bash
uv run python pipelines/v2-artifacts/export_run.py "<instance id>"
```

## Known limits

### Action-backed grading

All model judges receive full tool-call trajectories and a trusted server-audit
summary captured before accepted submission. Required submissions must actually
persist; absent/rejected products force a zero aggregate. Failed reads and empty
queries do not count as investigation. Evidence requires complete page coverage.
v2/v3 and focused rules hand the lab snapshot to the scorebox: 20% of execution
reward requires a successful test of the exact submitted bytes before acceptance.
Each judge now scores verified actions and unsupported completion claims explicitly.
See [workflow and scenario audit](docs/action-evidence-workflow.md).

### Critical compromise grading

Policy `compromise-gates-v1` requires the submitted baseline report to identify all
three confirmed compromised hosts: WS-G3-014, SRV-FILE-01 and SRV-WEB-02. Missing
any host is a **critical failure: mission score 0.00**, regardless of judge grades
or other successful checks. Component scores remain diagnostic. The framework
enforces this through negative-weight gate rows in `facts` across v1, v2 and v3;
later revision credit cannot erase a baseline compromise miss.

`uv run python regrade_runs.py` adds a versioned mission grade to local exported
scorecards and writes `grading.json`, preserving historical verifier records and
stored scores. For example, GPT-4o run `soc_triage-wl9guskc` changes from its stored
0.55 to mission score **0.00** for missing confirmed compromised hosts.

- `build.py` deploys the latest `soc` and pins the agent version. Pin the env too (`SOC_VERSION`)
  once more than one pipeline depends on different server versions.
- The direct judge needs strict JSON-schema output, which SGP supports for `gpt-4o`; the analyst
  runs on `gpt-4o` too, so the judge scores carry a self-grading caveat.
- The code checks are keyword heuristics written for the sample incident. A different incident
  needs new patterns in `check_facts/verify.py`, `check_artifacts/verify.py` and `ground_truth.json`.
- The lab container has internet egress (the local sandbox provider offers no internal network), so
  its isolation is the static screen, the runtime import denier, the scrubbed environment and the
  absence of secrets. Authoritative execution happens only in the scorebox, which has no network.
- The framework's local provider ignores cpu and memory limits for env containers; the lab and the
  scorebox limit each run with rlimits inside the container instead.

## Next steps

- Run the first evals and hand-grade them to see how far the judge can be trusted.
- Extend v3's report revision to updated code artifacts and a synchronized lab/scoring dataset.
- Add a second, held-out incident to the scorebox to measure how far rules and hunt scripts generalize.
- Evidence beyond text: disk images and memory captures parsed by trusted tooling inside the scorebox.
- Move to repeated runs (pass@k) with `agent-env task run --k`.
