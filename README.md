# aef-cyber: agent T&E for cyber defense with the AgentEnv Framework and SGP

This project evaluates an AI agent on a cyber defense staff task: triaging a security alert queue
and writing the incident report. It uses Scale's open-source
[AgentEnv Framework](https://www.agentenvframework.com/docs) (`agentenv-framework` 0.9.1335) and
models served by Scale GenAI Platform (SGP) on ScaleGov. Everything runs locally in Docker. It is
the cyber counterpart of [aef-toc-environment](https://github.com/cmullen-scale/aef-toc-environment),
and shares its layout, agent and config. **All scenario data is fictional and unclassified.**

## Which pipeline?

| Pipeline | Status | What it is | Run it |
| --- | --- | --- | --- |
| [v1-triage](pipelines/v1-triage/) | **Current** | The analyst triages the alert queue, then writes the incident report, in one conversation. Graded by the framework's own steps: code checks on the end state, a direct LLM judge per phase, one aggregate score, and a scorecard for human review. | `uv run agent-env run pipelines/v1-triage/soc-eval` |

The pipeline uses one world and one agent image:

- **The cyber defense cell** ([soc-env/](soc-env/)): an MCP server environment where an AI agent
  playing a division cyber defense analyst reads a fictional incident through tools (situation,
  alert queue, asset inventory, auth / DNS / proxy / endpoint logs, threat intelligence, change
  records, playbook) and submits its work.
- **`sgp-agent`** ([agents/sgp-agent/](agents/sgp-agent/)): one tool-using A2A agent that calls SGP
  models in OpenAI format. The pipeline deploys it with its role, prompts and model.

The incident has planted traps for the analyst to find:

- a high-severity port scan and a quarantined credential-dumping tool that are both authorized
  activity under change records
- a low-severity VPN logon that is the intrusion's foothold, with persistence and command and
  control visible only in the logs
- a credential attack on the plans file server that ends in the draft division order being
  exfiltrated
- a server recorded as decommissioned that is online and beaconing
- an unrelated phishing click that must not be merged into the intrusion

## Layout

```
.agentenv/config.toml        agent-env config: local stores and Docker sandboxes, SGP model endpoint
sgp_smoke_test.py            checks one SGP model call through agent-env's model config
agents/sgp-agent/            the shared agent (registered as sgp-agent)
soc-env/                     the world: SOC server (soc), fictional incident, smoke test
pipelines/
  v1-triage/                 current pipeline: triage, then incident report
runs/
  v1/<instance>/             v1 results, each with scorecard.md
```

Each folder has its own README: [soc-env](soc-env/README.md) for the tools, data format, traps and
registered ids; [v1](pipelines/v1-triage/README.md) for the pipeline.

## Setup

You need macOS, [uv](https://docs.astral.sh/uv/), Docker with the Compose plugin (Rancher Desktop
or Colima both work) and an SGP API key for a user who is a member of an SGP account.

1. **Python environment.** From this folder:

   ```bash
   uv sync
   ```

2. **Docker.** Start your Docker runtime and check Compose:

   ```bash
   docker compose version
   ```

3. **SGP credentials.** Export them in `~/.zshenv` (readable only by you, never in this repo).
   The account ID is the *account's* ID, and your user must be a member of that account:

   ```
   export SGP_API_KEY="..."
   export SGP_ACCOUNT_ID="..."
   ```

   `.agentenv/config.toml` points at `https://sgp-api.scalegov.com/v5` and sends both values as
   the `x-api-key` and `x-selected-account-id` headers. Model names take an extra `openai/` prefix
   for LiteLLM, e.g. `openai/openai/gpt-4o`.

4. **Check it.** List the account's models, then send one test call:

   ```bash
   uv run python sgp_smoke_test.py --list
   ```

   ```bash
   uv run python sgp_smoke_test.py openai/openai/gpt-4o
   ```

## Run it

The first time, register the world and the agent. The first deploy also builds agent-env's gateway
and service-database images, which takes a few minutes:

```bash
uv run agent-env env mcp-server put --id soc --dockerfile soc-env/soc/Dockerfile --platform linux/arm64
```

```bash
uv run agent-env artifact environment put --id soc-incident-sample --environment-name soc --description "INC-26-1107 (fictional)" soc-env/data/incident.json
```

```bash
uv run agent-env artifact environment-universe put --id soc-sample --environment-artifact soc-incident-sample
```

```bash
uv run agent-env a2a-agent put --id sgp-agent --dockerfile agents/sgp-agent/Dockerfile --platform linux/arm64 --skip-validation
```

Check the world with the model-free smoke test:

```bash
uv run agent-env run soc-env/smoke
```

The pipeline deploys the latest registered `soc` and pins `sgp-agent` version 1. A dry run checks
the bundle against the store and reports any missing id or version without running anything:

```bash
uv run agent-env run --dry-run pipelines/v1-triage/soc-eval
```

Then run an eval and export it:

```bash
uv run agent-env run pipelines/v1-triage/soc-eval
```

```bash
uv run python pipelines/v1-triage/export_run.py "<instance id>"
```

## Known limits

- `build.py` deploys the latest `soc` and pins the agent version. Pin the env too (`SOC_VERSION`)
  once more than one pipeline depends on different server versions.
- The direct judge needs strict JSON-schema output, which SGP supports for `gpt-4o`; the analyst
  runs on `gpt-4o` too, so the judge scores carry a self-grading caveat.
- The code checks are keyword heuristics written for the sample incident. A different incident
  needs new patterns in `check_facts/verify.py`.

## Next steps

- Run the first evals and hand-grade them to see how far the judge can be trusted.
- Add a v2 with a mid-task inject through the env's `data/add` (a new alert or bulletin after the
  report), as aef-toc-environment's v3 does with its FRAGO, and grade the revision.
- Move to repeated runs (pass@k) with `agent-env task run --k`.
