# soc-env: a cyber defense cell environment

`soc-env/` is the world the pipeline runs in: an MCP server environment (`soc/`) that holds one
security incident's records, the sample incident (`data/incident.json`) and a model-free smoke test
(`smoke/`). An agent playing a division cyber defense analyst reads the records through tools and
submits its triage and its incident report. **All data is fictional and unclassified.** Addresses
come from the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and domains end
in `.example`.

## Tools

Tool names carry the environment name as a prefix (`soc_`).

| Tool | What it returns |
| --- | --- |
| `soc_get_situation` | incident id, current time, tasking, organization, mission, crown jewels, escalation rules, network ranges |
| `soc_list_alerts`, `soc_get_alert(alert_id)` | the alert queue, and one alert in full |
| `soc_list_assets`, `soc_get_asset(host)` | the asset inventory, and one asset by hostname or ip |
| `soc_search_logs(source, host, contains, limit)` | records from `auth`, `dns`, `proxy`, `endpoint` or `all`, filtered by host and text |
| `soc_list_intel`, `soc_get_intel(intel_id)` | the threat intelligence bulletins, and one in full |
| `soc_list_change_records` | approved maintenance, scans and tests that explain expected activity |
| `soc_get_playbook` | the containment options the analyst may recommend, and the rules that bind them |
| `soc_list_injects` | updates issued mid-run (empty in v1) |
| `soc_submit_triage(assessments)` | one assessment per alert: verdict, rationale, related hosts and alerts; once |
| `soc_submit_incident_report(...)` | summary, affected hosts, accounts, indicators, narrative, containment actions, escalation, evidence; once per version |

Every call is written to a role-tagged audit log, which verifiers read with the submissions through
`data/get`.

## incident.json schema

```json
{
  "schema_version": "1.0",
  "metadata": {"incident_id", "exercise", "network", "current_time", "shift", "tasking"},
  "organization": {"name", "mission", "crown_jewels": [], "escalation": {}, "network_ranges": {}},
  "assets": [{"hostname", "ip", "role", "owner", "criticality", "os", "notes"}],
  "alerts": [{"id", "time", "source", "severity", "title", "host", "user", "status", "description", "indicators": []}],
  "logs": {"auth": [...], "dns": [...], "proxy": [...], "endpoint": [...]},
  "intel": [{"id", "time", "title", "source", "summary", "indicators": [{"type", "value", "context"}], "recommended_actions": []}],
  "change_records": [{"id", "title", "system", "window_start", "window_end", "approved_by", "status"}],
  "playbook": {"containment_options": [], "rules": []}
}
```

Log records are free-form objects with a `time` and a `host`; `soc_search_logs` matches the host
filter against every field, so `src` and `dest_ip` addresses match too. A `data/add` part with an
`"inject"` object (`id`, `title`, `text`) appends its alerts, logs and intel without a reset and
opens a new report version, the way aef-toc-environment's FRAGO does.

After editing or swapping the data, put a new version and point the universe at it:

```bash
uv run agent-env artifact environment put --id soc-incident-sample --environment-name soc --description "..." soc-env/data/incident.json
```

```bash
uv run agent-env artifact environment-universe put --id soc-sample --environment-artifact soc-incident-sample
```

## Answer key: the planted traps in the sample incident

See [pipelines/v1-triage/answer_key.md](../pipelines/v1-triage/answer_key.md). In short: ALT-1001
and ALT-1005 are authorized activity under CHG-0412 and CHG-0415; ALT-1002, ALT-1003 and ALT-1006
are one intrusion (VPN foothold on WS-G3-014, credential attack and exfiltration of the PLANS share
from SRV-FILE-01, lateral movement to the decommissioned SRV-WEB-02); ALT-1004 is an unrelated
phishing click with no follow-on.

## Registered ids

| What | Id | Version |
| --- | --- | --- |
| MCP server env (gateway provider, `environment_name=soc`) | `soc` | 2 |
| Its image | `soc__env_image` | 2 |
| Environment artifact (incident.json) | `soc-incident-sample` (file `soc-incident-sample__file`) | 1 |
| Universe | `soc-sample` | 1 |

Each `put` adds a version; the pipeline deploys the latest. Version 1's `soc_search_logs` ignored the
host filter (caught by the smoke test); version 2 fixes it. A fresh machine's first `put` is version 1
of the fixed server.

```bash
uv run agent-env env mcp-server put --id soc --dockerfile soc-env/soc/Dockerfile --platform linux/arm64
```

## Smoke test

`smoke/tasks/smoke.json` runs three steps: `deploy_env` soc, then `load_artifact` soc-sample, then
`env_outcome_verifier` with `smoke/artifacts/check_soc/verify.py`. The verifier checks behaviour,
not the incident's content, so it still passes after you swap the data. It calls every read tool,
checks that unknown alerts, assets, bulletins and log sources are refused, submits a triage (an
empty, a partial and an invalid one refused, then one accepted, then a second refused) and a report
(an incomplete one refused, one accepted, a second refused), and reads `data/get` to confirm the
stored submissions and the audit log.

```bash
uv run agent-env run soc-env/smoke
```
