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
| `soc_list_injects` | updates issued mid-run (empty so far) |
| `soc_get_log_schema` (v3) | the data object analyst code receives, the artifact contract and the allowed imports |
| `soc_list_evidence`, `soc_get_evidence(evidence_id, offset, length)` (v3) | forensic evidence items as paged text; json items pretty-printed, hexdumps as rows |
| `soc_submit_triage(assessments)` | one assessment per alert: verdict, rationale, related hosts and alerts; once |
| `soc_submit_incident_report(...)` | summary, affected hosts, accounts, indicators, narrative, containment actions, escalation, evidence; once per version |
| `soc_submit_artifact(kind, name, content, notes)` (v3) | a `sigma_rule`, `hunt_script` or `ioc_extractor`; screened statically on submission and rejected with the problems; 8 accepted per run; returns a receipt, never the content |
| `soc_submit_evidence_report(...)` (v3) | items analyzed, verdict, summary, one finding per item, indicators, recommended actions; once |

Nothing submitted is executed by this server: it parses (`ast.parse`, `yaml.safe_load` through the shared
`codescreen` and `sigma_lite` modules), hashes and stores. The lab (`lab/`) runs scripts for the analyst
mid-task; the scorebox (`scorebox/`) runs them for the grade, offline.

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
  "playbook": {"containment_options": [], "rules": []},
  "evidence": [{"id", "kind": "text|json|hexdump", "title", "source_host", "collected_at", "content"}]
}
```

Every log record carries a stable `id` (`auth-001`, `dns-004`, ...). `data/build_exports.py` derives
`log_export.json` (the object analyst code receives, built by `shared/logexport.py`) and validates
`ground_truth.json`, the grading labels that ship only inside the scorebox image and are never loaded
into an environment.

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
| MCP server env (gateway provider, `environment_name=soc`) | `soc` | 3 |
| Its image | `soc__env_image` | 3 |
| Lab env (`environment_name=lab`) | `lab` | 2 |
| Environment artifact (incident.json, for soc) | `soc-incident-sample` (file `soc-incident-sample__file`) | 2 |
| Universe for soc | `soc-sample` | 2 |
| Environment artifact (the same file, for lab) | `lab-incident-sample` | 1 |
| Universe for lab | `lab-sample` | 1 |

Each `put` adds a version; the pipelines deploy the latest. soc v1's `soc_search_logs` ignored the host
filter (caught by the smoke test); v2 fixed it; v3 added the evidence and artifact tools. lab v1
misreported scripts killed by the cpu limit; v2 fixed it. A fresh machine's first `put` of each is
version 1 of the current server. Both images are built with `--context soc-env`.

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

v3 adds rows for the schema, evidence paging, artifact submission (a `socket`-importing script, an
unsupported Sigma modifier, a bad kind and a bad name refused; a good script and rule accepted; a
duplicate name refused) and the evidence report.

`lab-smoke/` proves the lab's boundary with the project's own samples: the banned script is refused
without running, a spinning script is killed at its limit, a memory bomb dies under the address-space
limit, a crashing script reports its error, the golden hunt script finds its records and the golden
rule matches; runs are recorded without code. `scorebox-smoke/` drives the full offline scoring chain
with golden fixtures standing in for the analyst and expects reward 1.0.

```bash
uv run agent-env run soc-env/lab-smoke
```

```bash
uv run agent-env run soc-env/scorebox-smoke
```
