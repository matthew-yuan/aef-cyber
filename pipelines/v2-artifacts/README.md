# v2: evidence analysis and detection/response code, verified without host execution (current)

v2 is [v1](../v1-triage/) plus two phases and an execution boundary. The analyst works two environments
in one conversation: the cyber defense cell (`soc-env/soc`, env `soc` v3 or later) and a lab bench
(`soc-env/lab`, env `lab`).

1. **Triage** and 2. **Incident report**: as in v1, byte-identical prompts.
3. **Evidence analysis.** Seven read-only evidence items (a decoded PowerShell cradle, a scheduled-task
   export, two triage packages, a hex dump with strings, the phishing email, an implant configuration
   recovered from memory) through `soc_list_evidence` / `soc_get_evidence`. The analyst submits a
   structured evidence report. Some indicators exist only here (a fallback C2 domain, a mutex, a PDB
   path, a user agent, the beacon interval).
4. **Detection and response code.** Sigma rules, a hunt script defining `hunt(data)` and an IOC
   extractor defining `extract(data)`, submitted with `soc_submit_artifact`. Each submission is
   screened statically (imports allow-list, no files, network, processes or reflection, required
   entry function; Sigma parsed by our subset evaluator) and rejected with the problems if it fails.
   The analyst can run scripts and test rules in the lab first.

## Where analyst code runs, and where it never does

| Place | Runs analyst code? | How |
| --- | --- | --- |
| The host (runner process, verifiers, `build.py`, `export_run.py`) | **Never.** | Host-side files only `ast.parse`, `yaml.safe_load`, hash and regex-match it. `tests/test_host_inert.py` scans them for `exec`, `eval`, `compile`, `importlib`, `subprocess`. |
| The `soc` container | Never. | Parses, hashes and stores artifacts; returns receipts, not echoes. |
| The agent container | Never. | It holds the model credentials and has internet egress. |
| The `lab` container | Yes, interactively. | After the screen, in a child process as uid `runner` with rlimits (cpu, address space, processes, file size, open files), a scrubbed environment, dead proxies, closed stdin, a deadline and a runtime import denier (`soc-env/shared/bootstrap.py`). The lab holds no secrets and no ground truth. It sits on a Docker bridge, so its network defenses are the screen, the denier and the scrubbed environment. |
| The `scorebox` container | Yes, for the grade. | Started by `run_docker_container` with `network: none`; the grader runs as `runner` with every model variable blanked, refuses to execute anything if it finds itself root, networked or holding credentials, then runs the same child-process recipe and scores against `ground_truth.json`, which ships only in this image. |

The final `soc` snapshot reaches the scorebox through the framework (`snapshot_env` then
`load_artifact` with `artifact_from_step_id`, a `docker cp`): no host script touches the code.
`export_run.py` writes artifacts with a `.txt` suffix and a banner under `runs/v2/<instance>/artifacts/`.

## Grading

Seven verifiers, each totalling 1.0, so the aggregate is their mean:

| Step | Type | What it does |
| --- | --- | --- |
| `facts` | `env_outcome_verifier` | v1's 31 code checks on triage and report (generated from v1 by `build.py` with the total weight set to 1.0) |
| `artifact-checks` | `env_outcome_verifier` | 18 parse-only checks ([check_artifacts/verify.py](soc-eval/artifacts/check_artifacts/verify.py)): an artifact of each kind accepted, receipts intact, everything still parses, rejections bounded, the evidence report states each item's facts and keeps the legitimate run key legitimate, the contract was read before coding and every item before reporting |
| `exec-tests` | `run_container_unit_tests_verifier` | The scorebox grader ([soc-env/scorebox/harness/run_tests.py](../../soc-env/scorebox/harness/run_tests.py)): Sigma validity, precision, recall and behavior coverage; hunt script runs, schema, hosts, precision, recall; extractor runs, required indicators, no forbidden ones. Weighted rows, reward = weighted fraction passed |
| `judge-triage`, `judge-report` | `rubrics_verifier` | As in v1 |
| `judge-evidence` | `rubrics_verifier` | Accuracy, evidence-only indicators and contradictions, judgment (legitimate vs malicious, the distractor, actions) |
| `judge-artifacts` | `rubrics_verifier` | Detection logic, hunt method (including the lab test-and-fix loop), IOC fidelity |
| `score` | `aggregate_verifiers` | The mean |

Snapshots: `snap-triage`, `snap-report`, `snap-evidence`, `snap-final` (soc) and `snap-lab` (the lab's
run history), all as versioned artifacts.

**Models.** The analyst and the four judges run on `gpt-4o`; the scorecard flags the self-grading
caveat on the judge scores. The code checks and the scorebox are model-free.

## Files

```
pipelines/v2-artifacts/
  prompts/                 analyst_system (v1 plus the code contract), triage_user, report_user (v1), evidence_user, artifacts_user
  rubrics.json             the four rubrics; build.py divides each rubric's weights to total 1.0
  answer_key.md            v1's facts plus the evidence facts and what good code looks like
  build.py                 writes soc-eval/tasks/soc_artifacts.json; regenerates check_facts from v1; syncs the scorebox context
  export_run.py            unpacks one run into runs/v2/<instance>/ (scorecard, submissions, quarantined artifacts, lab history)
  soc-eval/
    artifacts/check_facts/        generated from v1 (do not edit here)
    artifacts/check_artifacts/    the v2 host-side checks
    artifacts/scorebox_context/   synced copy of soc-env/scorebox/ (do not edit here)
    tasks/soc_artifacts.json      25 steps
```

Sources of truth that this bundle copies: `pipelines/v1-triage/soc-eval/artifacts/check_facts/verify.py`,
`soc-env/scorebox/`, `soc-env/shared/` and `soc-env/data/`. After changing any of them, or a prompt or
rubric, rebuild:

```bash
uv run python pipelines/v2-artifacts/build.py
```

`tests/test_sync.py` and `tests/test_v2.py` fail when a copy or the task JSON is stale.

## Run it

Needs `soc` (v3 or later), `lab`, `soc-sample` and `lab-sample` registered (see the
[top-level README](../../README.md)). Check the bundle against the store, then run one eval and export it:

```bash
uv run agent-env run --dry-run pipelines/v2-artifacts/soc-eval
```

```bash
uv run agent-env run pipelines/v2-artifacts/soc-eval
```

```bash
uv run python pipelines/v2-artifacts/export_run.py "<instance id>"
```

Model-free proofs of the boundary, each a bundle under `soc-env/`: `smoke` (soc v3 tools, including
the screen refusing a `socket` import), `lab-smoke` (banned script refused, spinning script killed,
memory bomb dies, crash reported, golden script finds its records) and `scorebox-smoke` (the full
chain with golden fixtures standing in for the analyst; expects reward 1.0).

## Findings so far

None yet: no model run. All three smoke bundles pass and the dry run resolves every reference.
