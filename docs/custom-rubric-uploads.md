# Bounded rubric uploads (v1)

## Scope

This feature customizes **grading for an existing focused triage/report scenario**.
It does not upload an arbitrary new world, agent prompt, judge policy, executable
verifier, Docker definition, file archive or dataset. This deliberate first-version
boundary prevents an upload from requesting new compute or changing trusted
execution permissions. The current Python-artifact sandbox has known isolation
findings; uploads cannot select rules/code scenarios or add execution tools.

Use **Upload a rubric (JSON)** on the Run scenario page. Download a template or
start with `examples/triage-rubric.json`. Available check IDs and descriptions are
at `/api/rubrics/catalog`. Choose 2–20 distinct checks and positive weights from
0.1 to 10. At least one check must assess a scenario outcome, not only process.
The scenario must be `triage` or `report`; mismatched checks are refused.

Example:

```json
{
  "version": 1,
  "scenario": "triage",
  "title": "Intrusion triage rubric",
  "checks": [
    {"id": "triage-1001-fp", "weight": 1},
    {"id": "triage-1002-tp", "weight": 2}
  ]
}
```

## Execution and integrity

```mermaid
flowchart TD
  U[JSON upload <=16 KB] --> V[Strict schema and approved check IDs]
  V --> H[Canonical SHA-256 and bounded local storage]
  H --> R[Revalidate content hash at launch]
  R --> B[Fresh focused triage/report trial bundle]
  B --> A[Unchanged analyst task and tools]
  A --> T[Unchanged trusted facts, action gates and LLM judge]
  A --> C[Supplemental deterministic custom rubric]
  T --> O[Reports: trusted score and custom score separately]
  C --> O
```

The uploaded title is display-only. Uploaded values never enter model prompts or
judge criteria. Only allowlisted check IDs and bounded numeric weights enter a
trusted generated verifier. File paths/commands cannot be uploaded. A custom
rubric cannot remove accepted-submission gates. Custom report grading also keeps
the three confirmed-compromise gates. Its score cannot compensate for the trusted
scenario's failure: reliability success requires **both** scores to meet the
threshold. Original trusted aggregate remains unchanged.

Custom runs are limited to the matching focused scenario and at most three
trials, 20 analyst model-loop turns, 600 seconds per analyst phase, and 120 seconds
per judge call (AEF's finite retry policy still applies). Infrastructure is fixed
at one SOC plus one analyst; no uploaded field changes it. These are time/turn
limits, not a monetary budget or complete rate limit. The endpoint streams at
most 16 KB into its buffer and stores at most 100 distinct rubric files.

The upload is revalidated before execution and applied only to a private trial
bundle. Exports include `custom_rubric.md`, JSON/hash, the supplemental score,
trusted score, action receipts and normal reports. Inputs identifies the rubric
as grader-only data, not agent-visible instructions.

## Validation and attack model

Schema validation rejects extra fields, code, prompts, environment variables,
model overrides, deployment requests, negative/unbounded/nonfinite weights,
duplicate JSON keys/checks, unknown/out-of-scope checks, invalid Unicode titles,
deep malformed JSON and oversized files. It does not try to make a natural-language
"jailbreak detector" a security boundary. For example, an instruction-like title
can be accepted as inert display text, but tests verify it cannot change a task,
judge prompt, tool list or scoring gate.

Adversarial test cases include runaway/million-node requests, fake system/judge
instructions, URLs pointing to honeypots/metadata services, Python payloads,
path traversal, malformed JSON and persisted-file tampering. Test payloads use
nonresolving example domains; no attacker endpoint is contacted.

Live judge controls in `scripts/check_rogue_judge.py` put jailbreak, honeypot and
runaway instructions inside tool-returned evidence and agent narrative. Each
must score zero when accepted submission evidence is absent. These finite tests
are evidence about the tested model and prompts, **not proof that arbitrary
prompt injection is solved**. The judge has no tool loop; application deployment
and retry counts are not controlled by model text. Existing deterministic
submission/compromise gates remain the authority for mission-critical outcomes.

## Research basis

- [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/):
  untrusted text may manipulate model behavior; instruction filtering alone is
  insufficient. Here, uploads have no route into model/judge instructions.
- [OWASP LLM10:2025 Unbounded Consumption](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/):
  enforce input size, timeouts and resource/usage limits outside model reasoning.
- [InjecAgent](https://aclanthology.org/2024.findings-acl.624/): test indirect
  instructions in tool outputs as well as direct uploads.

The web server is localhost-only and inherits the user's model credentials
server-side. It is not a multi-tenant public upload service. Broader uploads need
separate authorization/quotas and stronger external sandbox isolation first.

## Observed verification — 2026-11-16

- Full regression: **151 pytest tests passed in 1.86 s**, including **41 upload
  and adversarial validation tests**. History-filter JavaScript tests, upload/
  launcher syntax checks and diff whitespace checks also passed.
- Live upload/validate/run/export trial completed in **121.53 s wall time**
  (**116.01 s AEF trial time**), GPT-5 analyst / GPT-6-Sol judge. Trusted facts,
  judge, focused aggregate and uploaded supplemental rubric all scored **1.00**.
  Export contains rubric JSON/hash, readable rubric, verifier evidence and report.
  Local batch: `e6650de9ed93480aa00c531741f37f1d`.
- Live jailbreak, honeypot-URL and runaway/million-node judge controls each scored
  **0.00** for unsupported successful-action claims. Three finite controls took
  approximately **13 s**; no attacker URL was contacted and no tools were supplied
  to the judge. This is not an exhaustive proof against injection.
- Real lab smoke passed at **1.00**, **27.9 s** AEF runtime: banned network code
  refused, infinite loop terminated, memory exhaustion contained, crash/shape
  failures reported, and golden scripts/rules succeeded. One sandbox torn down.
  Instance: `lab_smoke-78m6qpkq`. Known general-purpose sandbox gaps remain; this
  feature does not expose that execution path to uploaded data.
- Chrome desktop/mobile checks passed: template download, real upload validation,
  invalid upload blocking, scenario matching, 3-trial limit and custom-launch
  request. No JavaScript exceptions or horizontal mobile overflow observed.
  Launch was intercepted for the browser test; real model execution was verified
  separately above.
