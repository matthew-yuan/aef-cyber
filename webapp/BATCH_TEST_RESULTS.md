# Batch execution verification — 2026-11-16

Runtime: local Docker, 2 CPUs / 4 GB; GPT-5 analyst and GPT-6-Sol judge
through the configured LiteLLM proxy. No inference credentials are recorded here.

| Test | Trials | Concurrency | Wall time | Outcome |
| --- | ---: | ---: | ---: | --- |
| Functionality check, serial | 2 | 1 | 65.80 s | 2/2 successful; all three verifier scores 1.00 |
| Functionality check, parallel | 2 | 2 | 39.17 s | 2/2 successful |
| Functionality check, final per-trial namespaces | 2 | 2 | 40.05 s | 2/2 successful; unique bundles and snapshots |
| Triage + report, each repeated twice | 4 | 2 | 399.26 s | 4/4 completed; scores 1.00, 1.00, 1.00, 0.932 |
| Triage + report, final isolation retest | 2 | 2 | 289.97 s | 2/2 successful at threshold 0.80 |

The final parallel infrastructure test was **1.64× faster** than serial (39.1%
less wall time). The four-model-trial batch consumed 714.98 seconds of summed
AEF trial time over 399.26 seconds of batch wall time. That shows overlap, not
a controlled serial-model speedup: model latency varies and no matched serial
model comparison was performed.

All six model trials completed and met threshold 0.80. At k=2, 2/2 successes
still has a wide 95% Wilson interval (34.2%–100%); it does not establish high
population reliability. Focused report grading currently excludes full-pipeline
critical gates; this existing limitation also applies to these results.

Regression: **92 pytest tests passed** in 1.65 seconds, including batch bounds,
classification, snapshot namespaces, immutable inputs, scheduling bounds and
failure handling. JavaScript syntax and diff whitespace checks passed.

Chrome interaction test: selected two scenarios, k=2 and concurrency=2; verified
the submitted API payload, preserved selections, no JavaScript exceptions and
no horizontal overflow at mobile width 390 px. The submit request was mocked
in this browser test; real execution was exercised separately as above.

Detailed local manifests are under `.dashboard/batches/` (intentionally ignored).
Infrastructure batch IDs: `976eff82d30548518d1f856b7eb3ae8b`,
`9d6bb1ee2fd94e79bcab2efad2af2160`, `6bd427e9c8f446608757c3882c6642c9`.
Model batch IDs: `ae6bf19cbb28496bbde5537c03dbb998`,
`2fb22e7d18184f94b247870883cfb0e8`.
