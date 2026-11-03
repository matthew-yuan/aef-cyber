"""Build the derived data files from incident.json and ground_truth.json, and validate them.

    uv run python soc-env/data/build_exports.py

Writes soc-env/data/log_export.json: `{"incident_id", "sources": [...], "auth": [...], "dns": [...], "proxy": [...],
"endpoint": [...]}`, every record carrying its `id` and a `source` field. This is the exact object the
analyst's `hunt(data)` and `extract(data)` receive, and the object Sigma rules are evaluated against.
Checks that every record id is unique and that every id ground_truth.json names exists.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "shared"))
from logexport import SOURCES, build_export  # noqa: E402


def validate(incident: dict, truth: dict) -> list[str]:
    problems = []
    ids = {source: [r.get("id") for r in incident["logs"].get(source, [])] for source in SOURCES}
    for source, lst in ids.items():
        if any(i is None for i in lst):
            problems.append(f"{source}: a record has no id")
        if len(set(lst)) != len(lst):
            problems.append(f"{source}: duplicate ids")
    known = {i for lst in ids.values() for i in lst}
    for section in ("malicious_records", "fp_exempt", "must_not_match"):
        for source, body in truth.get(section, {}).items():
            if source == "note":
                continue
            for rid in (body if isinstance(body, list) else body.keys()):
                if rid not in known:
                    problems.append(f"{section}.{source}: unknown record id {rid}")
    malicious = {rid for body in truth["malicious_records"].values() for rid in body}
    for tag, rids in truth.get("behaviors", {}).items():
        for rid in rids:
            if rid not in malicious:
                problems.append(f"behaviors.{tag}: {rid} is not in malicious_records")
    evidence_ids = {e["id"] for e in incident.get("evidence", [])}
    for ev in truth.get("evidence_facts", {}):
        if ev not in evidence_ids:
            problems.append(f"evidence_facts: no evidence item {ev}")
    return problems


def main() -> int:
    incident = json.loads((HERE / "incident.json").read_text())
    truth = json.loads((HERE / "ground_truth.json").read_text())
    problems = validate(incident, truth)
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    export = build_export(incident)
    out = HERE / "log_export.json"
    out.write_text(json.dumps(export, indent=1, ensure_ascii=False) + "\n")
    counts = {s: len(export[s]) for s in SOURCES}
    malicious = sum(len(v) for v in truth["malicious_records"].values())
    print(f"wrote {out.relative_to(HERE.parent.parent)}: {counts}; {malicious} malicious records in {len(truth['behaviors'])} behaviors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
