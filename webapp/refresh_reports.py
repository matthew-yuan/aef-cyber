"""Refresh Markdown presentations from saved evidence, without rerunning models or changing scores."""
import json
from webapp.store import ROOT, STATE, PIPELINES, save
from webapp.reporting import scorecard, product, write_rubric


def main():
    for pipeline, config in PIPELINES.items():
        reference = ROOT / config["bundle"] / "rubric.md"
        write_rubric(pipeline, reference.parent)
    count = 0
    for path in STATE.glob("*/run.json"):
        record = json.loads(path.read_text())
        if record.get("pipeline") not in PIPELINES or record.get("status") != "completed":
            continue
        result_path = path.parent / "results.json"
        if not result_path.exists():
            continue
        results = json.loads(result_path.read_text())
        if not results:
            continue
        result = results[0]
        if not record.get("export_path"):
            record["export_path"] = f"runs/{record['pipeline']}/{result['instance_id'].rsplit('/', 1)[-1]}"
        out = ROOT / record["export_path"]
        out.mkdir(parents=True, exist_ok=True)
        write_rubric(record["pipeline"], out)
        verifications = result["context"].get("metadata", {}).get("verifications", {})
        (out / "grading_details.md").write_text(scorecard("Detailed grading evidence", verifications))
        # Keep full mission scorecards, which already contain current-policy gates and regression traces.
        if record["pipeline"] in ("rules", "triage", "report", "smoke"):
            (out / "scorecard.md").write_text(scorecard(record["name"], verifications))
            snapshots = list((out / "snapshot/soc").glob("*.json"))
            if snapshots:
                state = json.loads(snapshots[0].read_text())
                if isinstance(state, list):
                    state = next(p["data"] for p in state if p.get("data"))
                elif "parts" in state:
                    state = next(p["data"] for p in state["parts"] if p.get("data"))
                for kind in ("triage", "report"):
                    if record["pipeline"] == kind:
                        (out / f"{kind}.md").write_text(product(kind, state.get(kind)))
        save(path.parent, record)
        count += 1
    print(f"Wrote seven scenario rubrics and updated {count} saved runs")


if __name__ == "__main__":
    main()
