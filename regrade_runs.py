"""Apply the current compromise gates to exports without changing historical records.

    uv run python regrade_runs.py
"""
import json
from pathlib import Path

from grading import assess, summary

ROOT = Path(__file__).resolve().parent
MARKER = "<!-- mission-grade -->"
END_MARKER = "<!-- /mission-grade -->"


def regrade(folder):
    verifications = json.loads((folder / "verifications.json").read_text())
    score_id = next(key for key in ("soc-v3", "soc-v2", "soc-v1") if key in verifications)
    raw = verifications[score_id]["score"]
    rows = verifications.get("facts", {}).get("results", [])
    grade = {**assess(raw, rows), "historical_score": raw, "verifier_id": score_id}
    (folder / "grading.json").write_text(json.dumps(grade, indent=2) + "\n")
    path = folder / "scorecard.md"
    text = path.read_text()
    if text.startswith(MARKER):
        text = text.split(END_MARKER, 1)[1].lstrip("\n")
    header = "\n".join([MARKER, *summary(raw, rows),
                        f"Historical stored overall: {raw:.2f}. Regraded without rerunning models.", END_MARKER])
    path.write_text(header + "\n\n" + text)
    return grade


def main():
    for path in sorted((ROOT / "runs").glob("v*/*/verifications.json")):
        grade = regrade(path.parent)
        print(f"{path.parent.name}: {grade['historical_score']:.2f} → {grade['score']:.2f}"
              + (" CRITICAL FAILURE" if grade["critical_failure"] else ""))


if __name__ == "__main__":
    main()
