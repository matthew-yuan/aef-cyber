"""Readable focused results; analyst code stays quarantined text."""
import json
from pathlib import Path

from webapp.store import ROOT
from webapp.reporting import scorecard, product


def export_focused(kind, instance_id, context):
    import subprocess
    # Use the established CLI snapshot export contract; never execute submitted artifacts.
    out = ROOT / "runs" / kind / instance_id.rsplit("/", 1)[-1]
    out.mkdir(parents=True, exist_ok=True)
    verifications = context.get("metadata", {}).get("verifications", {})
    (out / "verifications.json").write_text(json.dumps(verifications, indent=2))
    (out / "scorecard.md").write_text(scorecard(f"{kind.title()} evaluation", verifications))
    snapshot = context.get("metadata", {}).get("env_snapshotted_universes", {}).get("snap-final")
    if snapshot:
        subprocess.run(["agent-env", "artifact", "environment-universe", "get", "--id", snapshot["id"],
                        "--version", str(snapshot["version"]), "--output-dir", str(out / "snapshot")], check=True, capture_output=True, timeout=60)
        state = json.loads(next((out / "snapshot/soc").glob("*.json")).read_text())
        if isinstance(state, dict) and "parts" in state:
            state = next(p["data"] for p in state["parts"] if p.get("data"))
        elif isinstance(state, list):
            state = next(p["data"] for p in state if p.get("data"))
        submission = state.get("triage" if kind == "triage" else "report")
        if submission:
            (out / f"{kind}.md").write_text(product(kind, submission))
        for name, artifact in state.get("artifacts", {}).get("sigma_rule", {}).items():
            safe = "".join(c for c in name if c.isalnum() or c in "-_")
            (out / f"rule-{safe}.yml.txt").write_text(artifact["content"])
        if kind == "rules":
            (out / "rules.md").write_text("# Generated rules\n\n" + "\n\n".join(
                f"## {name}\n\n```yaml\n{a['content']}\n```" for name, a in state.get("artifacts", {}).get("sigma_rule", {}).items()))
    return str(out.relative_to(ROOT))
