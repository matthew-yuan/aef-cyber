"""The lab env: a scratch bench where the analyst can run its hunt scripts and test its Sigma rules mid-task.

It holds the same incident logs as the soc env (seeded through load_artifact / data/add, never ground truth) and
offers: the data contract, the static screen, `lab_run_script` (screen first, then execute in a demoted, resource-
limited, scrubbed child process via the shared sandboxrun/bootstrap pair) and `lab_test_rule` (our sigma_lite
evaluator; the analyst's YAML is parsed, never executed). Every run is summarized in the audit log and in
data/get (sha256, outcome, counts), never the code itself. The lab has no secrets and no ground truth; the scoring
container, not the lab, decides the grade.
"""
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from agentenv_protocol import (
    AgentEnvEnvironment,
    DataPart,
    FilePart,
    add_data,
    ToolContext,
    environment_card,
    get_data,
    reset_data,
    tool,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import codescreen
    import sigma_lite
    import sandboxrun
    from logexport import SOURCES, build_export
except ImportError:  # running from the source tree
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "shared"))
    import codescreen
    import sigma_lite
    import sandboxrun
    from logexport import SOURCES, build_export

DATASETS_DIR = Path("/lab/datasets")
RUNS_DIR = Path("/lab/runs")
BOOTSTRAP = str(Path(__file__).resolve().parent / "bootstrap.py")
RUNNER_UID = 10002
BUDGET = 25             # runs plus rule tests per task
DEFAULT_TIMEOUT_S = 20
MAX_TIMEOUT_S = 30
SAMPLE = 5


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@environment_card(name="lab")
class AnalystLabEnv(AgentEnvEnvironment):
    """A sandboxed bench for the analyst's own hunt scripts, IOC extractors and Sigma rules."""

    def __init__(self) -> None:
        self._clear()

    def _clear(self) -> None:
        self.incident_id: str | None = None
        self.export: dict | None = None
        self.datasets: dict[str, str] = {}  # name -> path on disk
        self.runs: list[dict] = []
        self.rule_tests: list[dict] = []
        self.audit_log: list[dict] = []

    def _log(self, tool: str, args: dict, outcome: str, **fields) -> None:
        role = ToolContext.current().role
        self.audit_log.append({"at": _now(), "role": role, "tool": tool, "args": args, "outcome": outcome, **fields})

    def _used(self) -> int:
        return len(self.runs) + len(self.rule_tests)

    # ---- data plane -------------------------------------------------------------------------

    @reset_data
    async def _reset(self) -> None:
        self._clear()
        for path in DATASETS_DIR.glob("*.json") if DATASETS_DIR.exists() else []:
            path.unlink()

    @add_data
    async def _add(self, parts: list) -> None:
        for part in parts:
            if isinstance(part, DataPart):
                data = part.data
            elif isinstance(part, FilePart):
                data = json.loads(Path(part.file.uri.removeprefix("file://")).read_text())
            else:
                continue
            if "logs" not in data:
                continue
            self.incident_id = data.get("metadata", {}).get("incident_id", self.incident_id)
            self.export = build_export(data)
            DATASETS_DIR.mkdir(parents=True, exist_ok=True)
            path = DATASETS_DIR / "logs.json"
            path.write_text(json.dumps(self.export))
            path.chmod(0o644)
            self.datasets = {"logs": str(path)}

    @get_data
    async def _state(self) -> list:
        return [DataPart(data={
            "incident_id": self.incident_id,
            "datasets": sorted(self.datasets),
            "runs": self.runs,
            "rule_tests": self.rule_tests,
            "budget": {"used": self._used(), "limit": BUDGET},
            "audit_log": self.audit_log,
        })]

    # ---- read tools -------------------------------------------------------------------------

    @tool(name="{environment_name}_list_datasets")
    async def list_datasets(self) -> dict:
        """List the datasets a script can run against (currently 'logs': the incident's auth, dns, proxy and endpoint
        records) with record counts, and how much of your run budget is left."""
        self._log("list_datasets", {}, "ok")
        counts = {s: len(self.export.get(s, [])) for s in SOURCES} if self.export else {}
        return {"datasets": [{"name": n, "records": counts} for n in sorted(self.datasets)],
                "budget": {"used": self._used(), "limit": BUDGET}}

    @tool(name="{environment_name}_describe_dataset")
    async def describe_dataset(self, name: str = "logs") -> dict:
        """Describe a dataset: the exact object your hunt(data) / extract(data) receives (fields and an example record per
        source), the artifact contract and the Python modules a script may import."""
        self._log("describe_dataset", {"name": name}, "ok" if name in self.datasets else "not_found")
        if name not in self.datasets or not self.export:
            return {"error": f"No dataset {name!r}. Datasets: {sorted(self.datasets)}"}
        sources = {s: {"records": len(self.export[s]), "fields": list(dict.fromkeys(k for r in self.export[s] for k in r)),
                       "example": self.export[s][0] if self.export[s] else None} for s in SOURCES}
        return {"name": name, "top_level_keys": list(self.export), "sources": sources, "contract": codescreen.CONTRACT}

    @tool(name="{environment_name}_screen")
    async def screen(self, kind: str, code: str) -> dict:
        """Run the static screen on a script without executing it: kind is 'hunt_script' or 'ioc_extractor'. Returns the
        problems the screen would reject it for (imports outside the allow-list, file or network access, reflection,
        top-level side effects, a missing or wrong entry function)."""
        result = codescreen.screen(code or "", kind)
        self._log("screen", {"kind": kind, "sha256": result["sha256"], "bytes": result["bytes"]}, "ok" if result["ok"] else "problems",
                  problems=len(result["problems"]))
        return {"ok": result["ok"], "problems": result["problems"], "entry": result["entry"], "imports": result["imports"],
                "functions": result["functions"], "sha256": result["sha256"]}

    @tool(name="{environment_name}_history")
    async def history(self) -> dict:
        """Your runs and rule tests so far, newest last: outcome, counts and timing (never the code)."""
        self._log("history", {}, "ok")
        return {"runs": self.runs, "rule_tests": self.rule_tests, "budget": {"used": self._used(), "limit": BUDGET}}

    # ---- action tools -----------------------------------------------------------------------

    @tool(name="{environment_name}_run_script")
    async def run_script(self, kind: str, code: str, dataset: str = "logs", timeout_s: int = DEFAULT_TIMEOUT_S) -> dict:
        """Screen a script and, if it passes, run it against a dataset in an isolated child process (no network, no
        files, resource limits, a time limit of at most 30 seconds). kind: 'hunt_script' calls hunt(data) and
        summarizes the findings; 'ioc_extractor' calls extract(data) and summarizes the indicators. Returns the exit
        status, the tails of stdout and stderr, and the summary. Each call uses one unit of your budget."""
        code = code or ""
        digest = hashlib.sha256(code.encode("utf-8", "surrogatepass")).hexdigest()
        args = {"kind": kind, "dataset": dataset, "timeout_s": timeout_s, "sha256": digest, "bytes": len(code)}
        if self._used() >= BUDGET:
            self._log("run_script", args, "rejected", reason="budget")
            return {"error": f"The lab budget of {BUDGET} runs and rule tests is used up."}
        if dataset not in self.datasets:
            self._log("run_script", args, "rejected", reason="no_dataset")
            return {"error": f"No dataset {dataset!r}. Datasets: {sorted(self.datasets)}"}
        screen = codescreen.screen(code, kind)
        entry = {"run_id": None, "kind": kind, "dataset": dataset, "sha256": digest, "bytes": len(code),
                 "first_line": code.strip().splitlines()[0][:80] if code.strip() else "", "screen_ok": screen["ok"],
                 "executed": False, "exit_code": None, "timed_out": False, "elapsed_ms": 0, "at": _now()}
        if not screen["ok"]:
            self.runs.append({**entry, "outcome": "screen_failed", "problems": len(screen["problems"])})
            self._log("run_script", args, "screen_failed", problems=screen["problems"])
            return {"executed": False, "screen": {"ok": False, "problems": screen["problems"]},
                    "hint": "fix the problems and run again; lab_describe_dataset shows the contract and the allowed imports"}
        timeout_s = max(1, min(int(timeout_s or DEFAULT_TIMEOUT_S), MAX_TIMEOUT_S))
        run = sandboxrun.run_untrusted(code=code, kind=kind, dataset_path=self.datasets[dataset], work_root=str(RUNS_DIR),
                                       bootstrap_path=BOOTSTRAP, timeout_s=timeout_s, uid=RUNNER_UID, gid=RUNNER_UID)
        summary = self._summarize(kind, run)
        outcome = "timed_out" if run["timed_out"] else ("ok" if run["exit_code"] == 0 and run["result"] and run["result"].get("ok") else "error")
        entry.update(run_id=run["run_id"], executed=True, exit_code=run["exit_code"], timed_out=run["timed_out"],
                     elapsed_ms=run["elapsed_ms"], outcome=outcome, summary={k: v for k, v in summary.items() if k != "sample"})
        self.runs.append(entry)
        self._log("run_script", args, outcome, run_id=run["run_id"], elapsed_ms=run["elapsed_ms"])
        return {"run_id": run["run_id"], "executed": True, "outcome": outcome, "exit_code": run["exit_code"], "timed_out": run["timed_out"],
                "elapsed_ms": run["elapsed_ms"], "error": (run["result"] or {}).get("error") or run["result_error"],
                "traceback_tail": (run["result"] or {}).get("traceback_tail"), "stdout_tail": run["stdout_tail"],
                "stderr_tail": run["stderr_tail"], "screen": {"ok": True, "imports": screen["imports"]}, "summary": summary,
                "budget": {"used": self._used(), "limit": BUDGET}}

    def _summarize(self, kind: str, run: dict) -> dict:
        result = run.get("result") or {}
        value = result.get("result")
        if value is None:
            return {}
        known = {r["id"] for s in SOURCES for r in (self.export or {}).get(s, [])}
        if kind == "hunt_script":
            ids = [f.get("id") for f in value]
            bad = [f for f in value if not isinstance(f.get("id"), str) or f.get("id") not in known or not f.get("source")]
            return {"findings": len(value), "unique_records": len(set(ids)), "unknown_or_malformed": len(bad),
                    "by_behavior": dict(Counter(str(f.get("behavior")) for f in value).most_common(20)),
                    "by_host": dict(Counter(str(f.get("host")) for f in value).most_common(20)),
                    "record_ids": sorted({i for i in ids if isinstance(i, str)})[:200], "sample": value[:SAMPLE],
                    "truncated": result.get("truncated", False)}
        indicators = value.get("indicators", [])
        bad = [i for i in indicators if not str(i.get("value") or "").strip() or not i.get("type")]
        return {"indicators": len(indicators), "malformed": len(bad),
                "by_type": dict(Counter(str(i.get("type")) for i in indicators).most_common(20)),
                "values": sorted({str(i.get("value")) for i in indicators})[:100], "sample": indicators[:SAMPLE * 2],
                "truncated": result.get("truncated", False)}

    @tool(name="{environment_name}_test_rule")
    async def test_rule(self, rule_yaml: str, dataset: str = "logs") -> dict:
        """Validate a Sigma rule and evaluate it against a dataset with the lab's own evaluator (your YAML is parsed,
        never executed). Returns the match count per source and a sample of matched record ids and records, so you can
        see what the rule catches. No labels are available here: judge the matches yourself. One budget unit."""
        text = rule_yaml or ""
        digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
        args = {"dataset": dataset, "sha256": digest, "bytes": len(text)}
        if self._used() >= BUDGET:
            self._log("test_rule", args, "rejected", reason="budget")
            return {"error": f"The lab budget of {BUDGET} runs and rule tests is used up."}
        if dataset not in self.datasets or not self.export:
            self._log("test_rule", args, "rejected", reason="no_dataset")
            return {"error": f"No dataset {dataset!r}. Datasets: {sorted(self.datasets)}"}
        verdict = sigma_lite.validate(text)
        if not verdict["valid"]:
            self.rule_tests.append({"sha256": digest, "title": None, "valid": False, "errors": verdict["errors"], "at": _now()})
            self._log("test_rule", args, "invalid", errors=verdict["errors"])
            return {"valid": False, "errors": verdict["errors"]}
        rule = sigma_lite.parse(text)
        matches = sigma_lite.evaluate(rule, self.export)
        by_id = {r["id"]: r for s in SOURCES for r in self.export[s]}
        sample_ids = matches["matched_ids"][:10]
        self.rule_tests.append({"sha256": digest, "title": rule.title, "valid": True, "source": rule.source, "matched": matches["count"],
                                "by_source": matches["by_source"], "at": _now()})
        self._log("test_rule", args, "ok", matched=matches["count"])
        return {"valid": True, "title": rule.title, "source": rule.source, "warnings": rule.warnings, "matched": matches["count"],
                "by_source": matches["by_source"], "sample_ids": sample_ids, "sample_records": [by_id[i] for i in sample_ids[:3] if i in by_id],
                "budget": {"used": self._used(), "limit": BUDGET}}


if __name__ == "__main__":
    AnalystLabEnv().serve()
