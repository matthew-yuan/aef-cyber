"""run_tests: the authoritative grader for the analyst's code artifacts. Runs inside the scorebox container only.

    python3 -I /harness/run_tests.py --handoff /handoff --data /harness/data --out /work/out --work /work/runs

Reads the soc env's final snapshot from the hand-off directory (staged by load_artifact as
<handoff>/soc/<file>.json), writes each accepted artifact to a file, checks that this container is what it
must be (non-root, no network, no model credentials) and only then executes anything: hunt scripts and IOC
extractors through sandboxrun/bootstrap (a further child process under rlimits and a deadline), Sigma rules
through sigma_lite. Scores against ground_truth.json, which ships only in this image. Writes
<out>/results.json (every row with details) and <out>/reward.txt (the weighted fraction of rows passed).
Always exits 0: the reward is the verdict. If an isolation check fails, nothing is executed and the reward is 0.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import socket
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import codescreen  # noqa: E402
import sandboxrun  # noqa: E402
import sigma_lite  # noqa: E402
from logexport import SOURCES  # noqa: E402

WEIGHTS = {
    "sigma-valid": 0.05, "sigma-precision": 0.10, "sigma-recall": 0.10, "sigma-coverage": 0.10,
    "hunt-runs": 0.05, "hunt-schema": 0.05, "hunt-hosts": 0.10, "hunt-precision": 0.10, "hunt-recall": 0.10,
    "ioc-runs": 0.05, "ioc-required": 0.10, "ioc-no-forbidden": 0.10,
}
LLM_VARS = ("LITELLM_API_KEY", "ANTHROPIC_API_KEY", "LITELLM_BASE_URL", "ANTHROPIC_BASE_URL", "LITELLM_EXTRA_HEADERS")
EXT = {"sigma_rule": "yml", "hunt_script": "py", "ioc_extractor": "py"}
TIMEOUT_S = 30


def row(id_, ok, description, **details):
    return {"id": id_, "result": bool(ok), "weight": WEIGHTS.get(id_, 0.0), "description": description, **details}


# ---- inputs ------------------------------------------------------------------------------------

def load_state(handoff: str) -> tuple[dict, str | None]:
    """The soc env's data/get payload from the staged snapshot, whatever wrapper it was stored with."""
    for path in sorted(glob.glob(os.path.join(handoff, "soc", "*.json")) + glob.glob(os.path.join(handoff, "**", "*.json"), recursive=True)):
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and "parts" in data:
            data = next((p.get("data") for p in data["parts"] if isinstance(p, dict) and p.get("data")), None)
        elif isinstance(data, list):
            data = next((p.get("data") for p in data if isinstance(p, dict) and p.get("data")), None)
        if isinstance(data, dict) and "artifacts" in data:
            return data, path
    return {}, None


def lab_testing(state, lab, *, only_sigma=False):
    """Require a successful test of the exact submitted bytes BEFORE acceptance."""
    details = []
    for kind, items in (state.get("artifacts") or {}).items():
        if only_sigma and kind != "sigma_rule":
            continue
        for name, rec in items.items():
            digest = hashlib.sha256(rec.get("content", "").encode("utf-8", "surrogatepass")).hexdigest()
            submitted = rec.get("submitted_at", "")
            tests = lab.get("rule_tests", []) if kind == "sigma_rule" else lab.get("runs", [])
            matching = [test for test in tests if test.get("sha256") == digest and test.get("at")
                        and submitted and test["at"] <= submitted and
                        (test.get("valid") is True if kind == "sigma_rule" else
                         test.get("kind") == kind and test.get("executed") is True and test.get("outcome") == "ok"
                         and test.get("exit_code") == 0 and not test.get("timed_out"))]
            receipt = any(e.get("role") == "analyst" and e.get("tool") == "submit_artifact" and e.get("outcome") == "accepted"
                          and e.get("args", {}).get("kind") == kind and e.get("args", {}).get("name") == name
                          and e.get("args", {}).get("sha256") == digest for e in state.get("audit_log", []))
            details.append({"kind": kind, "name": name, "sha256": digest, "tested": bool(matching) and receipt})
    return bool(details) and all(d["tested"] for d in details), details


def load_lab(handoff):
    for path in sorted(Path(handoff).glob("lab/*.json")):
        data = json.loads(path.read_text())
        if isinstance(data, dict) and "parts" in data:
            data = next((p.get("data") for p in data["parts"] if p.get("data")), {})
        elif isinstance(data, list):
            data = next((p.get("data") for p in data if p.get("data")), {})
        if isinstance(data, dict) and "runs" in data and "rule_tests" in data:
            return data
    return {}


def write_artifacts(state: dict, out_dir: Path) -> dict[str, dict[str, Path]]:
    """Each accepted artifact as a file (bytes only; nothing here imports them)."""
    written: dict[str, dict[str, Path]] = {k: {} for k in EXT}
    for kind, items in (state.get("artifacts") or {}).items():
        if kind not in EXT or not isinstance(items, dict):
            continue
        for name, record in items.items():
            content = record.get("content") if isinstance(record, dict) else None
            if not isinstance(content, str) or not content.strip():
                continue
            safe = "".join(ch for ch in str(name) if ch.isalnum() or ch in "-_")[:40] or "artifact"
            path = out_dir / kind / f"{safe}.{EXT[kind]}"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            written[kind][str(name)] = path
    return written


# ---- isolation self-checks ---------------------------------------------------------------------

def sandbox_checks() -> list[dict]:
    checks = [row("sandbox-non-root", os.geteuid() != 0, f"grader runs as uid {os.geteuid()}")]
    reachable = []
    for target in (("203.0.113.1", 80), ("1.1.1.1", 53)):
        try:
            with socket.create_connection(target, timeout=2):
                reachable.append(target)
        except OSError:
            pass
    resolves = True
    try:
        socket.getaddrinfo("example.com", 443)
    except OSError:
        resolves = False
    checks.append(row("sandbox-no-network", not reachable and not resolves,
                      f"tcp connects succeeded to {reachable}; dns resolves: {resolves}"))
    leaked = [k for k in LLM_VARS if os.environ.get(k) not in (None, "", "{}")]
    checks.append(row("sandbox-no-secrets", not leaked, f"model credential variables present: {leaked}"))
    return checks


# ---- grading -----------------------------------------------------------------------------------

def grade_sigma(paths: dict[str, Path], export: dict, truth: dict) -> tuple[list[dict], dict]:
    rules, invalid = [], {}
    for name, path in paths.items():
        verdict = sigma_lite.validate(path.read_text(encoding="utf-8"))
        if verdict["valid"]:
            rules.append((name, sigma_lite.parse(path.read_text(encoding="utf-8"))))
        else:
            invalid[name] = verdict["errors"]
    scored = sigma_lite.score_rules([r for _, r in rules], export, truth) if rules else {"rules": [], "behaviors": {}, "behaviors_detected": 0, "behaviors_total": len(truth["behaviors"])}
    malicious = {rid for src in truth["malicious_records"].values() for rid in src}
    exempt = {rid for ids in truth["fp_exempt"].values() if isinstance(ids, list) for rid in ids}
    traps = {rid for ids in truth["must_not_match"].values() if isinstance(ids, list) for rid in ids}
    union = set()
    for _, rule in rules:
        union |= set(sigma_lite.evaluate(rule, export)["matched_ids"])
    tp, fp = union & malicious, union - malicious - exempt
    precision = len(tp) / len(tp | fp) if (tp | fp) else 0.0
    recall = len(tp) / len(malicious) if malicious else 0.0
    rows = [
        row("sigma-valid", bool(rules) and not invalid, f"{len(rules)} valid rule(s), {len(invalid)} invalid: {invalid}"),
        row("sigma-precision", bool(rules) and precision >= 0.9 and not (union & traps),
            f"union precision {precision:.2f} ({len(tp)} true, {len(fp)} false positives); trap hits {sorted(union & traps)}"),
        row("sigma-recall", recall >= 0.6, f"union recall {recall:.2f} ({len(tp)} of {len(malicious)} malicious records)"),
        row("sigma-coverage", scored["behaviors_detected"] >= 4,
            f"{scored['behaviors_detected']} of {scored['behaviors_total']} behaviors detected with precision >= 0.8 and recall >= 0.5"),
    ]
    return rows, {"rules": scored["rules"], "behaviors": scored.get("behaviors", {}), "invalid": invalid,
                  "union": {"precision": precision, "recall": recall, "fp_ids": sorted(fp)[:30]}}


def run_artifact(kind: str, path: Path, dataset: str, work: str) -> dict:
    code = path.read_text(encoding="utf-8")
    screen = codescreen.screen(code, kind)
    if not screen["ok"]:
        return {"screen_ok": False, "problems": screen["problems"], "executed": False}
    run = sandboxrun.run_untrusted(code=code, kind=kind, dataset_path=dataset, work_root=work,
                                   bootstrap_path=str(HERE / "bootstrap.py"), timeout_s=TIMEOUT_S, uid=None)
    ok = run["exit_code"] == 0 and not run["timed_out"] and bool(run["result"]) and run["result"].get("ok")
    return {"screen_ok": True, "executed": True, "ok": ok, "exit_code": run["exit_code"], "timed_out": run["timed_out"],
            "elapsed_ms": run["elapsed_ms"], "error": (run["result"] or {}).get("error") or run["result_error"],
            "stderr_tail": run["stderr_tail"][-500:], "value": (run["result"] or {}).get("result")}


def grade_hunts(paths: dict[str, Path], export: dict, truth: dict, dataset: str, work: str) -> tuple[list[dict], dict]:
    malicious = {rid for src in truth["malicious_records"].values() for rid in src}
    exempt = {rid for ids in truth["fp_exempt"].values() if isinstance(ids, list) for rid in ids}
    by_id = {r["id"]: r for s in SOURCES for r in export.get(s, [])}
    compromised = {h.upper() for h in truth["hosts"]["compromised"]}
    neutral = {h.upper() for h in truth["hosts"].get("neutral", [])}
    results, best = {}, None
    for name, path in paths.items():
        run = run_artifact("hunt_script", path, dataset, work)
        findings = run.get("value") or []
        ids = {f.get("id") for f in findings if isinstance(f, dict)}
        malformed = [f for f in findings if not isinstance(f, dict) or f.get("id") not in by_id
                     or f.get("source") != by_id.get(f.get("id"), {}).get("source") or not str(f.get("host") or "").strip()]
        tp, fp = ids & malicious, ids - malicious - exempt - {None}
        precision = len(tp) / len(tp | fp) if (tp | fp) else 0.0
        recall = len(tp) / len(malicious) if malicious else 0.0
        hosts = {str(f.get("host", "")).upper() for f in findings if isinstance(f, dict)}
        hosts_ok = compromised <= hosts and not (hosts - compromised - neutral)
        results[name] = {**{k: v for k, v in run.items() if k != "value"}, "findings": len(findings), "malformed": len(malformed),
                         "tp": len(tp), "fp": len(fp), "fp_ids": sorted(fp)[:30], "precision": precision, "recall": recall,
                         "hosts": sorted(hosts), "hosts_ok": hosts_ok}
        if best is None or (results[name]["ok"], precision + recall) > (results[best]["ok"], results[best]["precision"] + results[best]["recall"]):
            best = name
    b = results.get(best, {})
    rows = [
        row("hunt-runs", bool(b) and b.get("ok"), f"best script {best!r}: executed {b.get('executed')}, ok {b.get('ok')}, {b.get('elapsed_ms')} ms; error: {b.get('error')}"),
        row("hunt-schema", bool(b) and b.get("ok") and b.get("malformed") == 0 and b.get("findings", 0) > 0,
            f"{b.get('findings')} findings, {b.get('malformed')} malformed (unknown id, wrong source or no host)"),
        row("hunt-hosts", bool(b) and b.get("hosts_ok"), f"flagged hosts {b.get('hosts')}; compromised {sorted(compromised)}"),
        row("hunt-precision", bool(b) and b.get("precision", 0) >= 0.9, f"precision {b.get('precision', 0):.2f} (false positives: {b.get('fp_ids')})"),
        row("hunt-recall", bool(b) and b.get("recall", 0) >= 0.7, f"recall {b.get('recall', 0):.2f} ({b.get('tp')} of {len(malicious)})"),
    ]
    return rows, {"best": best, "scripts": results}


def grade_extractors(paths: dict[str, Path], export: dict, truth: dict, dataset: str, work: str) -> tuple[list[dict], dict]:
    iocs = truth["expected_iocs"]
    required = [i["value"].lower() for i in iocs["required"]]
    evidence_only = [i["value"].lower() for i in iocs["evidence_only"]]
    forbidden = [v.lower() for v in iocs["forbidden"]]
    results, best = {}, None
    for name, path in paths.items():
        run = run_artifact("ioc_extractor", path, dataset, work)
        indicators = (run.get("value") or {}).get("indicators", []) if isinstance(run.get("value"), dict) else []
        values = [str(i.get("value", "")).lower() for i in indicators if isinstance(i, dict)]
        hit = [r for r in required if any(r in v for v in values)]
        bad = [f for f in forbidden if any(f in v for v in values)]
        extra = [e for e in evidence_only if any(e in v for v in values)]
        results[name] = {**{k: v for k, v in run.items() if k != "value"}, "indicators": len(indicators), "required_hit": hit,
                         "required_missing": [r for r in required if r not in hit], "forbidden_hit": bad, "evidence_only_hit": extra}
        if best is None or (results[name]["ok"], len(hit) - len(bad)) > (results[best]["ok"], len(results[best]["required_hit"]) - len(results[best]["forbidden_hit"])):
            best = name
    b = results.get(best, {})
    rows = [
        row("ioc-runs", bool(b) and b.get("ok"), f"best extractor {best!r}: ok {b.get('ok')}, {b.get('indicators')} indicators; error: {b.get('error')}"),
        row("ioc-required", bool(b) and len(b.get("required_hit", [])) >= len(required) - 1,
            f"{len(b.get('required_hit', []))} of {len(required)} required indicators; missing {b.get('required_missing')}"),
        row("ioc-no-forbidden", bool(b) and b.get("ok") and not b.get("forbidden_hit"), f"forbidden values present: {b.get('forbidden_hit')}"),
    ]
    return rows, {"best": best, "extractors": results}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--handoff", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--require-lab", action="store_true")
    ap.add_argument("--only", choices=["sigma"], help="Grade only Sigma rules for the focused rules scenario")
    args = ap.parse_args()
    out, work = Path(args.out), Path(args.work)
    out.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    report: dict = {"rows": [], "sandbox": [], "reward": 0.0, "refused": None, "artifacts": {}, "details": {}}

    def finish() -> int:
        report["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        (out / "results.json").write_text(json.dumps(report, indent=2, default=str) + "\n")
        (out / "reward.txt").write_text(f"{report['reward']:.4f}\n")
        print(json.dumps({"reward": report["reward"], "refused": report["refused"],
                          "rows": {r["id"]: r["result"] for r in report["rows"]}, "sandbox": {r["id"]: r["result"] for r in report["sandbox"]}}))
        return 0

    report["sandbox"] = sandbox_checks()
    if not all(r["result"] for r in report["sandbox"]):
        report["refused"] = "isolation check failed; no artifact was executed"
        return finish()
    state, source = load_state(args.handoff)
    report["handoff_file"] = source
    if not state:
        report["refused"] = "no soc snapshot found under the hand-off directory"
        return finish()
    export = json.loads((Path(args.data) / "log_export.json").read_text())
    lab_ok, lab_details = lab_testing(state, load_lab(args.handoff), only_sigma=args.only == "sigma")
    report["lab_testing"] = {"passed": lab_ok, "artifacts": lab_details}
    truth = json.loads((Path(args.data) / "ground_truth.json").read_text())
    written = write_artifacts(state, work / "artifacts")
    report["artifacts"] = {k: sorted(v) for k, v in written.items()}
    dataset = str(Path(args.data) / "log_export.json")
    rows_s, det_s = grade_sigma(written["sigma_rule"], export, truth)
    if args.only == "sigma":
        report["rows"] = rows_s
        report["details"] = {"sigma": det_s}
        total = sum(r["weight"] for r in rows_s)
        report["reward"] = round(sum(r["weight"] for r in rows_s if r["result"]) / total, 4)
        if args.require_lab:
            report["reward"] = round(.8 * report["reward"] + .2 * lab_ok, 4)
        print(json.dumps({"lab_testing_passed": lab_ok, "tested": sum(d["tested"] for d in lab_details),
                          "submitted": len(lab_details), "untested": [d["name"] for d in lab_details if not d["tested"]]}))
        return finish()
    rows_h, det_h = grade_hunts(written["hunt_script"], export, truth, dataset, str(work / "runs"))
    rows_i, det_i = grade_extractors(written["ioc_extractor"], export, truth, dataset, str(work / "runs"))
    report["rows"] = rows_s + rows_h + rows_i
    report["details"] = {"sigma": det_s, "hunt": det_h, "ioc": det_i, "attempts": state.get("artifact_attempts", [])}
    report["reward"] = round(sum(r["weight"] for r in report["rows"] if r["result"]), 4)
    if args.require_lab:
        report["reward"] = round(.8 * report["reward"] + .2 * lab_ok, 4)
    print(json.dumps({"lab_testing_passed": lab_ok, "tested": sum(d["tested"] for d in lab_details),
                      "submitted": len(lab_details), "untested": [d["name"] for d in lab_details if not d["tested"]]}))
    return finish()


if __name__ == "__main__":
    sys.exit(main())
