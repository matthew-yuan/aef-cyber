"""The soc env: a division cyber defense cell's operations desk, which an analyst works in.

It holds one incident's records: the situation (organization, mission, tasking), the asset
inventory, the alert queue, the log sources (auth, dns, proxy, endpoint), threat intelligence
bulletins, change records and the containment playbook. The read tools show these to the agent. Two
action tools take the agent's work: its triage of the alert queue and its incident report.
Nothing is preloaded: the data plane loads an incident.json (see ../README.md for its schema).
Grading is not done here: verifiers read the end state through data/get.

The picture can change mid-run. A data/add part with an "inject" block adds records without a
reset: its alerts, logs and intel are appended and the inject is recorded. The incident report
takes one submission per version (the initial queue, then each inject in turn), and every
submission is kept, so the original and the revision can be compared.
"""
import json
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

VERDICTS = ("true_positive", "false_positive", "needs_more_info")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _key(text: str) -> str:
    """Normalize a hostname, ip or id for lookup: case, spaces, dots and dashes don't matter."""
    return "".join(ch for ch in str(text).upper() if ch.isalnum())


@environment_card(name="soc")
class CyberDefenseCellEnv(AgentEnvEnvironment):
    """A cyber defense cell's desk: the alert queue, assets, logs, intel, change records and playbook for one incident."""

    def __init__(self) -> None:
        self._clear()

    def _clear(self) -> None:
        self.metadata: dict = {}
        self.organization: dict = {}
        self.assets: list[dict] = []
        self.asset_index: dict[str, dict] = {}
        self.alerts: list[dict] = []
        self.logs: dict[str, list[dict]] = {}
        self.intel: list[dict] = []
        self.change_records: list[dict] = []
        self.playbook: dict = {}
        self.triage: dict | None = None
        self.reports: list[dict] = []  # incident report, one per version, in order
        self.injects: list[dict] = []
        self.audit_log: list[dict] = []

    @property
    def report(self) -> dict | None:
        """The latest incident report."""
        return self.reports[-1] if self.reports else None

    def _current_version(self) -> str:
        return self.injects[-1]["id"] if self.injects else "INITIAL"

    def _log(self, tool: str, args: dict, outcome: str, **fields) -> None:
        role = ToolContext.current().role
        self.audit_log.append({"at": _now(), "role": role, "tool": tool, "args": args, "outcome": outcome, **fields})

    # ---- data plane -------------------------------------------------------------------------

    @reset_data
    async def _reset(self) -> None:
        self._clear()

    @add_data
    async def _add(self, parts: list) -> None:
        for part in parts:
            if isinstance(part, DataPart):
                data = part.data
            elif isinstance(part, FilePart):
                data = json.loads(Path(part.file.uri.removeprefix("file://")).read_text())
            else:
                continue
            self.metadata.update(data.get("metadata", {}))
            self.organization.update(data.get("organization", {}))
            for asset in data.get("assets", []):
                self._add_asset(asset)
            self.alerts.extend(data.get("alerts", []))
            for source, records in data.get("logs", {}).items():
                self.logs.setdefault(source, []).extend(records)
            self.intel.extend(data.get("intel", []))
            self.change_records.extend(data.get("change_records", []))
            self.playbook.update(data.get("playbook", {}))
            if "inject" in data:
                self._issue_inject(data["inject"])

    def _add_asset(self, asset: dict) -> None:
        self.assets.append(asset)
        for name in [asset["hostname"], asset.get("ip", ""), *asset.get("aliases", [])]:
            if name:
                self.asset_index[_key(name)] = asset

    def _issue_inject(self, inject: dict) -> None:
        """Record an inject (new alerts, logs or intel arrive with it in the same part)."""
        self.injects.append({**inject, "received_at": _now()})

    @get_data
    async def _state(self) -> list:
        return [DataPart(data={
            "incident_id": self.metadata.get("incident_id"),
            "triage": self.triage,
            "report": self.report,
            "reports": self.reports,
            "injects": self.injects,
            "audit_log": self.audit_log,
        })]

    # ---- read tools -------------------------------------------------------------------------

    @tool(name="{environment_name}_get_situation")
    async def get_situation(self) -> dict:
        """Read the situation: the incident id, the current time, your tasking, the organization, its mission, crown jewels, escalation rules and network ranges."""
        self._log("get_situation", {}, "ok")
        return {"metadata": self.metadata, "organization": self.organization}

    @tool(name="{environment_name}_list_alerts")
    async def list_alerts(self) -> dict:
        """List the alert queue: each alert's id, time, severity, title, host and status, oldest first."""
        self._log("list_alerts", {}, "ok")
        return {"alerts": [{k: a.get(k) for k in ("id", "time", "severity", "title", "host", "status")} for a in self.alerts]}

    @tool(name="{environment_name}_get_alert")
    async def get_alert(self, alert_id: str) -> dict:
        """Read one alert in full by its id, such as 'ALT-1002': its source, description, user and indicators."""
        found = next((a for a in self.alerts if _key(a["id"]) == _key(alert_id)), None)
        self._log("get_alert", {"alert_id": alert_id}, "ok" if found else "not_found")
        if found is None:
            return {"error": f"No alert {alert_id!r}. Alerts in the queue: {[a['id'] for a in self.alerts]}"}
        return found

    @tool(name="{environment_name}_list_assets")
    async def list_assets(self) -> dict:
        """List the asset inventory: each host's name, ip, role and criticality."""
        self._log("list_assets", {}, "ok")
        return {"assets": [{k: a.get(k) for k in ("hostname", "ip", "role", "criticality")} for a in self.assets]}

    @tool(name="{environment_name}_get_asset")
    async def get_asset(self, host: str) -> dict:
        """Read one asset's record by hostname or ip, such as 'WS-G3-014' or '192.0.2.14': owner, role, criticality, OS and notes."""
        found = self.asset_index.get(_key(host))
        self._log("get_asset", {"host": host}, "ok" if found else "not_found")
        if found is None:
            return {"error": f"No asset {host!r}. Hosts on record: {[a['hostname'] for a in self.assets]}"}
        return found

    @tool(name="{environment_name}_search_logs")
    async def search_logs(self, source: str, host: str = "", contains: str = "", limit: int = 50) -> dict:
        """Search one log source: 'auth', 'dns', 'proxy', 'endpoint', or 'all'. Optional filters: host (a hostname or ip,
        matched against the record's host and addresses) and contains (case-insensitive text anywhere in the record,
        such as a user, domain, process or path). Returns up to limit records, oldest first, and the total matched."""
        args = {"source": source, "host": host, "contains": contains, "limit": limit}
        sources = list(self.logs) if source.lower() == "all" else [source.lower()]
        unknown = [s for s in sources if s not in self.logs]
        if unknown:
            self._log("search_logs", args, "not_found")
            return {"error": f"No log source {source!r}. Sources: {sorted(self.logs)} or 'all'."}
        candidates = set()
        if host.strip():
            candidates.add(_key(host))
            asset = self.asset_index.get(_key(host))
            if asset:
                candidates.update({_key(asset["hostname"]), _key(asset.get("ip", ""))})
            candidates.discard("")
        needle = contains.strip().lower()
        matched = []
        for src in sources:
            for record in self.logs[src]:
                raw = json.dumps(record, ensure_ascii=False)
                if candidates and not any(c in _key(raw) for c in candidates):
                    continue
                if needle and needle not in raw.lower():
                    continue
                matched.append({"source": src, **record})
        matched.sort(key=lambda r: r.get("time", ""))
        limit = max(1, min(int(limit or 50), 200))
        self._log("search_logs", args, "ok", matched=len(matched))
        return {"source": source, "matched": len(matched), "returned": min(limit, len(matched)), "records": matched[:limit]}

    @tool(name="{environment_name}_list_intel")
    async def list_intel(self) -> dict:
        """List the threat intelligence bulletins on hand: id, time, title and source."""
        self._log("list_intel", {}, "ok")
        return {"intel": [{k: i.get(k) for k in ("id", "time", "title", "source")} for i in self.intel]}

    @tool(name="{environment_name}_get_intel")
    async def get_intel(self, intel_id: str) -> dict:
        """Read one intelligence bulletin in full by its id, such as 'INT-26-031': summary, indicators and recommended actions."""
        found = next((i for i in self.intel if _key(i["id"]) == _key(intel_id)), None)
        self._log("get_intel", {"intel_id": intel_id}, "ok" if found else "not_found")
        if found is None:
            return {"error": f"No bulletin {intel_id!r}. Bulletins: {[i['id'] for i in self.intel]}"}
        return found

    @tool(name="{environment_name}_list_change_records")
    async def list_change_records(self) -> dict:
        """List the change records: approved maintenance, scans and tests that explain expected activity, with their windows and status."""
        self._log("list_change_records", {}, "ok")
        return {"change_records": self.change_records}

    @tool(name="{environment_name}_get_playbook")
    async def get_playbook(self) -> dict:
        """Read the incident response playbook: the containment actions you may recommend and the rules that bind them."""
        self._log("get_playbook", {}, "ok")
        return self.playbook

    @tool(name="{environment_name}_list_injects")
    async def list_injects(self) -> dict:
        """List the updates issued since you started (new alerts, intel or orders), oldest first. Empty when nothing has changed."""
        self._log("list_injects", {}, "ok")
        return {"injects": [{k: v for k, v in i.items() if k != "received_at"} for i in self.injects]}

    # ---- action tools -----------------------------------------------------------------------

    @tool(name="{environment_name}_submit_triage")
    async def submit_triage(self, assessments: list[dict]) -> dict:
        """Submit your triage of the whole alert queue. You can submit once, so read what you need first.
        assessments: one object per alert in the queue: {"alert_id": "ALT-1001", "verdict": "true_positive" |
        "false_positive" | "needs_more_info", "rationale": "the evidence, with log entries, change records or
        intel cited", "related_hosts": ["..."], "related_alerts": ["..."]}. Every alert must be assessed."""
        args = {"assessments": assessments}
        if self.triage is not None:
            self._log("submit_triage", args, "rejected", reason="already_submitted")
            return {"error": f"Triage was already submitted at {self.triage['submitted_at']}; it cannot be changed."}
        known = {_key(a["id"]): a["id"] for a in self.alerts}
        problems = []
        seen = []
        for item in assessments or []:
            if not isinstance(item, dict):
                problems.append(f"not an object: {item!r}")
                continue
            aid = _key(item.get("alert_id", ""))
            if aid not in known:
                problems.append(f"unknown alert_id {item.get('alert_id')!r}")
            elif aid in seen:
                problems.append(f"{known[aid]} assessed twice")
            seen.append(aid)
            if item.get("verdict") not in VERDICTS:
                problems.append(f"{item.get('alert_id')}: verdict must be one of {list(VERDICTS)}")
            if not str(item.get("rationale") or "").strip():
                problems.append(f"{item.get('alert_id')}: rationale is empty")
        missing = [known[k] for k in known if k not in seen]
        if missing:
            problems.append(f"not assessed: {missing}")
        if problems:
            self._log("submit_triage", args, "rejected", reason="incomplete", problems=problems)
            return {"error": "Triage is incomplete; " + "; ".join(problems)}
        self.triage = {"assessments": assessments, "submitted_at": _now()}
        self._log("submit_triage", args, "accepted")
        return {"status": "submitted", "submitted_at": self.triage["submitted_at"], "assessed": len(assessments)}

    @tool(name="{environment_name}_submit_incident_report")
    async def submit_incident_report(
        self,
        summary: str,
        affected_hosts: list[str],
        compromised_accounts: list[str],
        indicators: list[str],
        attack_narrative: str,
        containment_actions: list[dict],
        escalation: str,
        evidence_preserved: list[str],
    ) -> dict:
        """Submit the incident report. You can submit once per version: once for the initial queue, and once more
        after each update to revise it. A submission can't be changed.
        summary: what happened, in a few sentences. affected_hosts: every compromised or beaconing host.
        compromised_accounts: every account the intruder used. indicators: domains, ips, files, task or service names.
        attack_narrative: the sequence of events with times, from first access to the latest activity.
        containment_actions: one object per action, {"action": a playbook option, "target": host, account or
        indicator, "rationale": "..."}. escalation: who is told, what, and by when. evidence_preserved: what is captured first."""
        args = {
            "summary": summary, "affected_hosts": affected_hosts, "compromised_accounts": compromised_accounts,
            "indicators": indicators, "attack_narrative": attack_narrative, "containment_actions": containment_actions,
            "escalation": escalation, "evidence_preserved": evidence_preserved,
        }
        version = self._current_version()
        done = next((r for r in self.reports if r["version"] == version), None)
        if done is not None:
            self._log("submit_incident_report", args, "rejected", reason="already_submitted", version=version)
            return {"error": f"The incident report for {version} was already submitted at {done['submitted_at']}; it cannot be changed."}
        empty = [name for name in ("summary", "attack_narrative", "escalation") if not str(args[name] or "").strip()]
        empty += [name for name in ("affected_hosts", "containment_actions") if not args[name]]
        bad_actions = [a for a in containment_actions or []
                       if not (isinstance(a, dict) and str(a.get("action") or "").strip() and str(a.get("target") or "").strip())]
        if empty or bad_actions:
            reason = f"empty: {empty}" if empty else f"each containment action needs an 'action' and a 'target'; bad: {bad_actions}"
            self._log("submit_incident_report", args, "rejected", reason=reason, version=version)
            return {"error": f"The incident report is incomplete; {reason}"}
        entry = {**args, "version": version, "submitted_at": _now()}
        self.reports.append(entry)
        self._log("submit_incident_report", args, "accepted", version=version)
        return {"status": "submitted", "version": version, "submitted_at": entry["submitted_at"]}


if __name__ == "__main__":
    CyberDefenseCellEnv().serve()
