"""Versioned mission-critical grading policy for current and historical results."""

POLICY_VERSION = "compromise-gates-v1"
CRITICAL_CHECKS = {
    "report-host-ws-g3-014": "Missed confirmed compromise of WS-G3-014",
    "report-host-srv-file-01": "Missed confirmed compromise of SRV-FILE-01",
    "report-host-srv-web-02": "Missed confirmed compromise of SRV-WEB-02",
}


def critical_failures(rows):
    """Missing checks fail closed; partial reports cannot establish mission success."""
    by_id = {row["id"]: row for row in rows}
    return [description for check, description in CRITICAL_CHECKS.items()
            if by_id.get(check, {}).get("result") is not True]


def assess(raw_score, rows):
    failures = critical_failures(rows)
    return {"policy": POLICY_VERSION, "score": 0.0 if failures else float(raw_score),
            "critical_failure": bool(failures), "failures": failures}


def summary(raw_score, rows):
    grade = assess(raw_score, rows)
    status = "CRITICAL FAILURE" if grade["critical_failure"] else "Critical compromise gates passed"
    lines = [f"**Mission score ({POLICY_VERSION}): {grade['score']:.2f} — {status}.**", ""]
    if grade["failures"]:
        lines += [f"- {failure}" for failure in grade["failures"]]
        lines += ["", "Missing any confirmed compromised host forces the mission score to zero. "
                  "Component scores below are diagnostic; historical stored scores are unchanged.", ""]
    return lines
