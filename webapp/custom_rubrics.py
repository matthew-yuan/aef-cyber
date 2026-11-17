"""Untrusted JSON selects trusted observable checks, never instructions or infrastructure."""
import hashlib
import json


from pydantic import BaseModel, ConfigDict, Field
from typing import Literal

from webapp.store import ROOT
from webapp.reporting import deterministic_checks

MAX_BYTES = 16384


class Check(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9-]+$")
    weight: float = Field(ge=.1, le=10, allow_inf_nan=False)


class Rubric(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version: Literal[1]
    scenario: Literal["triage", "report"]
    title: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ()_.,-]*$")
    checks: list[Check] = Field(min_length=2, max_length=20)


def catalog(root=None):
    root = root or ROOT
    checks = deterministic_checks(root / "pipelines/v1-triage/soc-eval/artifacts/check_facts/verify.py")
    return {scenario: [{"id": key, "description": description} for key, description in checks
                       if key.startswith(prefixes)] for scenario, prefixes in
            (("triage", ("triage-", "process-")), ("report", ("report-", "contain-")))}


def validate_upload(raw, root=None):
    if len(raw) > MAX_BYTES:
        raise ValueError("Rubric exceeds 16 KB")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON keys are not allowed")
            result[key] = value
        return result
    try:
        data = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda x: (_ for _ in ()).throw(ValueError("Nonfinite JSON number")))
        rubric = Rubric.model_validate(data)
        if type(data.get("version")) is not int:
            raise ValueError("Integer version required")
    except (ValueError, RecursionError, UnicodeError):
        raise ValueError("Invalid rubric JSON/schema: use the downloaded template and approved check IDs") from None
    ids = [check.id for check in rubric.checks]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate rubric check IDs")
    allowed = {c["id"] for c in catalog(root)[rubric.scenario]}
    if not set(ids) <= allowed:
        raise ValueError("Checks must belong to the selected cyber scenario; see approved check catalog")
    if not any(i.startswith("triage-" if rubric.scenario == "triage" else "report-") for i in ids):
        raise ValueError("Include at least one scenario outcome check, not only process/containment")
    normalized = rubric.model_dump()
    normalized["sha256"] = hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()
    return normalized


def apply_rubric(bundle, rubric, *, root=None):
    """Modify only our trusted task copy. Uploaded strings are never Python source."""
    raw = {key: value for key, value in rubric.items() if key != "sha256"}
    validated = validate_upload(json.dumps(raw).encode(), root=root)
    if validated != rubric:
        raise ValueError("Rubric integrity check failed")
    artifact = bundle / "artifacts/check_custom"
    artifact.mkdir(parents=True, exist_ok=True)
    source = (bundle / "artifacts/check_facts/verify.py").read_text()
    # Focused generated file wraps baseline_score; append another trusted wrapper.
    wrapper = '''
def score(state):
    weights = CUSTOM_WEIGHTS
    rows = baseline_score(state)
    chosen = [dict(r, weight=weights[r['id']]) for r in rows if r['id'] in weights]
    total = sum(weights.values())
    for row in chosen:
        row['weight'] /= total
    chosen += [r for r in rows if (r.get('action_gate') and r['id'].startswith(CUSTOM_PREFIX))
               or (CUSTOM_PREFIX == 'report-' and r.get('critical'))]
    return chosen
'''
    weights = {c["id"]: c["weight"] for c in rubric["checks"]}
    # Only canonical allowlisted IDs/numbers become literals; no uploaded code/text.
    source += "\nCUSTOM_WEIGHTS = " + json.dumps(weights) + "\nCUSTOM_PREFIX = " + json.dumps(rubric["scenario"] + "-") + "\n" + wrapper
    (artifact / "verify.py").write_text(source)
    for path in (bundle / "tasks").glob("*.json"):
        steps = json.loads(path.read_text())
        if [s.get("prompt_id") for s in steps if s["type"] == "prompt_agent"] != [rubric["scenario"]]:
            raise ValueError("Rubric can only extend the matching focused scenario")
        score = steps.pop()
        phase = rubric["scenario"]
        steps.append({"id": "custom-rubric", "type": "env_outcome_verifier", "env_id": "soc",
                      "file_artifact_id": "check_custom", "verifier_id": "custom-rubric", "score_aggregator": "weighted_average",
                      "depends_on": [{"task_step_id": phase}]})
        # Supplemental: preserve original aggregate, required actions and judge policy.
        score["depends_on"].append({"task_step_id": "custom-rubric"})
        steps.append(score)
        path.write_text(json.dumps(steps, indent=2) + "\n")
    (bundle / "custom_rubric.json").write_text(json.dumps(rubric, indent=2))
