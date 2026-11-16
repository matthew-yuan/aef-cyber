"""sigma_lite: a small, trusted evaluator for a documented subset of Sigma detection rules.

Rules are YAML written by the analyst; this module parses them with yaml.safe_load and evaluates them
against the incident's log records with our own code. No analyst code ever runs, and no regular
expressions are accepted (the `re` modifier is refused), so a rule can be evaluated anywhere.

Supported subset
  title (required), id, status, description, author, references, tags, level, falsepositives
  logsource: service: auth | dns | proxy | endpoint, or category mapped by CATEGORY_MAP
  detection: named selections; a selection is a dict (AND of its fields), a list of dicts (OR), or a
             list of strings (keywords: any field contains any of them); a field's value may be a scalar
             or a list (OR, or AND with the `all` modifier); `*` and `?` wildcards; `null` matches absent
  modifiers: contains, startswith, endswith, all, cidr, gt, gte, lt, lte
  condition: identifiers, not, and, or, parentheses, `1 of sel*`, `all of sel*`, `1 of them`, `all of them`
Refused: aggregations (`| count() ...`), `near`, `timeframe` (warned and ignored), regex and encoding
modifiers, multi-document files, more than 20 selections or 200 field terms.
"""
from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field

import yaml

MAX_BYTES = 32 * 1024
MAX_SELECTIONS = 20
MAX_TERMS = 200
SOURCES = ("auth", "dns", "proxy", "endpoint")
CATEGORY_MAP = {
    "authentication": "auth", "logon": "auth", "vpn": "auth",
    "dns_query": "dns", "dns": "dns",
    "proxy": "proxy", "proxy_web": "proxy", "web_proxy": "proxy", "webserver": "proxy", "firewall": "proxy",
    "process_creation": "endpoint", "file_event": "endpoint", "service_installation": "endpoint",
    "service_creation": "endpoint", "scheduled_task": "endpoint", "registry_event": "endpoint", "antivirus": "endpoint",
    "endpoint": "endpoint",
}
FIELD_ALIASES = {
    "image": "process", "parentimage": "parent", "commandline": "command_line", "targetfilename": "path",
    "queryname": "query", "query": "query", "destinationip": "dest_ip", "dst_ip": "dest_ip", "c-uri": "url", "cs-uri": "url",
    "uri": "url", "targetusername": "user", "subjectusername": "user", "username": "user", "ipaddress": "src", "sourceip": "src",
    "src_ip": "src", "computer": "host", "computername": "host", "hostname": "host", "eventtype": "event", "logontype": "logon_type",
    "status": "result", "cs-method": "method", "cs-bytes": "bytes_out", "sc-bytes": "bytes_in", "sc-status": "status",
    "answer": "answer", "dstip": "dest_ip",
}
MODIFIERS = frozenset({"contains", "startswith", "endswith", "all", "cidr", "gt", "gte", "lt", "lte"})
KNOWN_KEYS = frozenset({"title", "id", "status", "description", "author", "references", "tags", "level", "falsepositives",
                        "logsource", "detection", "date", "modified", "related", "fields", "name", "license"})


class RuleError(ValueError):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


@dataclass
class Term:
    field: str | None  # None = keyword search over the whole record
    values: list
    modifiers: tuple[str, ...]


@dataclass
class Selection:
    name: str
    alternatives: list[list[Term]]  # OR of (AND of terms)


@dataclass
class Rule:
    title: str
    rule_id: str | None
    level: str | None
    tags: list[str]
    source: str | None  # None = every source
    selections: dict[str, Selection]
    condition: tuple
    warnings: list[str] = field(default_factory=list)
    sha256: str = ""


# ---- parsing -------------------------------------------------------------------------------------

def _resolve_field(name: str) -> str:
    return FIELD_ALIASES.get(name.lower(), name.lower())


def _terms(selection_name: str, mapping: dict, problems: list[str], counter: list[int]) -> list[Term]:
    terms = []
    for raw_key, raw_value in mapping.items():
        counter[0] += 1
        parts = str(raw_key).split("|")
        field_name, mods = parts[0].strip(), tuple(m.strip().lower() for m in parts[1:])
        bad = [m for m in mods if m not in MODIFIERS]
        if bad:
            problems.append(f"{selection_name}.{raw_key}: unsupported modifier(s) {bad}; supported: {sorted(MODIFIERS)}")
            continue
        if sum(m in ("contains", "startswith", "endswith", "cidr", "gt", "gte", "lt", "lte") for m in mods) > 1:
            problems.append(f"{selection_name}.{raw_key}: combine at most one matching modifier with 'all'")
            continue
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        if any(isinstance(v, (dict, list)) for v in values):
            problems.append(f"{selection_name}.{raw_key}: values must be scalars or a list of scalars")
            continue
        terms.append(Term(_resolve_field(field_name), list(values), mods))
    return terms


def _selection(name: str, body, problems: list[str], counter: list[int]) -> Selection | None:
    if isinstance(body, dict):
        return Selection(name, [_terms(name, body, problems, counter)])
    if isinstance(body, list):
        if body and all(isinstance(x, dict) for x in body):
            return Selection(name, [_terms(name, x, problems, counter) for x in body])
        if body and all(isinstance(x, (str, int, float)) for x in body):
            counter[0] += len(body)
            return Selection(name, [[Term(None, [str(x) for x in body], ())]])
        problems.append(f"{name}: a selection list must hold only maps or only keywords")
        return None
    problems.append(f"{name}: a selection must be a map or a list")
    return None


_TOKEN = re.compile(r"\s*(?:(\()|(\))|(and|or|not)\b|(1|all)\s+of\s+(them|[A-Za-z0-9_]+\*?)|([A-Za-z0-9_]+)|(\S))")


def _tokenize(text: str, problems: list[str]) -> list[tuple[str, str]]:
    tokens, pos = [], 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            break
        pos = m.end()
        if m.group(1):
            tokens.append(("(", "("))
        elif m.group(2):
            tokens.append((")", ")"))
        elif m.group(3):
            tokens.append(("op", m.group(3)))
        elif m.group(4):
            tokens.append(("quant", f"{m.group(4)} of {m.group(5)}"))
        elif m.group(6):
            tokens.append(("id", m.group(6)))
        elif m.group(7):
            problems.append(f"condition: unexpected character {m.group(7)!r}")
            return []
    return tokens


def _parse_condition(text: str, names: list[str], problems: list[str]) -> tuple:
    if "|" in text:
        problems.append("condition: aggregations (`| count() ...`) are not supported")
        return ()
    if re.search(r"\bnear\b", text):
        problems.append("condition: `near` is not supported")
        return ()
    tokens = _tokenize(text, problems)
    if problems:
        return ()
    pos = [0]

    def peek():
        return tokens[pos[0]] if pos[0] < len(tokens) else (None, None)

    def take():
        tok = tokens[pos[0]]
        pos[0] += 1
        return tok

    def expr():
        node = term()
        while peek() == ("op", "or"):
            take()
            node = ("or", node, term())
        return node

    def term():
        node = factor()
        while peek() == ("op", "and"):
            take()
            node = ("and", node, factor())
        return node

    def factor():
        kind, value = peek()
        if kind is None:
            problems.append("condition: unexpected end")
            return ()
        if (kind, value) == ("op", "not"):
            take()
            return ("not", factor())
        if kind == "(":
            take()
            node = expr()
            if peek() != (")", ")"):
                problems.append("condition: missing ')'")
                return ()
            take()
            return node
        if kind == "quant":
            take()
            quant, pattern = value.split(" of ")
            matched = names if pattern == "them" else [n for n in names if fnmatch.fnmatchcase(n, pattern)]
            if not matched:
                problems.append(f"condition: `{value}` matches no selection")
                return ()
            return ("all" if quant == "all" else "any", tuple(("sel", n) for n in matched))
        if kind == "id":
            take()
            if value not in names:
                problems.append(f"condition: unknown selection {value!r}; defined: {names}")
                return ()
            return ("sel", value)
        problems.append(f"condition: unexpected token {value!r}")
        take()
        return ()

    node = expr()
    if not problems and pos[0] != len(tokens):
        problems.append(f"condition: trailing tokens after position {pos[0]}")
    return () if problems else node


def parse(text: str) -> Rule:
    """Parse one rule. Raises RuleError with every problem found."""
    problems: list[str] = []
    data = text.encode("utf-8", "surrogatepass")
    if len(data) > MAX_BYTES:
        raise RuleError([f"rule is {len(data)} bytes; the limit is {MAX_BYTES}"])
    try:
        docs = [d for d in yaml.safe_load_all(text)]
    except yaml.YAMLError as exc:
        raise RuleError([f"YAML error: {str(exc).splitlines()[0]}"])
    if len(docs) != 1 or not isinstance(docs[0], dict):
        raise RuleError(["a rule file must hold exactly one YAML mapping"])
    doc = docs[0]
    warnings = [f"unknown key {k!r} ignored" for k in doc if k not in KNOWN_KEYS]
    title = doc.get("title")
    if not isinstance(title, str) or not title.strip():
        problems.append("title is required")
    logsource = doc.get("logsource") or {}
    source = None
    if isinstance(logsource, dict):
        service = str(logsource.get("service") or "").lower()
        category = str(logsource.get("category") or "").lower()
        if service in SOURCES:
            source = service
        elif category in CATEGORY_MAP:
            source = CATEGORY_MAP[category]
        elif service in CATEGORY_MAP:
            source = CATEGORY_MAP[service]
        else:
            warnings.append(f"logsource {logsource!r} maps to no single source; the rule runs over all sources")
    else:
        problems.append("logsource must be a map")
    detection = doc.get("detection")
    selections: dict[str, Selection] = {}
    condition: tuple = ()
    if not isinstance(detection, dict):
        problems.append("detection must be a map of selections plus a condition")
    else:
        if "timeframe" in detection:
            warnings.append("timeframe is ignored")
        counter = [0]
        for name, body in detection.items():
            if name in ("condition", "timeframe"):
                continue
            sel = _selection(str(name), body, problems, counter)
            if sel is not None:
                selections[str(name)] = sel
        if len(selections) > MAX_SELECTIONS:
            problems.append(f"{len(selections)} selections; the limit is {MAX_SELECTIONS}")
        if counter[0] > MAX_TERMS:
            problems.append(f"{counter[0]} field terms; the limit is {MAX_TERMS}")
        cond = detection.get("condition")
        if isinstance(cond, list):
            cond = " or ".join(f"({c})" for c in cond)
        if not isinstance(cond, str) or not cond.strip():
            problems.append("detection.condition is required")
        elif not selections:
            problems.append("detection needs at least one selection")
        elif not problems:
            condition = _parse_condition(cond.strip(), list(selections), problems)
    if problems:
        raise RuleError(problems)
    tags = doc.get("tags") or []
    return Rule(title=title.strip(), rule_id=str(doc["id"]) if doc.get("id") is not None else None,
                level=str(doc["level"]).lower() if doc.get("level") else None,
                tags=[str(t) for t in tags] if isinstance(tags, list) else [],
                source=source, selections=selections, condition=condition, warnings=warnings,
                sha256=hashlib.sha256(data).hexdigest())


def validate(text: str) -> dict:
    """A never-raising wrapper for submission-time checks."""
    try:
        rule = parse(text)
    except RuleError as exc:
        return {"valid": False, "errors": exc.problems, "warnings": [], "title": None, "source": None}
    return {"valid": True, "errors": [], "warnings": rule.warnings, "title": rule.title, "source": rule.source,
            "selections": list(rule.selections), "sha256": rule.sha256}


# ---- evaluation ---------------------------------------------------------------------------------

def _record_value(record: dict, field_name: str):
    for key, value in record.items():
        if key.lower() == field_name:
            return value
    return None


def _glob(value: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(value.lower(), pattern.lower().replace("[", "[[]"))


def _match_value(actual, expected, mods: tuple[str, ...]) -> bool:
    if expected is None:
        return actual is None
    if actual is None:
        return False
    mod = next((m for m in mods if m != "all"), None)
    if mod in ("gt", "gte", "lt", "lte"):
        try:
            a, e = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return {"gt": a > e, "gte": a >= e, "lt": a < e, "lte": a <= e}[mod]
    if mod == "cidr":
        try:
            return ipaddress.ip_address(str(actual).strip()) in ipaddress.ip_network(str(expected).strip(), strict=False)
        except ValueError:
            return False
    text, pattern = str(actual), str(expected)
    if mod == "contains":
        return _glob(text, f"*{pattern}*")
    if mod == "startswith":
        return _glob(text, f"{pattern}*")
    if mod == "endswith":
        return _glob(text, f"*{pattern}")
    return _glob(text, pattern)


def _match_term(record: dict, term: Term) -> bool:
    if term.field is None:  # keywords
        blob = " ".join(str(v) for v in record.values()).lower()
        return any(str(v).lower() in blob for v in term.values)
    actual = _record_value(record, term.field)
    results = [_match_value(actual, v, term.modifiers) for v in term.values]
    return all(results) if "all" in term.modifiers else any(results)


def _match_selection(record: dict, sel: Selection) -> bool:
    return any(all(_match_term(record, t) for t in terms) for terms in sel.alternatives)


def _eval(node: tuple, record: dict, selections: dict[str, Selection]) -> bool:
    op = node[0]
    if op == "sel":
        return _match_selection(record, selections[node[1]])
    if op == "not":
        return not _eval(node[1], record, selections)
    if op == "and":
        return _eval(node[1], record, selections) and _eval(node[2], record, selections)
    if op == "or":
        return _eval(node[1], record, selections) or _eval(node[2], record, selections)
    if op == "any":
        return any(_eval(n, record, selections) for n in node[1])
    if op == "all":
        return all(_eval(n, record, selections) for n in node[1])
    raise ValueError(f"bad condition node {node!r}")


def evaluate(rule: Rule, export: dict) -> dict:
    """Match a rule against the export (`{source: [record, ...]}`); records need an `id`."""
    matched, by_source = [], {}
    for source in SOURCES if rule.source is None else (rule.source,):
        hits = [r.get("id") for r in export.get(source, []) if isinstance(r, dict) and _eval(rule.condition, r, rule.selections)]
        by_source[source] = len(hits)
        matched.extend(hits)
    return {"matched_ids": matched, "by_source": by_source, "count": len(matched)}


def score_rules(rules: list[Rule], export: dict, ground_truth: dict, precision_floor: float = 0.8,
                recall_floor: float = 0.5) -> dict:
    """Per-rule precision and recall against ground truth, and which behaviors the rule set covers."""
    malicious = {rid: beh for src in ground_truth.get("malicious_records", {}).values() for rid, beh in src.items()}
    exempt = {rid for ids in ground_truth.get("fp_exempt", {}).values() for rid in ids}
    behaviors = {tag: set(ids) for tag, ids in ground_truth.get("behaviors", {}).items()}
    per_rule = []
    for rule in rules:
        hits = set(evaluate(rule, export)["matched_ids"])
        tp, fp = hits & set(malicious), hits - set(malicious) - exempt
        precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else None
        beh_recall = {tag: len(tp & ids) / len(ids) for tag, ids in behaviors.items() if tp & ids}
        per_rule.append({"title": rule.title, "source": rule.source, "matched": len(hits), "tp": len(tp), "fp": len(fp),
                         "fp_ids": sorted(fp)[:20], "precision": precision, "behavior_recall": beh_recall,
                         "level": rule.level, "tags": rule.tags})
    coverage = {}
    for tag, ids in behaviors.items():
        best = max((r for r in per_rule if tag in r["behavior_recall"]),
                   key=lambda r: (r["precision"] or 0, r["behavior_recall"][tag]), default=None)
        detected = bool(best and (best["precision"] or 0) >= precision_floor and best["behavior_recall"][tag] >= recall_floor)
        coverage[tag] = {"records": len(ids), "detected": detected, "best_rule": best["title"] if best else None,
                         "recall": best["behavior_recall"][tag] if best else 0.0, "precision": best["precision"] if best else None}
    detected = sum(c["detected"] for c in coverage.values())
    return {"rules": per_rule, "behaviors": coverage, "behaviors_detected": detected, "behaviors_total": len(coverage),
            "coverage": detected / len(coverage) if coverage else 0.0}
