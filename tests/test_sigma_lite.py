import pytest

import sigma_lite
from conftest import FIXTURES

GOLDEN = sorted((FIXTURES / "golden" / "sigma").glob("*.yml"))
EXPECTED_IDS = {
    "vpn_foreign_logon": {"auth-006"},
    "svc_backup_spray": {f"auth-{i:03d}" for i in range(8, 20)},
    "c2_beacon_dns": {"dns-004", "dns-005", "dns-006", "dns-007", "dns-008", "dns-009", "dns-010", "dns-012", "dns-013"},
    "c2_beacon_proxy": {"proxy-003", "proxy-004", "proxy-006", "proxy-009"},
    "exfil_upload": {"proxy-005"},
    "persistence_task": {"endpoint-004"},
    "lateral_wmi": {"endpoint-009"},
    "service_install_decommissioned": {"endpoint-010"},
}


@pytest.mark.parametrize("path", GOLDEN, ids=[p.stem for p in GOLDEN])
def test_golden_rules_match_exactly(path, export):
    rule = sigma_lite.parse(path.read_text())
    assert rule.source in sigma_lite.SOURCES, rule.warnings
    assert set(sigma_lite.evaluate(rule, export)["matched_ids"]) == EXPECTED_IDS[path.stem]


def test_golden_set_covers_every_behavior(export, ground_truth):
    rules = [sigma_lite.parse(p.read_text()) for p in GOLDEN]
    scored = sigma_lite.score_rules(rules, export, ground_truth)
    assert all(r["fp"] == 0 for r in scored["rules"]), scored["rules"]
    assert scored["behaviors_detected"] == scored["behaviors_total"] == 8, scored["behaviors"]


def test_decoys_are_counted_as_false_positives(export, ground_truth):
    decoy = sigma_lite.parse((FIXTURES / "weak" / "decoy_scanner.yml").read_text())
    broad = sigma_lite.parse((FIXTURES / "weak" / "overbroad_auth.yml").read_text())
    scored = sigma_lite.score_rules([decoy, broad], export, ground_truth)
    assert scored["rules"][0]["fp_ids"] == ["endpoint-002"] and scored["rules"][0]["precision"] == 0.0
    assert scored["rules"][1]["precision"] < 0.5 and scored["behaviors_detected"] == 0


def test_validate_reports_problems_without_raising():
    bad = sigma_lite.validate("title: x\nlogsource: {service: dns}\ndetection:\n  sel:\n    query|re: '.*'\n  condition: sel\n")
    assert not bad["valid"] and any("unsupported modifier" in e for e in bad["errors"])
    agg = sigma_lite.validate("title: x\nlogsource: {service: dns}\ndetection:\n  sel:\n    query: a\n  condition: sel | count() > 3\n")
    assert not agg["valid"] and any("aggregation" in e for e in agg["errors"])
    multi = sigma_lite.validate("title: a\n---\ntitle: b\n")
    assert not multi["valid"]
    unknown = sigma_lite.validate("title: x\nlogsource: {service: dns}\ndetection:\n  sel:\n    query: a\n  condition: other\n")
    assert any("unknown selection" in e for e in unknown["errors"])
    assert not sigma_lite.validate("title: x\nlogsource: {service: dns}\ndetection:\n  condition: sel\n")["valid"]
    assert not sigma_lite.validate(": not yaml: [")["valid"]


def test_condition_grammar_keywords_wildcards_and_aliases(export):
    text = (
        "title: grammar\nlogsource: {service: proxy}\ndetection:\n"
        "  sel_a:\n    cs-method: POST\n  sel_b:\n    URL|contains: upload\n  keywords:\n    - 'Single 48.3 MB upload'\n"
        "  bad:\n    host: WS-MED-*\n  condition: (1 of sel_*) and not bad and all of sel_*\n"
    )
    rule = sigma_lite.parse(text)
    assert set(sigma_lite.evaluate(rule, export)["matched_ids"]) == {"proxy-005"}
    kw = sigma_lite.parse("title: k\nlogsource: {service: proxy}\ndetection:\n  keywords:\n    - 48.3 MB\n  condition: keywords\n")
    assert sigma_lite.evaluate(kw, export)["matched_ids"] == ["proxy-005"]
    everywhere = sigma_lite.parse("title: all\nlogsource: {product: windows}\ndetection:\n  s:\n    host: SRV-WEB-02\n  condition: s\n")
    assert everywhere.source is None and everywhere.warnings
    assert set(sigma_lite.evaluate(everywhere, export)["by_source"]) == set(sigma_lite.SOURCES)
    nulls = sigma_lite.parse("title: n\nlogsource: {service: auth}\ndetection:\n  s:\n    user: null\n  condition: s\n")
    assert sigma_lite.evaluate(nulls, export)["count"] == 0
    cond_list = sigma_lite.parse("title: l\nlogsource: {service: dns}\ndetection:\n  a:\n    host: WS-G1-007\n  b:\n    host: SRV-VSCAN-01\n  condition:\n    - a\n    - b\n")
    assert set(sigma_lite.evaluate(cond_list, export)["matched_ids"]) == {"dns-001", "dns-003"}


def test_limits():
    many = "title: m\nlogsource: {service: dns}\ndetection:\n" + "".join(f"  s{i}:\n    query: q{i}\n" for i in range(25)) + "  condition: 1 of them\n"
    assert any("selections" in e for e in sigma_lite.validate(many)["errors"])
    assert any("bytes" in e for e in sigma_lite.validate("title: " + "x" * 40000)["errors"])
