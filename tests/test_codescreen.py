import pytest

import codescreen
from conftest import FIXTURES

EXPECTED_RULE = {
    "net.py": "import", "proc.py": "import", "reflect.py": "dunder", "fileio.py": "call", "dunder_import.py": "call",
    "getattr_dunder.py": "reflection", "format_dunder.py": "reflection", "toplevel.py": "top-level",
    "noentry.py": "interface", "urllib_request.py": "import", "async_code.py": "async",
}


def test_golden_hunt_and_extract_pass():
    for name, kind in (("hunt.py", "hunt_script"), ("extract.py", "ioc_extractor")):
        result = codescreen.screen((FIXTURES / "golden" / name).read_text(), kind)
        assert result["ok"], (name, result["problems"])
        assert result["entry"] in result["functions"]
        assert result["sha256"] and result["bytes"] > 0


@pytest.mark.parametrize("name,rule", sorted(EXPECTED_RULE.items()))
def test_malicious_fixtures_are_refused(name, rule):
    result = codescreen.screen((FIXTURES / "malicious" / name).read_text(), "hunt_script")
    assert not result["ok"], name
    assert rule in {p["rule"] for p in result["problems"]}, (name, result["problems"])


def test_size_and_syntax_and_signature():
    big = "x = 1\n" * 20000 + "def hunt(data):\n    return []\n"
    assert {p["rule"] for p in codescreen.screen(big, "hunt_script")["problems"]} == {"size"}
    assert codescreen.screen("def hunt(data:\n", "hunt_script")["problems"][0]["rule"] == "syntax"
    two = codescreen.screen("def hunt(data, more):\n    return []\n", "hunt_script")
    assert {p["rule"] for p in two["problems"]} == {"interface"}
    ok = codescreen.screen("def hunt(data, limit=10):\n    return []\n", "hunt_script")
    assert ok["ok"], ok["problems"]
    assert not codescreen.screen("def extract(data):\n    return {}\n", "hunt_script")["ok"]
    assert codescreen.screen("def hunt(data):\n    return []\n", "sigma_rule")["problems"][0]["rule"] == "kind"


def test_main_guard_and_urllib_parse_allowed():
    src = 'from urllib import parse\nimport urllib.parse\nURL = "x"\n\ndef hunt(data):\n    return [parse.urlsplit(URL).path]\n\nif __name__ == "__main__":\n    hunt({})\n'
    result = codescreen.screen(src, "hunt_script")
    assert result["ok"], result["problems"]
    assert result["imports"] == ["urllib.parse"]


def test_contract_lists_every_kind():
    assert set(codescreen.CONTRACT) >= {"data", "hunt_script", "ioc_extractor", "sigma_rule", "allowed_imports"}
