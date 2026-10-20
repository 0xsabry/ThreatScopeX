"""Curated Sigma conformance corpus.

This module is split deliberately into two concerns:

* **Parsing/validation compatibility** - rules are loaded through
  :class:`SigmaEngine` to confirm that YAML parsing and modifier validation
  behave as documented (valid vs invalid).
* **Event-matching compatibility** - rules are evaluated against synthetic
  events and compared with the expected detection outcome.

Passing YAML parsing does NOT imply pySigma event-matching equivalence; the
optional pySigma check below only exercises rule parsing. Intentional
deviations from pySigma semantics are documented per test.
"""
import base64
import os

import pytest

import core.sigma_engine as sigma_engine
from core.sigma_engine import SigmaEngine, SigmaRule

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "sigma")


def _rule(detection: dict, **extra) -> SigmaRule:
    data = {"title": "conformance", "detection": detection, "level": "high"}
    data.update(extra)
    return SigmaRule(data)


def _event(fields=None, raw="", **extra):
    event = {"fields": fields or {}, "raw": raw}
    event.update(extra)
    return event


# ============================================================ fixtures on disk
def _load_fixture_engine() -> SigmaEngine:
    engine = SigmaEngine(rules_dir=FIXTURE_DIR)
    engine.load_rules()
    return engine


def test_fixture_corpus_loads_with_expected_valid_invalid_split():
    engine = _load_fixture_engine()
    stats = engine.get_stats()
    assert stats["available"] is True
    assert stats["load_status"] == "ok"
    assert stats["loaded"] == 6
    assert stats["invalid"] == 3
    invalid_ids = {r["rule_id"] for r in stats["invalid_rules"]}
    assert invalid_ids == {
        "44444444-4444-4444-4444-444444444444",
        "55555555-5555-5555-5555-555555555555",
        "66666666-6666-6666-6666-666666666666",
    }


def test_invalid_fixtures_rejected_for_expected_reasons():
    engine = _load_fixture_engine()
    reasons = {
        r["rule_id"]: " ".join(r["errors"]).lower()
        for r in engine.get_stats()["invalid_rules"]
    }
    assert "fieldref" in reasons["44444444-4444-4444-4444-444444444444"]
    assert "wide" in reasons["55555555-5555-5555-5555-555555555555"]
    assert "re" in reasons["66666666-6666-6666-6666-666666666666"]
    # Rejected by modifier validation, not by a YAML parsing failure.
    for text in reasons.values():
        assert "yaml" not in text


def test_invalid_fixtures_never_detect():
    engine = _load_fixture_engine()
    event = _event(
        {"Image": "C:\\Windows\\cmd.exe", "CommandLine": "foo -encodedcommand bar"}
    )
    matched_ids = {m["rule_id"] for m in engine.match_event(event)}
    assert "44444444-4444-4444-4444-444444444444" not in matched_ids
    assert "55555555-5555-5555-5555-555555555555" not in matched_ids
    assert "66666666-6666-6666-6666-666666666666" not in matched_ids


def test_valid_fixtures_detect_expected_events():
    engine = _load_fixture_engine()
    process_event = _event(
        {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "whoami /all"}
    )
    assert any(
        m["rule_id"] == "11111111-1111-1111-1111-111111111111"
        for m in engine.match_event(process_event)
    )

    encoded = base64.b64encode(b"Invoke-Mimikatz").decode()
    b64_event = _event({"CommandLine": "powershell -enc " + encoded})
    assert any(
        m["rule_id"] == "22222222-2222-2222-2222-222222222222"
        for m in engine.match_event(b64_event)
    )

    windash_event = _event({"CommandLine": "powershell /encodedcommand AAAA"})
    assert any(
        m["rule_id"] == "33333333-3333-3333-3333-333333333333"
        for m in engine.match_event(windash_event)
    )


# ====================================================== condition operators
@pytest.mark.parametrize(
    "condition,detection,fields,expected",
    [
        ("a and b", {"a": {"X": "1"}, "b": {"Y": "2"}}, {"X": "1", "Y": "2"}, True),
        ("a and b", {"a": {"X": "1"}, "b": {"Y": "2"}}, {"X": "1"}, False),
        ("a or b", {"a": {"X": "1"}, "b": {"Y": "2"}}, {"Y": "2"}, True),
        ("not a", {"a": {"X": "1"}}, {"Y": "9"}, True),
        ("not a", {"a": {"X": "1"}}, {"X": "1"}, False),
        ("(a or b) and c", {"a": {"X": "1"}, "b": {"Y": "2"}, "c": {"Z": "3"}},
         {"Y": "2", "Z": "3"}, True),
        ("1 of sel*", {"sel1": {"X": "1"}, "sel2": {"Y": "2"}}, {"X": "1"}, True),
        ("all of sel*", {"sel1": {"X": "1"}, "sel2": {"Y": "2"}}, {"X": "1"}, False),
        ("all of them", {"a": {"X": "1"}, "b": {"Y": "2"}}, {"X": "1", "Y": "2"}, True),
        ("1 of them", {"a": {"X": "1"}, "b": {"Y": "2"}}, {"Y": "2"}, True),
    ],
)
def test_condition_operators_and_cardinality(condition, detection, fields, expected):
    rule = _rule({**detection, "condition": condition})
    assert rule.valid is True
    assert rule.matches(_event(fields)) is expected


def test_all_quantifier_on_scalar_is_rejected():
    rule = _rule({"s": {"A|all": "x"}, "condition": "s"})
    assert rule.valid is False


def test_all_with_list_requires_every_value():
    rule = _rule({"s": {"A|contains|all": ["http", "GET"]}, "condition": "s"})
    assert rule.valid is True
    assert rule.matches(_event({"A": "http request GET /"})) is True
    assert rule.matches(_event({"A": "http request POST /"})) is False


# ================================================ string match modifiers
@pytest.mark.parametrize(
    "field_spec,needle,value,expected",
    [
        ("F|contains", "mimikatz", "run mimikatz now", True),
        ("F|contains", "mimikatz", "run notepad now", False),
        ("F|startswith", "powershell", "PowerShell -enc", True),
        ("F|startswith", "powershell", "cmd /c powershell", False),
        ("F|endswith", ".exe", "C:\\Windows\\cmd.exe", True),
        ("F|endswith", ".exe", "C:\\Windows\\cmd.dll", False),
    ],
)
def test_string_match_modifiers(field_spec, needle, value, expected):
    rule = _rule({"s": {field_spec: needle}, "condition": "s"})
    assert rule.valid is True
    assert rule.matches(_event({"F": value})) is expected


# ================================================ encoding modifiers
def test_base64_exact_padded_and_embedded():
    encoded = base64.b64encode(b"ping").decode()
    assert encoded.endswith("==")
    exact = _rule({"s": {"F|base64": "ping"}, "condition": "s"})
    assert exact.matches(_event({"F": encoded})) is True
    # Deviation from older ThreatScope builds: padding is preserved and matching
    # is exact (pySigma value-transformation semantics).
    assert exact.matches(_event({"F": encoded.rstrip("=")})) is False

    embedded = _rule({"s": {"F|base64|contains": "ping"}, "condition": "s"})
    assert embedded.matches(_event({"F": "prefix " + encoded})) is True


def test_base64offset_alignments():
    assert SigmaRule._expand_value("cmd", ["base64offset"]) == ["Y21k", "NtZ", "jbW"]
    rule = _rule(
        {"s": {"F|base64offset|contains": "Invoke-Mimikatz"}, "condition": "s"}
    )
    for offset in (0, 1, 2):
        buffer = b"HEAD" * offset + b"Invoke-Mimikatz" + b"TAILTAIL"
        field = base64.b64encode(buffer).decode()
        assert rule.matches(_event({"F": field})) is True


def test_wide_base64_chain_and_utf16_bom():
    encoded = base64.b64encode("cmd".encode("utf-16-le")).decode()
    wide = _rule({"s": {"F|wide|base64|contains": "cmd"}, "condition": "s"})
    assert wide.matches(_event({"F": "prefix " + encoded})) is True

    encoded_bom = base64.b64encode(b"\xff\xfe" + "cmd".encode("utf-16-le")).decode()
    utf16 = _rule({"s": {"F|utf16|base64|contains": "cmd"}, "condition": "s"})
    assert utf16.matches(_event({"F": encoded_bom})) is True


def test_terminal_encoding_is_invalid():
    for spec in ("F|wide", "F|utf16", "F|utf16le", "F|utf16be", "F|base64|wide"):
        rule = _rule({"s": {spec: "cmd"}, "condition": "s"})
        assert rule.valid is False, spec
        assert rule.matches(_event({"F": "c\x00m\x00d\x00"})) is False


# ================================================ windash
def test_windash_positive_and_negative():
    rule = _rule({"s": {"F|windash": "-encodedcommand"}, "condition": "s"})
    assert rule.matches(_event({"F": "-encodedcommand"})) is True
    assert rule.matches(_event({"F": "/encodedcommand"})) is True
    assert rule.matches(_event({"F": "\u2013encodedcommand"})) is True
    # Mid-word dash is not an eligible separator.
    assert rule.matches(_event({"F": "a-b"})) is False


def test_windash_expansion_set_and_cap():
    assert set(SigmaRule._expand_value("-param-name", ["windash"])) == {
        "-param-name",
        "/param-name",
        "\u2013param-name",
        "\u2014param-name",
        "\u2015param-name",
    }
    value = "x -a -b -c -d"
    assert SigmaRule._expand_value(value, ["windash"]) == [value]


# ================================================ cased/exists/neq/numeric/cidr
@pytest.mark.parametrize(
    "spec,value,expected",
    [
        ("F|cased: 'ABC'", "ABC", True),
        ("F|cased: 'ABC'", "abc", False),
        ("F|exists: true", "anything", True),
        ("F|neq: 'x'", "y", True),
        ("F|neq: 'x'", "x", False),
        ("F|gt: 5", "10", True),
        ("F|gt: 5", "5", False),
        ("F|gte: 5", "5", True),
        ("F|lt: 5", "4", True),
        ("F|lte: 5", "5", True),
    ],
)
def test_value_type_modifiers(spec, value, expected):
    field, literal = spec.split(": ", 1)
    literal = literal.strip("'")
    if literal.isdigit():
        literal = int(literal)
    rule = _rule({"s": {field: literal}, "condition": "s"})
    assert rule.valid is True
    assert rule.matches(_event({"F": value})) is expected


def test_exists_false_on_missing_field():
    rule = _rule({"s": {"F|exists": False}, "condition": "s"})
    assert rule.matches(_event({})) is True
    assert rule.matches(_event({"F": "present"})) is False


def test_cidr_positive_and_negative():
    rule = _rule({"s": {"F|cidr": "10.0.0.0/8"}, "condition": "s"})
    assert rule.matches(_event({"F": "10.5.6.7"})) is True
    assert rule.matches(_event({"F": "192.168.1.1"})) is False


# ================================================ regex
def test_regex_flags_and_default_case_sensitivity():
    assert _rule({"s": {"F|re": "ABC"}, "condition": "s"}).matches(
        _event({"F": "abc"})
    ) is False
    assert _rule({"s": {"F|re|i": "ABC"}, "condition": "s"}).matches(
        _event({"F": "abc"})
    ) is True
    assert _rule({"s": {"F|re|s": "a.c"}, "condition": "s"}).matches(
        _event({"F": "a\nc"})
    ) is True
    multi = _rule({"s": {"F|re|m": "^beta$"}, "condition": "s"})
    assert multi.matches(_event({"F": "alpha\nbeta\ngamma"})) is True


def test_malformed_regex_is_invalid_and_does_not_detect():
    rule = _rule({"s": {"F|re": "("}, "condition": "s"})
    assert rule.valid is False
    assert rule.matches(_event({"F": "anything"})) is False


def test_oversized_regex_pattern_is_invalid():
    pattern = "a" * (sigma_engine.REGEX_MAX_PATTERN_LENGTH + 1)
    rule = _rule({"s": {"F|re": pattern}, "condition": "s"})
    assert rule.valid is False


def test_regex_timeout_treated_as_incomplete(monkeypatch):
    class TimeoutEngine:
        IGNORECASE = 2
        MULTILINE = 8
        DOTALL = 16
        error = Exception

        @staticmethod
        def search(pattern, text, flags=0, timeout=None):
            raise TimeoutError("boom")

    monkeypatch.setattr(sigma_engine, "_regex_engine", TimeoutEngine)
    rule = _rule({"s": {"F|re": "(a+)+$"}, "condition": "s"})
    ctx = sigma_engine.SigmaScanContext()
    assert rule.matches(_event({"F": "aaaa"}), ctx) is False
    assert ctx.summary()["regex_timeouts"] == 1


# ================================================ unsupported / invalid combos
@pytest.mark.parametrize(
    "spec",
    [
        "F|fieldref: B",
        "F|expand: '%something%'",
        "F|frobnicate: x",
        "F|contains|re: x",
        "F|startswith|re: x",
        "F|endswith|re: x",
        "F|cidr|contains: 10.0.0.0/8",
        "F|i: x",
        "F|all: x",
    ],
)
def test_invalid_modifier_specs_are_rejected(spec):
    field = spec.split(": ", 1)[0]
    rule = _rule({"s": {field: "x"}, "condition": "s"})
    assert rule.valid is False
    assert rule.matches(_event({"F": "x", "B": "x"})) is False


def test_unknown_modifier_does_not_detect_but_valid_rule_is_unaffected():
    invalid = _rule({"s": {"F|frobnicate": "x"}, "condition": "s"})
    valid = _rule({"s": {"F|contains": "x"}, "condition": "s"})
    assert invalid.valid is False
    assert valid.valid is True
    assert valid.matches(_event({"F": "axb"})) is True


# ================================================ optional pySigma parsing
def test_pysigma_optional_parsing_compatibility():
    """Optional parse-only cross-check; skipped when pySigma is unavailable.

    This asserts nothing about event-matching equivalence. It only confirms
    that pySigma can parse the three valid fixtures. Deeper, version-aware
    semantic comparison lives in ``test_sigma_pysigma_crosscheck.py``.
    """
    sigma_rule_mod = pytest.importorskip(
        "sigma.rule", reason="pySigma not installed (optional dev/test tool)"
    )
    parser = getattr(getattr(sigma_rule_mod, "SigmaRule", None), "from_yaml", None)
    if parser is None:
        pytest.skip("pySigma SigmaRule.from_yaml unavailable")
    for name in (
        "valid_process_creation.yml",
        "valid_base64_chain.yml",
        "valid_windash.yml",
    ):
        with open(os.path.join(FIXTURE_DIR, name), encoding="utf-8") as fh:
            assert parser(fh.read()) is not None, name
