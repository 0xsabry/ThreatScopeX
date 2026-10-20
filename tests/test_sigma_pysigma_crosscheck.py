"""pySigma cross-check for the curated Sigma conformance corpus (test-only).

pySigma is an optional development/test tool (see ``requirements-dev.txt``); it
is never imported by ThreatScopeX at runtime. This module is skipped entirely
when pySigma is not installed, so the application suite still runs everywhere.

The verification is split into three explicitly separated categories:

A. **Rule parsing and schema validation** - ``PySigmaRule.from_yaml`` versus
   ``SigmaRule.valid``.
B. **Modifier / condition semantic compatibility** - pySigma modifier classes
   versus ``SigmaRule._expand_value`` and the local validator.
C. **ThreatScopeX event-matching results** - *not* cross-checked here. pySigma
   has no backend-agnostic event-matching API in this environment, so no
   matching equivalence is claimed. Event matching stays covered by
   ``test_sigma_conformance.py``.

Where pySigma and ThreatScopeX intentionally differ, the divergence is asserted
explicitly rather than hidden. One pySigma behaviour changed between 1.x and 2.x
(the ``utf16`` + ``base64`` byte-order mark and the ``windash`` expansion cap);
those version-dependent cases are branched on the detected pySigma version.
"""
import importlib.metadata as metadata
import os

import pytest

pytest.importorskip("sigma", reason="pySigma not installed (optional test-only tool)")

from sigma.exceptions import (  # noqa: E402
    SigmaError,
    SigmaModifierError,
    SigmaTypeError,
    SigmaValueError,
)
from sigma.rule import SigmaRule as PySigmaRule  # noqa: E402

from core.sigma_engine import SigmaEngine  # noqa: E402
from core.sigma_engine import SigmaRule as TSXRule  # noqa: E402

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "sigma")


def _pysigma_version():
    parts = metadata.version("pySigma").split(".")
    return tuple(int(p) for p in parts[:2] if p.isdigit())


PYSIGMA_VERSION = _pysigma_version()
# pySigma 2.x changed the `utf16|base64` byte-order mark and capped `windash`.
PY_SIGMA_2 = PYSIGMA_VERSION >= (2, 0)

VALID_FIXTURES = (
    "valid_process_creation.yml",
    "valid_base64_chain.yml",
    "valid_windash.yml",
)
# ThreatScopeX intentionally rejects these; pySigma accepts them.
DEVIATION_FIXTURES = (
    "invalid_unsupported_modifier.yml",
    "invalid_terminal_wide.yml",
)
TSX_INVALID_IDS = {
    "44444444-4444-4444-4444-444444444444",
    "55555555-5555-5555-5555-555555555555",
    "66666666-6666-6666-6666-666666666666",
}


def _tsx_rule(spec, value):
    return TSXRule(
        {"title": "t", "level": "low", "detection": {"s": {spec: value}, "condition": "s"}}
    )


def _parse_text(text):
    try:
        return PySigmaRule.from_yaml(text), None
    except SigmaError as exc:
        return None, exc


def _parse(spec, value):
    text = (
        "title: t\nlogsource:\n  product: windows\n"
        f"detection:\n  s:\n    {spec}: {value!r}\n  condition: s\n"
    )
    return _parse_text(text)


def _flatten(values):
    out = []
    for value in values:
        if hasattr(value, "values"):
            out.extend(_flatten(value.values))
        else:
            out.append(str(value))
    return out


def _pysigma_values(spec, value):
    rule, err = _parse(spec, value)
    assert err is None, f"pySigma unexpectedly rejected {spec}: {err}"
    item = next(iter(rule.detection.detections["s"].detection_items))
    return _flatten(item.value)


def _fixture_engine():
    engine = SigmaEngine(rules_dir=FIXTURE_DIR)
    engine.load_rules()
    return engine


# =========================================================== Category A: parse
@pytest.mark.parametrize("name", VALID_FIXTURES)
def test_a_valid_fixtures_parse_in_pysigma(name):
    with open(os.path.join(FIXTURE_DIR, name), encoding="utf-8") as fh:
        _, err = _parse_text(fh.read())
    assert err is None, f"pySigma rejected valid fixture {name}: {err}"


def test_a_invalid_re_combination_rejected_for_expected_reason():
    with open(
        os.path.join(FIXTURE_DIR, "invalid_re_with_contains.yml"), encoding="utf-8"
    ) as fh:
        _, err = _parse_text(fh.read())
    assert isinstance(err, SigmaValueError)
    assert "regular expression" in str(err).lower()


@pytest.mark.parametrize("name", DEVIATION_FIXTURES)
def test_a_deviation_fixtures_accepted_by_pysigma(name):
    """pySigma accepts these; ThreatScopeX rejects them (documented deviation)."""
    with open(os.path.join(FIXTURE_DIR, name), encoding="utf-8") as fh:
        _, err = _parse_text(fh.read())
    assert err is None, f"expected pySigma to accept {name}: {err}"


def test_a_tsx_fixture_split_is_documented():
    stats = _fixture_engine().get_stats()
    assert stats["loaded"] == 6
    assert stats["invalid"] == 3
    assert {r["rule_id"] for r in stats["invalid_rules"]} == TSX_INVALID_IDS


# ==================================================== Category B: semantics
@pytest.mark.parametrize(
    "spec,value,expected",
    [
        ("F|base64", "ping", ["cGluZw=="]),
        ("F|base64offset", "cmd", ["Y21k", "NtZ", "jbW"]),
        ("F|wide", "cmd", ["c\x00m\x00d\x00"]),
        ("F|utf16", "cmd", ["\ufeffc\x00m\x00d\x00"]),
        ("F|utf16be", "cmd", ["\x00c\x00m\x00d"]),
        ("F|wide|base64", "cmd", ["YwBtAGQA"]),
        ("F|utf16be|base64", "cmd", ["AGMAbQBk"]),
    ],
)
def test_b_value_transforms_match_pysigma(spec, value, expected):
    assert TSXRule._expand_value(value, spec.split("|")[1:]) == expected
    assert _pysigma_values(spec, value) == expected


def test_b_utf16_base64_bom_behavior_is_version_aware():
    """pySigma 1.x encodes the marker as UTF-8; 2.x and ThreatScopeX use FF FE."""
    tsx = TSXRule._expand_value("cmd", ["utf16", "base64"])
    psy = _pysigma_values("F|utf16|base64", "cmd")
    if PY_SIGMA_2:
        assert tsx == psy == ["//5jAG0AZAA="]
    else:
        assert psy == ["77u/YwBtAGQA"]
        assert tsx == ["//5jAG0AZAA="]


def test_b_windash_variant_sets_match_pysigma():
    expected = {
        "-param-name",
        "/param-name",
        "\u2013param-name",
        "\u2014param-name",
        "\u2015param-name",
    }
    assert set(TSXRule._expand_value("-param-name", ["windash"])) == expected
    assert set(_pysigma_values("F|windash", "-param-name")) == expected
    # Mid-word dashes are not eligible separators in either implementation.
    assert TSXRule._expand_value("a-b", ["windash"]) == ["a-b"]
    assert _pysigma_values("F|windash", "a-b") == ["a-b"]


def test_b_windash_expansion_cap():
    value = "x -a -b -c -d"
    if PY_SIGMA_2:
        _, err = _parse("F|windash", value)
        assert isinstance(err, SigmaError)
    else:
        assert len(_pysigma_values("F|windash", value)) == 625
    # ThreatScopeX rejects the rule regardless (bounded expansion).
    assert _tsx_rule("F|windash", value).valid is False


@pytest.mark.parametrize(
    "spec,exc",
    [
        ("F|contains|re", SigmaValueError),
        ("F|startswith|re", SigmaValueError),
        ("F|endswith|re", SigmaValueError),
        ("F|frobnicate", SigmaModifierError),
        ("F|utf16le", SigmaModifierError),
        ("F|re|z", SigmaModifierError),
        ("F|exists", SigmaTypeError),
        ("F|gt", SigmaTypeError),
        ("F|cidr", SigmaTypeError),
        ("F|i", SigmaTypeError),
    ],
)
def test_b_rejections_agree_with_pysigma(spec, exc):
    _, err = _parse(spec, "x")
    assert isinstance(err, exc), f"{spec}: expected {exc.__name__}, got {err!r}"
    assert _tsx_rule(spec, "x").valid is False


@pytest.mark.parametrize(
    "spec",
    ["F|fieldref", "F|expand", "F|wide", "F|utf16", "F|utf16be", "F|base64|wide", "F|all"],
)
def test_b_tsx_is_stricter_than_pysigma(spec):
    """Documented deviations: pySigma accepts these, ThreatScopeX rejects them."""
    _, err = _parse(spec, "x")
    assert err is None, f"pySigma unexpectedly rejected {spec}: {err}"
    assert _tsx_rule(spec, "x").valid is False


@pytest.mark.parametrize(
    "condition",
    [
        "a and b",
        "a or b",
        "not a",
        "(a or b) and c",
        "1 of sel*",
        "all of sel*",
        "all of them",
        "1 of them",
    ],
)
def test_b_conditions_parse_in_both(condition):
    text = (
        "title: t\nlogsource:\n  product: windows\n"
        "detection:\n  a:\n    X: '1'\n  b:\n    Y: '2'\n"
        "  sel1:\n    X: '1'\n  sel2:\n    Y: '2'\n"
        f"  condition: {condition}\n"
    )
    _, err = _parse_text(text)
    assert err is None, f"pySigma rejected condition {condition!r}: {err}"
    detection = {
        "a": {"X": "1"},
        "b": {"Y": "2"},
        "sel1": {"X": "1"},
        "sel2": {"Y": "2"},
        "condition": condition,
    }
    assert TSXRule({"title": "t", "detection": detection}).valid is True


# ============================================== Category C: matching (not cross-checked)
def test_c_event_matching_is_not_cross_checked_by_pysigma():
    """pySigma provides no backend-agnostic event-matching API in this env.

    ThreatScopeX event matching (positive/negative fixtures) is verified in
    ``test_sigma_conformance.py``; this cross-check makes no equivalence claim.
    """
    assert not hasattr(PySigmaRule, "matches")
    assert not hasattr(PySigmaRule, "match_event")
    assert not hasattr(PySigmaRule, "process")
