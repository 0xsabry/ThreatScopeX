"""Regression tests for the Sigma hardening work.

Covers modifier validation, the newly-supported modifiers (exists/neq/
gt-gte-lt-lte/cased), windash semantics, and the scan-scoped regex budget /
incomplete-scan diagnostics.
"""
import core.sigma_engine as sigma_engine
from core.sigma_engine import SigmaEngine, SigmaRule, SigmaScanContext


def _rule(detection: dict, **extra) -> SigmaRule:
    data = {"title": "t", "detection": detection, "level": "high"}
    data.update(extra)
    return SigmaRule(data)


def _event(fields=None, raw="", event_id=None):
    event = {"fields": fields or {}, "raw": raw}
    if event_id is not None:
        event["event_id"] = event_id
    return event


# ------------------------------------------------------- validation
def test_unsupported_fieldref_modifier_is_rejected():
    rule = _rule({"s": {"A|fieldref": "B"}, "condition": "s"})
    assert rule.valid is False
    assert any("fieldref" in e for e in rule.validation_errors)


def test_unknown_modifier_is_rejected_and_does_not_detect():
    rule = _rule({"s": {"A|frobnicate": "x"}, "condition": "s"})
    assert rule.valid is False
    assert rule.matches(_event({"A": "x"})) is False


def test_re_combined_with_contains_is_rejected():
    rule = _rule({"s": {"A|contains|re": "x"}, "condition": "s"})
    assert rule.valid is False


def test_cidr_combined_with_contains_is_rejected():
    rule = _rule({"s": {"A|cidr|contains": "10.0.0.0/8"}, "condition": "s"})
    assert rule.valid is False


def test_all_on_scalar_value_is_rejected():
    rule = _rule({"s": {"A|all": "x"}, "condition": "s"})
    assert rule.valid is False


def test_regex_flag_without_re_is_rejected():
    rule = _rule({"s": {"A|i": "x"}, "condition": "s"})
    assert rule.valid is False


def test_invalid_rule_does_not_affect_valid_unrelated_rule():
    invalid = _rule({"s": {"A|fieldref": "B"}, "condition": "s"}, id="bad")
    valid = _rule({"s": {"A|contains": "x"}, "condition": "s"}, id="good")
    assert invalid.valid is False
    assert valid.valid is True
    assert valid.matches(_event({"A": "axb"})) is True


# ------------------------------------------------------- new modifiers
def test_numeric_comparisons():
    gt = _rule({"s": {"F|gt": 5}, "condition": "s"})
    assert gt.matches(_event({"F": "10"})) is True
    assert gt.matches(_event({"F": "5"})) is False

    gte = _rule({"s": {"F|gte": 5}, "condition": "s"})
    assert gte.matches(_event({"F": "5"})) is True

    lt = _rule({"s": {"F|lt": 5}, "condition": "s"})
    assert lt.matches(_event({"F": "4"})) is True
    assert lt.matches(_event({"F": "5"})) is False

    lte = _rule({"s": {"F|lte": 5}, "condition": "s"})
    assert lte.matches(_event({"F": "5"})) is True


def test_exists_modifier_true_and_false():
    present = _rule({"s": {"F|exists": True}, "condition": "s"})
    absent = _rule({"s": {"F|exists": False}, "condition": "s"})
    assert present.matches(_event({"F": "anything"})) is True
    assert present.matches(_event({})) is False
    assert absent.matches(_event({})) is True
    assert absent.matches(_event({"F": "anything"})) is False


def test_neq_modifier_inverts_match():
    rule = _rule({"s": {"F|neq": "x"}, "condition": "s"})
    assert rule.matches(_event({"F": "y"})) is True
    assert rule.matches(_event({"F": "x"})) is False


def test_cased_modifier_is_case_sensitive():
    rule = _rule({"s": {"F|cased": "ABC"}, "condition": "s"})
    assert rule.matches(_event({"F": "ABC"})) is True
    assert rule.matches(_event({"F": "abc"})) is False


def test_startswith_and_endswith_are_case_insensitive_by_default():
    rule = _rule({"s": {"F|startswith": "abc"}, "condition": "s"})
    assert rule.matches(_event({"F": "ABCdef"})) is True
    rule2 = _rule({"s": {"F|endswith": "def"}, "condition": "s"})
    assert rule2.matches(_event({"F": "ABCdef"})) is True


# ------------------------------------------------------- windash
def test_windash_expands_only_parameter_separators():
    variants = SigmaRule._expand_value("-param-name", ["windash"])
    assert set(variants) == {
        "-param-name",
        "/param-name",
        "\u2013param-name",
        "\u2014param-name",
        "\u2015param-name",
    }


def test_windash_does_not_expand_mid_word_dash():
    assert SigmaRule._expand_value("a-b", ["windash"]) == ["a-b"]


def test_windash_rule_matches_slash_variant_only():
    rule = _rule({"s": {"CommandLine|windash": "/param-name"}, "condition": "s"})
    assert rule.matches(_event({"CommandLine": "/param-name"})) is True
    assert rule.matches(_event({"CommandLine": "-param-name"})) is True
    assert rule.matches(_event({"CommandLine": "a-b"})) is False


def test_windash_caps_expansions():
    value = "x -a -b -c -d"
    assert SigmaRule._expand_value(value, ["windash"]) == [value]


# ------------------------------------------------------- matcher safety
def test_startswith_combined_with_re_is_rejected_not_silently_ignored():
    rule = _rule({"s": {"F|startswith|re": "abc"}, "condition": "s"})
    assert rule.valid is False
    assert rule.matches(_event({"F": "xabc"})) is False


# ------------------------------------------------------- regex budget
def test_regex_budget_exhaustion_marks_scan_incomplete():
    rule = _rule({"s": {"F|re": "a"}, "condition": "s"})
    ctx = SigmaScanContext(max_regex_evaluations=1)
    assert rule.matches(_event({"F": "a"}), ctx) is True
    assert rule.matches(_event({"F": "a"}), ctx) is False
    summary = ctx.summary()
    assert summary["incomplete"] is True
    assert "regex_budget_exhausted" in summary["reasons"]


def test_regex_full_subject_is_not_truncated():
    # The old implementation truncated at 8192 chars and returned a false
    # negative; the match now lives beyond that boundary.
    rule = _rule({"s": {"F|re": "needle"}, "condition": "s"})
    field = "x" * 9000 + "needle"
    assert rule.matches(_event({"F": field})) is True


def test_oversized_regex_subject_is_reported_as_incomplete():
    rule = _rule({"s": {"F|re": "a"}, "condition": "s"})
    ctx = SigmaScanContext(max_subject_length=4)
    assert rule.matches(_event({"F": "aaaaa"}), ctx) is False
    summary = ctx.summary()
    assert summary["incomplete"] is True
    assert summary["oversized_subjects"] == 1
    assert "oversized_subjects" in summary["reasons"]


def test_missing_regex_engine_is_recorded(monkeypatch):
    monkeypatch.setattr(sigma_engine, "_regex_engine", None)
    rule = _rule({"s": {"F|re": "a"}, "condition": "s"})
    ctx = SigmaScanContext()
    assert rule.matches(_event({"F": "a"}), ctx) is False
    summary = ctx.summary()
    assert summary["missing_regex_engine"] == 1
    assert "missing_regex_engine" in summary["reasons"]


def test_regex_timeout_is_recorded_as_incomplete(monkeypatch):
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
    ctx = SigmaScanContext()
    assert rule.matches(_event({"F": "aaaa"}), ctx) is False
    assert ctx.summary()["regex_timeouts"] == 1
    assert "regex_timeouts" in ctx.summary()["reasons"]


# ------------------------------------------------------- rule errors
def test_invalid_rule_records_skipped_diagnostic():
    rule = _rule({"s": {"A|fieldref": "B"}, "condition": "s"}, id="bad")
    ctx = SigmaScanContext()
    assert rule.matches(_event({"A": "x"}), ctx) is False
    summary = ctx.summary()
    assert summary["skipped_rules"] == 1
    assert "skipped_rules" in summary["reasons"]


def test_unexpected_rule_error_is_recorded(monkeypatch):
    def _boom(self, selection, event, context=None):
        raise RuntimeError("simulated bug")

    monkeypatch.setattr(SigmaRule, "_evaluate_field_selection", _boom)
    rule = _rule({"s": {"F": "x"}, "condition": "s"})
    ctx = SigmaScanContext()
    assert rule.matches(_event({"F": "x"}), ctx) is False
    summary = ctx.summary()
    assert summary["unexpected_rule_errors"] == 1
    assert "unexpected_rule_errors" in summary["reasons"]


def test_expected_rule_error_is_recorded(monkeypatch):
    def _boom(self, selection, event, context=None):
        raise ValueError("bad value")

    monkeypatch.setattr(SigmaRule, "_evaluate_field_selection", _boom)
    rule = _rule({"s": {"F": "x"}, "condition": "s"})
    ctx = SigmaScanContext()
    assert rule.matches(_event({"F": "x"}), ctx) is False
    assert ctx.summary()["rule_errors"] == 1


# ------------------------------------------------------- engine stats
def test_engine_stats_expose_scan_and_invalid_rules():
    engine = SigmaEngine()
    ctx = SigmaScanContext()
    stats = engine.get_stats(ctx)
    assert "invalid" in stats
    assert "invalid_rules" in stats
    assert stats["scan"]["complete"] is True
    assert "limits" in stats["scan"]


# ------------------------------------------------------- analyzer integration
def test_analyzer_surfaces_incomplete_detection(monkeypatch):
    from core.analyzer import LogAnalyzer

    analyzer = LogAnalyzer()
    analyzer.events = [{"raw": "a", "fields": {"F": "a"}}]
    analyzer.sigma_engine.rules = [
        _rule({"s": {"F|re": "a"}, "condition": "s"})
    ]
    monkeypatch.setattr(
        analyzer.sigma_engine,
        "new_scan_context",
        lambda **kwargs: SigmaScanContext(max_regex_evaluations=0),
    )

    results = analyzer.analyze()

    assert results["detection_complete"] is False
    assert "regex_budget_exhausted" in results["sigma_diagnostics"]["reasons"]
    assert results["sigma_stats"]["scan"]["incomplete"] is True
    assert "INCOMPLETE DETECTION" in analyzer.generate_report()
