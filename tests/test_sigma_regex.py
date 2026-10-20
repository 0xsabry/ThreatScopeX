"""Regression tests for bounded execution of the Sigma ``re`` modifier."""
import time

import pytest

import core.sigma_engine as sigma_engine
from core.sigma_engine import SigmaRule


def _rule(detection: dict) -> SigmaRule:
    return SigmaRule({"title": "t", "detection": detection, "level": "high"})


def _event(fields) -> dict:
    return {"fields": fields, "raw": ""}


def _re_rule(pattern: str, *flags: str) -> SigmaRule:
    modifier_spec = "|".join(("re",) + flags)
    return _rule({"s": {f"F|{modifier_spec}": pattern}, "condition": "s"})


def test_regex_engine_is_available():
    # The security fix depends on a timeout-capable engine being installed.
    assert sigma_engine.REGEX_TIMEOUT_AVAILABLE is True
    assert sigma_engine._regex_engine is not None


def test_re_normal_match_and_nonmatch():
    rule = _re_rule("a.c")
    assert rule.matches(_event({"F": "axc"})) is True
    assert rule.matches(_event({"F": "azzz"})) is False


def test_re_is_case_sensitive_by_default():
    rule = _re_rule("ABC")
    assert rule.matches(_event({"F": "ABC"})) is True
    assert rule.matches(_event({"F": "abc"})) is False


def test_re_ignorecase_flag_enables_case_insensitive():
    rule = _re_rule("ABC", "i")
    assert rule.matches(_event({"F": "abc"})) is True


def test_re_malformed_pattern_is_no_match_without_raising():
    rule = _re_rule("(")
    assert rule.matches(_event({"F": "anything"})) is False


def test_re_oversized_pattern_is_skipped():
    pattern = "a" * (sigma_engine.REGEX_MAX_PATTERN_LENGTH + 1)
    rule = _re_rule(pattern)
    assert rule.matches(_event({"F": "a" * 10})) is False


def test_re_oversized_input_is_bounded_and_matches_within_cap():
    rule = _re_rule("needle")
    assert rule.matches(_event({"F": "needle" + "x" * 100_000})) is True


def test_regex_timeout_is_passed_and_handled(monkeypatch):
    calls = {}

    class TimeoutEngine:
        IGNORECASE = 2
        MULTILINE = 8
        DOTALL = 16
        error = Exception

        @staticmethod
        def search(pattern, text, flags=0, timeout=None):
            calls["pattern"] = pattern
            calls["timeout"] = timeout
            raise TimeoutError("simulated catastrophic backtracking")

    monkeypatch.setattr(sigma_engine, "_regex_engine", TimeoutEngine)
    rule = _re_rule("(a+)+$")
    assert rule.matches(_event({"F": "a" * 50 + "X"})) is False
    assert calls["timeout"] == sigma_engine.REGEX_TIMEOUT_SECONDS


def test_regex_unavailable_refuses_unbounded_stdlib_fallback(monkeypatch):
    def _fail(*args, **kwargs):  # pragma: no cover - must never execute
        raise AssertionError("unbounded re.search must not be used for the re modifier")

    monkeypatch.setattr(sigma_engine, "_regex_engine", None)
    monkeypatch.setattr(sigma_engine.re, "search", _fail)
    rule = _re_rule("anything")
    assert rule.matches(_event({"F": "anything"})) is False


def test_catastrophic_pattern_is_bounded(monkeypatch):
    monkeypatch.setattr(sigma_engine, "REGEX_TIMEOUT_SECONDS", 0.05)
    rule = _re_rule("(a+)+$")
    start = time.monotonic()
    result = rule.matches(_event({"F": "a" * 4000 + "X"}))
    elapsed = time.monotonic() - start
    assert result is False
    # Generous upper bound: proves execution is bounded, not that it is fast.
    assert elapsed < 2.0
