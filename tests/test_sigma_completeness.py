"""Detection-completeness, log-bounding, and context-isolation tests."""
import logging
from concurrent.futures import ThreadPoolExecutor

import pytest

import core.sigma_engine as sigma_engine
from core.sigma_engine import SigmaEngine, SigmaRule, SigmaScanContext


def _rule(detection: dict, **extra) -> SigmaRule:
    data = {"title": "completeness", "detection": detection, "level": "high"}
    data.update(extra)
    return SigmaRule(data)


def _event(fields=None, raw=""):
    return {"fields": fields or {}, "raw": raw}


def _fresh_limiter(monkeypatch, **kwargs):
    limiter = sigma_engine._RateLimitedLogger(**kwargs)
    monkeypatch.setattr(sigma_engine, "_log_limiter", limiter)
    return limiter


# --------------------------------------------------------- bounded logging
def test_unexpected_rule_error_logging_is_bounded(monkeypatch, caplog):
    limiter = _fresh_limiter(monkeypatch, max_per_window=3, window_seconds=3600)

    def _boom(self, selection, event, context=None):
        raise RuntimeError("boom")

    monkeypatch.setattr(SigmaRule, "_evaluate_field_selection", _boom)
    rule = _rule({"s": {"F": "x"}, "condition": "s"})
    ctx = SigmaScanContext()
    caplog.set_level(logging.WARNING, logger="threatscope.sigma")

    for _ in range(50):
        assert rule.matches(_event({"F": "x"}), ctx) is False

    stats = limiter.stats()
    # 3 records in the window plus one suppression notice.
    assert stats["emitted"]["unexpected_rule_error"] == 4
    assert stats["suppressed"]["unexpected_rule_error"] == 47
    assert stats["suppressed_total"] == 47
    # Exact counters are unaffected by log suppression.
    assert ctx.summary()["unexpected_rule_errors"] == 50


def test_repeated_failures_keep_consistent_counts(monkeypatch, caplog):
    limiter = _fresh_limiter(monkeypatch, max_per_window=2, window_seconds=3600)

    def _boom(self, selection, event, context=None):
        raise ValueError("bad value")

    monkeypatch.setattr(SigmaRule, "_evaluate_field_selection", _boom)
    rule = _rule({"s": {"F": "x"}, "condition": "s"})
    caplog.set_level(logging.WARNING, logger="threatscope.sigma")

    ctx1 = SigmaScanContext()
    for _ in range(10):
        rule.matches(_event({"F": "x"}), ctx1)
    first = (dict(limiter.stats()["emitted"]), dict(limiter.stats()["suppressed"]))
    assert ctx1.summary()["rule_errors"] == 10

    limiter.reset()
    ctx2 = SigmaScanContext()
    for _ in range(10):
        rule.matches(_event({"F": "x"}), ctx2)
    second = (dict(limiter.stats()["emitted"]), dict(limiter.stats()["suppressed"]))
    assert ctx2.summary()["rule_errors"] == 10
    assert first == second


def test_log_limiter_bounds_key_table(monkeypatch, caplog):
    limiter = _fresh_limiter(
        monkeypatch, max_per_window=5, window_seconds=3600, max_keys=2
    )
    caplog.set_level(logging.WARNING, logger="threatscope.sigma")
    for i in range(10):
        limiter.warning(f"key{i}", "message %d", i)
    stats = limiter.stats()
    # Distinct keys cannot grow the table without limit (max_keys + overflow),
    # and total emission stays bounded (window cap + one notice per key).
    assert len(stats["emitted"]) <= limiter.max_keys + 1
    assert sum(stats["emitted"].values()) <= (limiter.max_keys + 1) * (
        limiter.max_per_window + 1
    )
    assert stats["suppressed_total"] > 0


def test_suppression_notice_reports_suppressed_tail(monkeypatch, caplog):
    _fresh_limiter(monkeypatch, max_per_window=1, window_seconds=3600)

    def _boom(self, selection, event, context=None):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(SigmaRule, "_evaluate_field_selection", _boom)
    rule = _rule({"s": {"F": "x"}, "condition": "s"})
    caplog.set_level(logging.WARNING, logger="threatscope.sigma")
    for _ in range(6):
        rule.matches(_event({"F": "x"}))

    messages = [r.getMessage() for r in caplog.records]
    assert any("suppressed" in m for m in messages)
    assert any(m.startswith("Unexpected error") for m in messages)


# --------------------------------------------------------- incomplete vs clean
def test_incomplete_scan_distinguishable_from_clean_scan():
    rule = _rule({"s": {"F|re": "a"}, "condition": "s"})
    event = _event({"F": "a"})

    clean = SigmaScanContext()
    assert rule.matches(event, clean) is True
    assert clean.summary()["complete"] is True

    exhausted = SigmaScanContext(max_regex_evaluations=0)
    assert rule.matches(event, exhausted) is False
    summary = exhausted.summary()
    assert summary["incomplete"] is True
    assert "regex_budget_exhausted" in summary["reasons"]


@pytest.mark.parametrize(
    "factory,expected_reason",
    [
        (lambda: SigmaScanContext(max_regex_evaluations=0), "regex_budget_exhausted"),
        (lambda: SigmaScanContext(max_subject_length=2), "oversized_subjects"),
    ],
)
def test_reported_incomplete_reasons(factory, expected_reason):
    rule = _rule({"s": {"F|re": "a"}, "condition": "s"})
    ctx = factory()
    rule.matches(_event({"F": "aaaa"}), ctx)
    assert expected_reason in ctx.summary()["reasons"]


# --------------------------------------------------------- context isolation
def test_independent_contexts_do_not_share_budget():
    rule = _rule({"s": {"F|re": "a"}, "condition": "s"})
    event = _event({"F": "a"})

    ctx_a = SigmaScanContext(max_regex_evaluations=1)
    ctx_b = SigmaScanContext()

    assert rule.matches(event, ctx_a) is True
    assert rule.matches(event, ctx_a) is False  # budget for A exhausted
    assert ctx_a.summary()["incomplete"] is True

    assert rule.matches(event, ctx_b) is True   # B unaffected
    assert ctx_b.summary()["complete"] is True


def test_contexts_isolated_across_threads():
    rule = _rule({"s": {"F|re": "a"}, "condition": "s"})
    event = _event({"F": "a"})
    engine = SigmaEngine()

    def _run(_):
        ctx = engine.new_scan_context()
        hits = sum(1 for _ in range(25) if rule.matches(event, ctx))
        return ctx.summary()["regex_evaluations"], hits, ctx.summary()["complete"]

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(_run, range(4)))

    for evaluations, hits, complete in results:
        assert evaluations == 25
        assert hits == 25
        assert complete is True


# --------------------------------------------------------- skipped rules
def test_skipped_rule_counts_are_accurate_and_deduplicated():
    rule = _rule({"s": {"F|fieldref": "B"}, "condition": "s"}, id="bad-rule")
    ctx = SigmaScanContext()
    for _ in range(25):
        assert rule.matches(_event({"F": "x"}), ctx) is False
    summary = ctx.summary()
    assert summary["skipped_rules"] == 1  # deduplicated per rule id
    assert "skipped_rules" in summary["reasons"]


# --------------------------------------------------------- missing YAML dep
def test_engine_without_yaml_support_is_consistent(monkeypatch):
    monkeypatch.setattr(sigma_engine, "YAML_AVAILABLE", False)
    engine = SigmaEngine()

    assert engine.available is False
    assert engine.load_status == "yaml_unavailable"
    assert engine.load_rules() == 0

    stats = engine.get_stats()
    assert stats["available"] is False
    assert stats["yaml_available"] is False
    assert stats["load_status"] == "yaml_unavailable"
    assert stats["loaded"] == 0
    assert stats["total_rules"] == 0
    assert stats["invalid_rules"] == []
    # No scan/evaluation is reported for an unavailable engine.
    assert engine.match_event(_event({"F": "x"})) == []
    assert engine.new_scan_context().summary()["complete"] is True


def test_engine_stats_before_load_do_not_claim_rules():
    engine = SigmaEngine()
    stats = engine.get_stats()
    assert stats["loaded"] == 0
    assert stats["load_status"] == "not_loaded"
