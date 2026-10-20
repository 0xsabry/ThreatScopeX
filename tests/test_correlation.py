"""Regression tests for correlation time-windowing and FP whitelist."""
from datetime import datetime, timedelta

from core.correlation import CorrelationEngine
from core.false_positive import FalsePositiveSuppressor

BASE = datetime(2024, 1, 1, 12, 0, 0)


def _findings(offset_minutes):
    return {
        "brute_force": [{"rule_id": "brute_force", "timestamp": BASE.isoformat()}],
        "privilege_escalation": [{
            "rule_id": "privilege_escalation",
            "timestamp": (BASE + timedelta(minutes=offset_minutes)).isoformat(),
        }],
    }


def _has(engine, findings, window, corr_id="CORR-002"):
    results = engine.correlate(findings, time_window_minutes=window)
    return any(c["id"] == corr_id for c in results)


def test_legacy_behaviour_without_window():
    assert _has(CorrelationEngine(), _findings(5), None) is True


def test_within_window_triggers():
    assert _has(CorrelationEngine(), _findings(5), 60) is True


def test_outside_window_does_not_trigger():
    assert _has(CorrelationEngine(), _findings(600), 5) is False


def test_whitelist_pattern_suppresses_finding(tmp_path):
    fp = FalsePositiveSuppressor(model_path=str(tmp_path / "fp.json"))
    fp.whitelisted_patterns = ["benign-agent"]
    findings = [
        {"rule_id": "brute_force", "raw": "benign-agent activity"},
        {"rule_id": "brute_force", "raw": "real brute force"},
    ]
    filtered, suppressed = fp.filter_findings(findings)
    assert len(suppressed) == 1
    assert suppressed[0]["raw"] == "benign-agent activity"
    assert len(filtered) == 1
