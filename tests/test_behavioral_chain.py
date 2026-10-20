"""Regression tests for the behavioral chaining engine."""
from datetime import datetime, timedelta

from core.behavioral_chain import BehavioralChainEngine

BASE = datetime(2024, 1, 1, 12, 0, 0)


def _add(engine, labels, offset_seconds):
    engine.add_event(BASE + timedelta(seconds=offset_seconds), labels)


def _triggers(engine, chain_id):
    return any(c["chain_id"] == chain_id for c in engine.analyze())


def test_min_count_is_enforced_on_first_stage():
    # BC-002 requires 5 failed logins before a success
    engine = BehavioralChainEngine()
    for i in range(4):
        _add(engine, ["brute_force"], i * 10)
    _add(engine, ["auth_success"], 100)
    assert _triggers(engine, "BC-002") is False

    engine = BehavioralChainEngine()
    for i in range(5):
        _add(engine, ["brute_force"], i * 10)
    _add(engine, ["auth_success"], 100)
    assert _triggers(engine, "BC-002") is True


def test_chain_respects_time_window():
    engine = BehavioralChainEngine()
    for i in range(6):
        _add(engine, ["brute_force"], i * 10)
    _add(engine, ["auth_success"], 3600)  # outside the 15-minute window
    assert _triggers(engine, "BC-002") is False


def test_events_fed_from_findings_use_rule_id_labels():
    engine = BehavioralChainEngine()
    findings = {
        "brute_force": [
            {"rule_id": "brute_force",
             "timestamp": (BASE + timedelta(seconds=i * 10)).isoformat(),
             "line_number": i}
            for i in range(5)
        ],
        "off_hours_access": [
            {"rule_id": "off_hours_access",
             "timestamp": (BASE + timedelta(seconds=100)).isoformat(),
             "line_number": 99}
        ],
    }
    engine.add_events_from_findings(findings, [])
    assert len(engine.events) == 6
    assert "brute_force" in engine.events[0].labels


def test_timestamp_parser_handles_iso_and_datetime():
    assert BehavioralChainEngine._parse_timestamp("2024-01-01T12:00:00Z") is not None
    assert BehavioralChainEngine._parse_timestamp(BASE) == BASE
    assert BehavioralChainEngine._parse_timestamp("not-a-date") is None
