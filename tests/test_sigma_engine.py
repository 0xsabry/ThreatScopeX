"""Regression tests for the Sigma rule engine (condition parsing & modifiers)."""
import base64

from core.sigma_engine import SigmaRule


def _rule(detection: dict) -> SigmaRule:
    return SigmaRule({"title": "t", "detection": detection, "level": "high"})


def _event(fields=None, raw="", event_id=None):
    event = {"fields": fields or {}, "raw": raw}
    if event_id is not None:
        event["event_id"] = event_id
    return event


def test_all_of_prefix_with_no_selections_does_not_match_everything():
    rule = _rule({"sel_a": {"Field": "x"}, "condition": "all of x*"})
    assert rule.matches(_event({"Field": "x"})) is False


def test_one_of_prefix_with_no_selections_does_not_match():
    rule = _rule({"sel_a": {"Field": "x"}, "condition": "1 of x*"})
    assert rule.matches(_event({"Field": "x"})) is False


def test_all_of_them_requires_each_selection():
    rule = _rule({"a": {"X": "1"}, "b": {"Y": "2"}, "condition": "all of them"})
    assert rule.matches(_event({"X": "1", "Y": "2"})) is True
    assert rule.matches(_event({"X": "1"})) is False


def test_field_value_is_exact_not_substring():
    rule = _rule({"s": {"EventID": 4688}, "condition": "s"})
    assert rule.matches(_event({"EventID": "14688"})) is False
    assert rule.matches(_event({"EventID": "4688"})) is True


def test_missing_field_does_not_fall_back_to_raw():
    rule = _rule({"s": {"CommandLine|contains": "mimikatz"}, "condition": "s"})
    assert rule.matches(_event({}, raw="mimikatz executed here")) is False


def test_trailing_and_not_filter_is_evaluated():
    rule = _rule({
        "selection": {"Image|endswith": "cmd.exe"},
        "filter": {"CommandLine|contains": "benign"},
        "condition": "selection and not filter",
    })
    assert rule.matches(_event({"Image": "C:\\Windows\\cmd.exe", "CommandLine": "evil"})) is True
    assert rule.matches(_event({"Image": "C:\\Windows\\cmd.exe", "CommandLine": "benign"})) is False


def test_base64_modifier_matches_encoded_value():
    encoded = base64.b64encode(b"Invoke-Mimikatz").decode()
    rule = _rule({"s": {"CommandLine|base64": "Invoke-Mimikatz"}, "condition": "s"})
    assert rule.matches(_event({"CommandLine": encoded})) is True
    assert rule.matches(_event({"CommandLine": "powershell -enc " + encoded})) is False


def test_contains_and_endswith_modifiers():
    rule = _rule({"s": {"Image|endswith": "\\powershell.exe"}, "condition": "s"})
    assert rule.matches(_event({
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    })) is True


def test_default_glob_wildcards():
    rule = _rule({"s": {"CommandLine": "*mimikatz*"}, "condition": "s"})
    assert rule.matches(_event({"CommandLine": "x mimikatz y"})) is True
    assert rule.matches(_event({"CommandLine": "nothing here"})) is False


def test_cidr_modifier():
    rule = _rule({"s": {"DestinationIp|cidr": "10.0.0.0/8"}, "condition": "s"})
    assert rule.matches(_event({"DestinationIp": "10.5.6.7"})) is True
    assert rule.matches(_event({"DestinationIp": "192.168.1.1"})) is False


def test_eventid_alias_resolves_top_level_and_fields():
    rule = _rule({"s": {"EventID": "4688"}, "condition": "s"})
    assert rule.matches(_event({"EventID": "4688"})) is True
    assert rule.matches(_event({}, event_id="4688")) is True
