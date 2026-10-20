"""Regression tests for parser fixes (CloudTrail/Azure/firewall/MFT)."""
import json

from parsers.log_parsers import CloudTrailParser, AzureActivityParser
from parsers.linux_parsers import FirewallLogParser
from parsers.forensic_parsers import MFTParser


def test_cloudtrail_accepts_top_level_list(tmp_path):
    p = tmp_path / "ct.json"
    p.write_text(json.dumps([
        {"eventName": "CreateUser", "eventTime": "2024-01-01T00:00:00Z"}
    ]))
    events = CloudTrailParser().parse(str(p))
    assert len(events) == 1
    assert events[0]["event_id"] == "CreateUser"


def test_cloudtrail_accepts_records_wrapper(tmp_path):
    p = tmp_path / "ct2.json"
    p.write_text(json.dumps({"Records": [{"eventName": "DeleteTrail"}]}))
    assert len(CloudTrailParser().parse(str(p))) == 1


def test_azure_accepts_top_level_list(tmp_path):
    p = tmp_path / "az.json"
    p.write_text(json.dumps([
        {"operationName": {"value": "roleAssignments/write"}, "caller": "u@x"}
    ]))
    events = AzureActivityParser().parse(str(p))
    assert len(events) == 1
    assert events[0]["event_id"] == "roleAssignments/write"


def test_firewall_parses_iptables_without_dport():
    # Optional trailing DPT group previously caused the wrong branch to be taken
    line = ("Jan  1 00:00:00 host kernel: [12345.6] IN=eth0 OUT= MAC=aa:bb "
            "SRC=10.0.0.1 DST=10.0.0.2 LEN=60 PROTO=TCP SPT=1234")
    event = FirewallLogParser()._parse_line(line, 1)
    assert event is not None
    assert event["fields"]["dest_ip"] == "10.0.0.2"
    assert event["fields"]["source_ip"] == "10.0.0.1"
    assert event["fields"]["protocol"] == "TCP"


def test_mft_timestamp_seven_digit_fraction_and_z():
    parsed = MFTParser._parse_timestamp("2024-01-01T12:00:00.1234567Z")
    assert parsed is not None
    assert parsed.microsecond == 123456


def test_mft_timestamp_plain_formats():
    assert MFTParser._parse_timestamp("2024-01-01 12:00:00.123456") is not None
    assert MFTParser._parse_timestamp("") is None
