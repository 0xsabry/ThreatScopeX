"""Smoke tests for the agentic copilot and threat-intel URL construction."""
from intel.enrichment import _virustotal_url_id, _url_segment


def test_agentic_investigate_runs_clean():
    from ai.agentic_core import AgenticCopilot
    results = {
        "threat_score": 50,
        "threat_level": "HIGH",
        "summary": {"total_findings": 3, "critical": 1, "high": 1},
        "mitre_hits": {"T1059": 1, "T1059.001": 2},
        "findings": [],
        "iocs": {"hashes": {"md5": ["a" * 32], "sha256": ["b" * 64]},
                 "top_ips": []},
    }
    report = AgenticCopilot().investigate(results)
    assert report["triage"]["attack_stages_detected"] == ["Execution"]


def test_virustotal_url_id_is_base64url():
    # VT v3 URL id is base64url(url) without padding, not a sha256 digest
    url = "http://example.com/path"
    expected = "aHR0cDovL2V4YW1wbGUuY29tL3BhdGg"
    assert _virustotal_url_id(url) == expected


def test_url_segment_encodes_path_characters():
    assert "/" not in _url_segment("evil.com/path")
    assert "?" not in _url_segment("a?b=c")
