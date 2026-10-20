"""Tests for export formats (STIX validity, PDF generation)."""
import json

import pytest

from export.exporters import export_stix, export_pdf, PDF_AVAILABLE

RESULTS = {
    "metadata": {"filepath": "x<b>.log"},
    "threat_score": 70,
    "threat_level": "HIGH",
    "summary": {"total_findings": 1, "critical": 1, "high": 0, "medium": 0,
                "low": 0, "mitre_techniques": 1, "total_iocs": 3, "correlations": 1},
    "findings": [{"severity": "critical", "title": "Cred",
                  "description": "dump", "mitre": "T1003"}],
    "iocs": {"top_ips": ["1.2.3.4"], "top_domains": ["evil.com"],
             "urls": ["http://x/y'a"], "hashes": {"md5": ["a" * 32], "sha1": [], "sha256": ["b" * 64]},
             "cves": []},
    "mitre_hits": {"T1003": 2},
}


def test_stix_uses_correct_hash_algorithm_names(tmp_path):
    out = tmp_path / "out.stix.json"
    export_stix(RESULTS, str(out))
    bundle = json.loads(out.read_text())
    patterns = [o["pattern"] for o in bundle["objects"]
                if o["type"] == "indicator" and "hashes" in o.get("pattern", "")]
    assert "[file:hashes.'MD5'" in patterns[0]
    assert any("'SHA-256'" in p for p in patterns)


def test_stix_identity_class_is_valid(tmp_path):
    out = tmp_path / "out2.stix.json"
    export_stix(RESULTS, str(out))
    bundle = json.loads(out.read_text())
    identity = [o for o in bundle["objects"] if o["type"] == "identity"][0]
    assert identity["identity_class"] in {
        "individual", "group", "system", "organization", "class", "unknown"
    }


def test_stix_escapes_single_quotes_in_patterns(tmp_path):
    out = tmp_path / "out3.stix.json"
    export_stix(RESULTS, str(out))
    bundle = json.loads(out.read_text())
    url_pattern = [o["pattern"] for o in bundle["objects"]
                   if "url:value" in o.get("pattern", "")][0]
    assert "\\'" in url_pattern


@pytest.mark.skipif(not PDF_AVAILABLE, reason="reportlab not installed")
def test_pdf_export_handles_markup_in_metadata(tmp_path):
    out = tmp_path / "r.pdf"
    result = export_pdf(RESULTS, str(out))
    import os
    assert os.path.exists(result)
    assert os.path.getsize(result) > 0
