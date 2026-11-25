"""Current CLI tests.

Tests the actual ``cli.py`` interface of the current web application:
``--help``, ``analyze --help``, and a real offline end-to-end analysis
of the committed sample ``sample_anyonomus login.evtx`` with JSON export.

No API key or live third-party service is needed: the sample analysis
runs fully offline. Assertions follow the real JSON schema produced by
``export.exporters.export_json`` (``tool``, ``results.metadata``,
``results.threat_score``, ``results.threat_level``, ``results.summary``,
``results.findings``) — they were written from an inspected export, not
assumed.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_EVTX = REPO_ROOT / "sample_anyonomus login.evtx"


def run_cli(*args, **kwargs):
    """Run the current CLI as a subprocess from the repository root."""
    return subprocess.run(
        [sys.executable, "cli.py", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        **kwargs,
    )


class TestCliHelp(unittest.TestCase):
    def test_top_level_help(self):
        result = run_cli("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ThreatScope", result.stdout)
        self.assertIn("analyze", result.stdout)

    def test_analyze_help(self):
        result = run_cli("analyze", "--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--output", result.stdout)
        self.assertIn("json", result.stdout)


class TestCliSampleAnalysis(unittest.TestCase):
    def test_analyze_sample_evtx_to_json(self):
        self.assertTrue(SAMPLE_EVTX.exists(), f"committed sample missing: {SAMPLE_EVTX}")
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.json"
            result = run_cli(
                "analyze", str(SAMPLE_EVTX),
                "-o", str(output_path), "-f", "json",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output_path.exists(), "CLI did not write the JSON export")
            with open(output_path, encoding="utf-8") as f:
                report = json.load(f)

        # Export envelope identifies the tool.
        self.assertEqual(report.get("tool"), "ThreatScope")
        results = report.get("results")
        self.assertIsInstance(results, dict, "export has no 'results' object")

        # Result metadata and summary from the real run.
        metadata = results.get("metadata", {})
        self.assertGreater(
            metadata.get("total_events", 0), 0,
            "sample analysis parsed zero events",
        )
        self.assertIn("threat_score", results)
        score = results["threat_score"]
        self.assertIsInstance(score, int)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)
        level = results.get("threat_level")
        self.assertIsInstance(level, str)
        self.assertTrue(level, "threat_level is empty")
        summary = results.get("summary")
        self.assertIsInstance(summary, dict, "results has no 'summary'")
        self.assertIn("total_findings", summary)
        self.assertIsInstance(results.get("findings"), list)


if __name__ == "__main__":
    unittest.main()
