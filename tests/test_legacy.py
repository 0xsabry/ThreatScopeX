"""Legacy desktop GUI compatibility checks.

``ThreatscopeX.py`` is a separate legacy desktop GUI (``VERSION = "1.0"``)
with its own 308-rule ``PATTERNS`` dictionary. These checks validate
only that legacy GUI — they do NOT validate ``app.py`` or ``cli.py``,
and the Tkinter GUI is never launched.

The pattern data is read by parsing the source with ``ast`` instead of
importing the module, so the checks run in a headless runner even where
Tkinter is unavailable. The CLI smoke test is the one step that needs
Tkinter (the legacy module imports it at the top level) and is skipped
with a clear reason when it cannot be imported.
"""

import ast
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LEGACY_FILE = REPO_ROOT / "ThreatscopeX.py"
SAMPLE_EVTX = REPO_ROOT / "sample_anyonomus login.evtx"

# The legacy GUI's own documented counts.
EXPECTED_LEGACY_RULE_COUNT = 308
EXPECTED_LEGACY_VERSION = "1.0"

REQUIRED_FIELDS = {"patterns", "severity", "weight", "category", "desc"}


def load_legacy_patterns():
    """Return the legacy PATTERNS dict, read from source without importing.

    The legacy module imports Tkinter at the top level, which a headless
    runner may not have; the patterns themselves are a plain literal.
    """
    tree = ast.parse(LEGACY_FILE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "PATTERNS":
                    return ast.literal_eval(node.value)
    raise AssertionError("PATTERNS assignment not found in ThreatscopeX.py")


def load_legacy_version():
    """Return the legacy VERSION string, read from source without importing."""
    tree = ast.parse(LEGACY_FILE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "VERSION":
                    return ast.literal_eval(node.value)
    raise AssertionError("VERSION assignment not found in ThreatscopeX.py")


class TestLegacyGui(unittest.TestCase):
    def test_legacy_source_compiles(self):
        import py_compile

        self.assertTrue(
            py_compile.compile(str(LEGACY_FILE), doraise=True),
            "ThreatscopeX.py does not compile",
        )

    def test_legacy_version_is_1_0(self):
        self.assertEqual(load_legacy_version(), EXPECTED_LEGACY_VERSION)

    def test_legacy_rule_count(self):
        patterns = load_legacy_patterns()
        self.assertEqual(
            len(patterns),
            EXPECTED_LEGACY_RULE_COUNT,
            f"legacy PATTERNS has {len(patterns)} rules, expected "
            f"{EXPECTED_LEGACY_RULE_COUNT}",
        )

    def test_legacy_patterns_have_required_fields_and_compile(self):
        patterns = load_legacy_patterns()
        errors = []
        for name, rule in patterns.items():
            missing = REQUIRED_FIELDS - set(rule.keys())
            if missing:
                errors.append(
                    f"{name}: missing required field(s): {', '.join(sorted(missing))}"
                )
            for pattern in rule.get("patterns", []):
                try:
                    re.compile(pattern)
                except re.error as exc:
                    errors.append(f"{name}: regex does not compile: {pattern!r} ({exc})")
        self.assertEqual(errors, [], "Invalid legacy patterns:\n" + "\n".join(errors))

    @unittest.skipUnless(
        importlib.util.find_spec("tkinter") is not None,
        "tkinter is not available in this environment; the legacy CLI "
        "smoke test needs it because ThreatscopeX.py imports it",
    )
    def test_legacy_cli_smoke(self):
        """Legacy CLI mode on the committed sample, headless (no GUI launch)."""
        self.assertTrue(SAMPLE_EVTX.exists(), f"committed sample missing: {SAMPLE_EVTX}")
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "legacy_report.json"
            result = subprocess.run(
                [sys.executable, "ThreatscopeX.py", "-f", str(SAMPLE_EVTX),
                 "-j", str(output_path)],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=300,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output_path.exists(), "legacy CLI did not write JSON")
            with open(output_path, encoding="utf-8") as f:
                report = json.load(f)
        self.assertEqual(report.get("version"), EXPECTED_LEGACY_VERSION)
        self.assertGreater(report.get("threat_score", 0), 0)


if __name__ == "__main__":
    unittest.main()
