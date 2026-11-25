"""Current detection-engine validation.

Tests ``core.analyzer.BUILTIN_PATTERNS`` — the detection patterns of the
current web application (``app.py`` / ``cli.py``) — not the legacy desktop
GUI's ``PATTERNS`` dictionary (see ``test_legacy.py`` for that).

The expected count (57) matches the README's documented count
("57 Detection Categories", 27 original + 30 extended). If the source
count changes for a legitimate reason, update the README and this
constant together from the actual source — never hardcode a wrong number.
"""

import re
import unittest

from core.analyzer import BUILTIN_PATTERNS

# Documented in the README; counted in core/analyzer.py (BUILTIN_PATTERNS).
EXPECTED_PATTERN_COUNT = 57

REQUIRED_FIELDS = {"patterns", "severity", "weight", "category", "desc", "mitre"}


def validate_patterns(patterns):
    """Return a list of human-readable problems in a patterns mapping.

    Every problem names the pattern and the exact defect, so a failure
    tells the reader what to fix instead of just failing a count.
    """
    errors = []
    for name, rule in patterns.items():
        if not isinstance(rule, dict):
            errors.append(f"{name}: rule is not a mapping")
            continue
        missing = REQUIRED_FIELDS - set(rule.keys())
        if missing:
            errors.append(f"{name}: missing required field(s): {', '.join(sorted(missing))}")
        regexes = rule.get("patterns")
        if not isinstance(regexes, list) or not regexes:
            errors.append(f"{name}: 'patterns' must be a non-empty list")
            continue
        for pattern in regexes:
            try:
                re.compile(pattern)
            except re.error as exc:
                errors.append(f"{name}: regex does not compile: {pattern!r} ({exc})")
    return errors


class TestBuiltinPatterns(unittest.TestCase):
    def test_pattern_count_matches_readme(self):
        self.assertEqual(
            len(BUILTIN_PATTERNS),
            EXPECTED_PATTERN_COUNT,
            f"BUILTIN_PATTERNS has {len(BUILTIN_PATTERNS)} top-level patterns, "
            f"but the README documents {EXPECTED_PATTERN_COUNT}. Reconcile the "
            "README and the source from the actual count; do not hardcode a "
            "wrong number here.",
        )

    def test_every_pattern_has_required_fields(self):
        errors = validate_patterns(BUILTIN_PATTERNS)
        self.assertEqual(errors, [], "Invalid detection patterns:\n" + "\n".join(errors))

    def test_every_regex_compiles(self):
        bad = []
        for name, rule in BUILTIN_PATTERNS.items():
            for pattern in rule["patterns"]:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    bad.append(f"{name}: {pattern!r} ({exc})")
        self.assertEqual(bad, [], "Regexes that do not compile:\n" + "\n".join(bad))

    def test_invalid_patterns_produce_useful_failures(self):
        """The validator must catch a broken rule and name the defect."""
        broken = {
            "broken_rule": {
                "patterns": ["[unclosed", "valid"],
                "severity": "high",
                # 'weight', 'category', 'desc', 'mitre' deliberately missing
            },
        }
        errors = validate_patterns(broken)
        self.assertTrue(
            any("broken_rule" in e and "unclosed" in e for e in errors),
            f"validator did not report the bad regex: {errors}",
        )
        self.assertTrue(
            any("broken_rule" in e and "missing required field" in e for e in errors),
            f"validator did not report the missing fields: {errors}",
        )
        # A bare re.compile of the bad pattern must also raise, so a bad
        # rule can never slip through silently.
        with self.assertRaises(re.error):
            re.compile("[unclosed")


if __name__ == "__main__":
    unittest.main()
