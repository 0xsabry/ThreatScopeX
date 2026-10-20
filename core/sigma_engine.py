"""
ThreatScope V2 — Full SigmaHQ Rule Engine
Author: 0xSABRY

Complete Sigma rule parser supporting:
- Full condition logic (and, or, not, 1 of, all of)
- Field selections with modifiers (contains, startswith, endswith, re, base64)
- Aggregation conditions (count, min, max, avg, sum)
- Log source filtering
- MITRE ATT&CK mapping
"""

import re
import os
import base64
import ipaddress
import logging
import threading
import time
from pathlib import Path
from collections import defaultdict, deque
from itertools import product
from typing import Dict, List, Optional, Any, Set, Tuple

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

logger = logging.getLogger("threatscope.sigma")

# ── Bounded regex execution for the ``re`` modifier ──────────────────────
# The stdlib ``re`` engine cannot bound execution time, so a rule (or a
# community-supplied rule) containing a catastrophic pattern such as
# ``(a+)+$`` combined with attacker-controlled log content can hang analysis.
# We therefore use the ``regex`` package, whose ``timeout`` argument provides
# a hard, enforceable execution bound.
# When ``regex`` is unavailable we deliberately do NOT fall back to the
# unbounded stdlib engine (that would reintroduce the ReDoS); the pattern is
# skipped and recorded as an incomplete evaluation instead.
try:
    import regex as _regex_engine
    REGEX_TIMEOUT_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the runtime environment
    _regex_engine = None
    REGEX_TIMEOUT_AVAILABLE = False

# Scan-scoped defaults. ``config`` exposes these through environment variables
# (see README "Sigma detection limits"); the fallbacks keep the engine usable
# when imported standalone.
try:
    from config import (
        SIGMA_REGEX_MAX_EVALUATIONS as _CFG_MAX_EVALUATIONS,
        SIGMA_REGEX_MAX_SECONDS as _CFG_MAX_SECONDS,
        SIGMA_REGEX_TIMEOUT_SECONDS as _CFG_OPERATION_TIMEOUT,
        SIGMA_REGEX_MAX_SUBJECT_LENGTH as _CFG_MAX_SUBJECT_LENGTH,
    )
except Exception:  # pragma: no cover - standalone import
    _CFG_MAX_EVALUATIONS = 10_000
    _CFG_MAX_SECONDS = 30.0
    _CFG_OPERATION_TIMEOUT = 2.0
    _CFG_MAX_SUBJECT_LENGTH = 1_000_000

REGEX_MAX_EVALUATIONS = int(_CFG_MAX_EVALUATIONS)
REGEX_MAX_TOTAL_SECONDS = float(_CFG_MAX_SECONDS)
REGEX_TIMEOUT_SECONDS = float(_CFG_OPERATION_TIMEOUT)
REGEX_MAX_SUBJECT_LENGTH = int(_CFG_MAX_SUBJECT_LENGTH)
REGEX_MAX_PATTERN_LENGTH = 1000
REGEX_MIN_REMAINING_SECONDS = 0.05

# ``regex.error`` is not a subclass of ``re.error``; resolve the right class.
_REGEX_ERROR = getattr(_regex_engine, "error", re.error)


class SigmaEvaluationError(RuntimeError):
    """Expected rule-evaluation failure (bad combination or malformed data)."""


# ============================================================
# Sigma Field Modifiers
# ============================================================
SUPPORTED_MATCH_MODIFIERS = {"contains", "startswith", "endswith", "re"}
SUPPORTED_ENCODING_MODIFIERS = {
    "base64", "base64offset", "wide", "utf16", "utf16le", "utf16be",
}
SUPPORTED_TRANSFORM_MODIFIERS = SUPPORTED_ENCODING_MODIFIERS | {"windash"}
SUPPORTED_NUMERIC_MODIFIERS = {"gt", "gte", "lt", "lte"}
SUPPORTED_FLAG_MODIFIERS = {"i", "ignorecase", "m", "multiline", "s", "dotall"}
SUPPORTED_LIST_MODIFIERS = {"all", "neq"}
SUPPORTED_TYPE_MODIFIERS = {"cased"}
SUPPORTED_MODIFIERS = (
    SUPPORTED_MATCH_MODIFIERS
    | SUPPORTED_TRANSFORM_MODIFIERS
    | SUPPORTED_NUMERIC_MODIFIERS
    | SUPPORTED_FLAG_MODIFIERS
    | SUPPORTED_LIST_MODIFIERS
    | SUPPORTED_TYPE_MODIFIERS
    | {"cidr", "exists"}
)
UNSUPPORTED_MODIFIERS = {
    "fieldref": "field references are not supported by the local matcher",
    "expand": "placeholder expansion requires a Sigma pipeline",
    "day": "timestamp-part modifiers are not supported",
    "hour": "timestamp-part modifiers are not supported",
    "minute": "timestamp-part modifiers are not supported",
    "month": "timestamp-part modifiers are not supported",
    "week": "timestamp-part modifiers are not supported",
    "year": "timestamp-part modifiers are not supported",
}

_WINDASH_ELIGIBLE_RE = re.compile(r"\B[-/]\b")
_WINDASH_VARIANTS = ("-", "/", "\u2013", "\u2014", "\u2015")
WINDASH_MAX_EXPANSIONS = 3


def _short(value: Any, limit: int = 160) -> str:
    """Render an untrusted value for a bounded diagnostic sample."""
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "..."


class _RateLimitedLogger:
    """Bounds repeated diagnostic log records while preserving exact counters.

    Rule evaluation runs once per rule per event, so a malformed rule or event
    could otherwise emit an unbounded number of log records. This wrapper emits
    at most ``max_per_window`` records per key per rolling window, followed by a
    single suppression notice, and then stays silent until the window resets.

    Exact failure counts live in :class:`SigmaScanContext`; only log *emission*
    is bounded, so a suppressed log never hides that a scan is incomplete or
    that rules failed.
    """

    def __init__(
        self,
        max_per_window: int = 5,
        window_seconds: float = 60.0,
        max_keys: int = 128,
    ):
        self.max_per_window = max(1, int(max_per_window))
        self.window_seconds = max(0.0, float(window_seconds))
        self.max_keys = max(1, int(max_keys))
        self._state: Dict[str, dict] = {}
        self._suppressed: Dict[str, int] = defaultdict(int)
        self._emitted: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
        self.suppressed_total = 0

    def _should_emit(self, key: str, now: float) -> Tuple[bool, int, str]:
        state = self._state.get(key)
        if state is None or (now - state["start"]) >= self.window_seconds:
            state = {"start": now, "count": 0, "notified": False}
            if len(self._state) >= self.max_keys and key not in self._state:
                # Bound the key table so distinct keys cannot grow without limit.
                key = "__overflow__"
                state = self._state.get(key, state)
            self._state[key] = state
        if state["count"] < self.max_per_window:
            state["count"] += 1
            return True, 0, key
        state["count"] += 1
        self._suppressed[key] += 1
        self.suppressed_total += 1
        if not state["notified"]:
            state["notified"] = True
            return True, self._suppressed[key], key
        return False, self._suppressed[key], key

    def log(self, level: int, key: str, msg: Any, *args: Any) -> None:
        try:
            text = msg % args if args else str(msg)
        except Exception:
            text = msg if isinstance(msg, str) else str(msg)
        with self._lock:
            emit, suppressed, effective_key = self._should_emit(
                key, time.monotonic()
            )
            if emit:
                self._emitted[effective_key] += 1
        if not emit:
            return
        if suppressed:
            logger.log(
                level,
                "%s [%s: %d further messages suppressed in this window]",
                text, effective_key, suppressed,
            )
        else:
            logger.log(level, text)

    def warning(self, key: str, msg: Any, *args: Any) -> None:
        self.log(logging.WARNING, key, msg, *args)

    def error(self, key: str, msg: Any, *args: Any) -> None:
        self.log(logging.ERROR, key, msg, *args)

    def debug(self, key: str, msg: Any, *args: Any) -> None:
        self.log(logging.DEBUG, key, msg, *args)

    def stats(self) -> Dict[str, Any]:
        """Return emitted/suppressed counts (for diagnostics and tests)."""
        with self._lock:
            return {
                "emitted": dict(self._emitted),
                "suppressed": dict(self._suppressed),
                "suppressed_total": self.suppressed_total,
                "max_per_window": self.max_per_window,
                "window_seconds": self.window_seconds,
            }

    def reset(self) -> None:
        with self._lock:
            self._state.clear()
            self._suppressed.clear()
            self._emitted.clear()
            self.suppressed_total = 0


# Process-wide limiter: many scans (e.g. web requests) share one budget so log
# volume is bounded across the process, while per-scan counters stay exact.
_log_limiter = _RateLimitedLogger()


def get_log_limiter_stats() -> Dict[str, Any]:
    """Return the process-wide Sigma log-limiter counters."""
    return _log_limiter.stats()


class SigmaScanContext:
    """Per-analysis state for bounded regex work and diagnostics.

    One instance is created per analysis/scan and passed explicitly through the
    evaluation chain. It is deliberately not stored on the shared
    :class:`SigmaEngine`, so concurrent Flask requests cannot interfere with
    each other's budgets or diagnostics.

    The context tracks both an evaluation-count budget and an elapsed-time
    deadline. Both are checked before every regex evaluation, so the budget is
    shared across events, rules, field values and encoded candidates.
    """

    MAX_SAMPLES = 50
    _SAMPLE_MAX_CHARS = 240

    def __init__(
        self,
        max_regex_evaluations: Optional[int] = None,
        max_seconds: Optional[float] = None,
        per_operation_timeout: Optional[float] = None,
        max_subject_length: Optional[int] = None,
    ):
        self.max_regex_evaluations = (
            REGEX_MAX_EVALUATIONS
            if max_regex_evaluations is None
            else int(max_regex_evaluations)
        )
        self.max_seconds = (
            REGEX_MAX_TOTAL_SECONDS if max_seconds is None else float(max_seconds)
        )
        self.per_operation_timeout = (
            REGEX_TIMEOUT_SECONDS
            if per_operation_timeout is None
            else float(per_operation_timeout)
        )
        self.max_subject_length = (
            REGEX_MAX_SUBJECT_LENGTH
            if max_subject_length is None
            else int(max_subject_length)
        )
        self._started = time.monotonic()
        self._deadline = self._started + max(0.0, self.max_seconds)

        self.regex_evaluations = 0
        self.regex_elapsed_seconds = 0.0
        self.regex_timeouts = 0
        self.budget_exhausted = 0
        self.oversized_subjects = 0
        self.missing_engine = 0
        self.invalid_patterns = 0
        self.patterns_too_long = 0
        self.rule_errors = 0
        self.unexpected_rule_errors = 0
        self.skipped_rules = 0
        self._skipped_rule_ids: Set[str] = set()
        self._samples: deque = deque(maxlen=self.MAX_SAMPLES)

    def elapsed_seconds(self) -> float:
        return max(0.0, time.monotonic() - self._started)

    def remaining_seconds(self) -> float:
        return max(0.0, self._deadline - time.monotonic())

    @property
    def exhausted(self) -> bool:
        return (
            self.regex_evaluations >= self.max_regex_evaluations
            or self.remaining_seconds() <= REGEX_MIN_REMAINING_SECONDS
        )

    def regex_budget_reason(self) -> Optional[str]:
        if self.regex_evaluations >= self.max_regex_evaluations:
            return "evaluation_count"
        if self.remaining_seconds() <= REGEX_MIN_REMAINING_SECONDS:
            return "elapsed_time"
        return None

    def effective_timeout(self) -> float:
        return max(0.0, min(self.per_operation_timeout, self.remaining_seconds()))

    def _sample(self, kind: str, detail: str) -> None:
        self._samples.append(f"{kind}: {detail}"[: self._SAMPLE_MAX_CHARS])

    def record_timeout(self, pattern: str) -> None:
        self.regex_timeouts += 1
        self._sample("regex_timeout", _short(pattern))

    def record_budget_exhausted(self, reason: str) -> None:
        self.budget_exhausted += 1
        self._sample("budget_exhausted", reason)

    def record_oversized_subject(self, length: int) -> None:
        self.oversized_subjects += 1
        self._sample("oversized_subject", f"{length} > {self.max_subject_length}")

    def record_missing_engine(self, pattern: str) -> None:
        self.missing_engine += 1
        self._sample("missing_regex_engine", _short(pattern))

    def record_invalid_pattern(self, pattern: str) -> None:
        self.invalid_patterns += 1
        self._sample("invalid_pattern", _short(pattern))

    def record_pattern_too_long(self, length: int) -> None:
        self.patterns_too_long += 1
        self._sample(
            "pattern_too_long", f"{length} > {REGEX_MAX_PATTERN_LENGTH}"
        )

    def record_rule_error(
        self, rule_id: str, exc: BaseException, unexpected: bool = False
    ) -> None:
        if unexpected:
            self.unexpected_rule_errors += 1
            kind = "unexpected_rule_error"
        else:
            self.rule_errors += 1
            kind = "rule_error"
        self._sample(kind, f"{rule_id}: {type(exc).__name__}: {exc}")

    def record_skipped_rule(
        self, rule_id: str, reason: str, detail: str = ""
    ) -> None:
        key = rule_id or "<no-id>"
        if key not in self._skipped_rule_ids:
            self._skipped_rule_ids.add(key)
            self.skipped_rules += 1
            self._sample(f"skipped_rule:{reason}", f"{key}: {detail}")

    def summary(self) -> Dict[str, Any]:
        reasons = []
        if self.budget_exhausted:
            reasons.append("regex_budget_exhausted")
        if self.regex_timeouts:
            reasons.append("regex_timeouts")
        if self.oversized_subjects:
            reasons.append("oversized_subjects")
        if self.missing_engine:
            reasons.append("missing_regex_engine")
        if self.invalid_patterns:
            reasons.append("invalid_regex_patterns")
        if self.patterns_too_long:
            reasons.append("oversized_regex_patterns")
        if self.rule_errors:
            reasons.append("rule_evaluation_errors")
        if self.unexpected_rule_errors:
            reasons.append("unexpected_rule_errors")
        if self.skipped_rules:
            reasons.append("skipped_rules")

        return {
            "complete": not reasons,
            "incomplete": bool(reasons),
            "reasons": reasons,
            "regex_evaluations": self.regex_evaluations,
            "regex_seconds": round(self.regex_elapsed_seconds, 3),
            "regex_timeouts": self.regex_timeouts,
            "budget_exhausted": self.budget_exhausted,
            "oversized_subjects": self.oversized_subjects,
            "missing_regex_engine": self.missing_engine,
            "invalid_regex_patterns": self.invalid_patterns,
            "oversized_regex_patterns": self.patterns_too_long,
            "rule_errors": self.rule_errors,
            "unexpected_rule_errors": self.unexpected_rule_errors,
            "skipped_rules": self.skipped_rules,
            "elapsed_seconds": round(self.elapsed_seconds(), 3),
            "limits": {
                "max_regex_evaluations": self.max_regex_evaluations,
                "max_seconds": self.max_seconds,
                "per_operation_timeout_seconds": self.per_operation_timeout,
                "max_subject_length": self.max_subject_length,
            },
            "samples": list(self._samples),
        }

# Log source to platform mapping
LOGSOURCE_PLATFORM_MAP = {
    "windows": "windows",
    "linux": "linux",
    "macos": "macos",
    "aws": "cloud",
    "azure": "cloud",
    "gcp": "cloud",
    "okta": "cloud",
    "m365": "cloud",
    "github": "cloud",
}


class SigmaRule:
    """
    Represents a parsed Sigma detection rule with full condition support.
    """

    def __init__(self, rule_data: dict, source_file: str = ""):
        """
        Initialize a Sigma rule from parsed YAML data.

        Args:
            rule_data: Parsed YAML dictionary of the Sigma rule.
            source_file: Path to the source YAML file.
        """
        self.raw = rule_data
        self.source_file = source_file
        self.id = rule_data.get("id", "")
        self.title = rule_data.get("title", "Untitled Rule")
        self.status = rule_data.get("status", "experimental")
        self.description = rule_data.get("description", "")
        self.author = rule_data.get("author", "")
        self.date = rule_data.get("date", "")
        self.modified = rule_data.get("modified", "")
        self.level = rule_data.get("level", "medium").lower()
        self.falsepositives = rule_data.get("falsepositives", [])

        # Log source
        logsource = rule_data.get("logsource", {})
        self.log_category = logsource.get("category", "")
        self.log_product = logsource.get("product", "")
        self.log_service = logsource.get("service", "")

        # MITRE ATT&CK mapping
        self.tags = rule_data.get("tags", [])
        self.mitre_techniques = []
        self.mitre_tactics = []
        self._parse_mitre_tags()

        # Detection logic
        self.detection = rule_data.get("detection", {})
        self.condition = self.detection.get("condition", "")
        self._selection_cache = {}

        # Platform
        self.platform = self._determine_platform()

        # Severity weight
        self.weight = {"critical": 40, "high": 25, "medium": 15, "low": 5, "informational": 1}.get(
            self.level, 15
        )

        # Validation is deliberately non-throwing: invalid rules are marked
        # invalid so a scan can skip them and report the affected rule instead
        # of aborting or silently misinterpreting it.
        self.validation_errors: List[str] = []
        self.valid = True
        self._validate_detection()

    # ----------------------------------------------------------
    # Rule validation
    # ----------------------------------------------------------
    @staticmethod
    def _is_bool_value(value: Any) -> bool:
        if isinstance(value, bool):
            return True
        return isinstance(value, str) and value.lower() in ("true", "false")

    @staticmethod
    def _add_validation_error(errors: List[str], message: str) -> None:
        # Bound the error list so a hostile rule cannot exhaust memory.
        if len(errors) < 20:
            errors.append(message)

    def _validate_detection(self) -> None:
        """Validate modifier names, chains and value types before evaluation."""
        errors: List[str] = []
        if not isinstance(self.detection, dict) or not self.detection:
            self._add_validation_error(errors, "rule has no detection block")
        else:
            for sel_name, selection in self.detection.items():
                if sel_name == "condition":
                    continue
                if isinstance(selection, list):
                    # Plain keyword lists do not use field modifiers.
                    continue
                if not isinstance(selection, dict):
                    self._add_validation_error(
                        errors, f"selection '{sel_name}' is not a mapping"
                    )
                    continue
                for field_spec, values in selection.items():
                    self._validate_field_spec(str(field_spec), values, errors)
                    if len(errors) >= 20:
                        break
                if len(errors) >= 20:
                    break

        self.validation_errors = errors
        self.valid = not errors

    def _validate_field_spec(
        self, field_spec: str, values: Any, errors: List[str]
    ) -> None:
        parts = field_spec.split("|")
        modifiers = parts[1:]
        if any(m == "" for m in modifiers):
            self._add_validation_error(errors, f"{field_spec}: empty modifier")
            return

        unknown = [m for m in modifiers if m not in SUPPORTED_MODIFIERS]
        if unknown:
            for modifier in unknown:
                if modifier in UNSUPPORTED_MODIFIERS:
                    self._add_validation_error(
                        errors,
                        f"{field_spec}: unsupported modifier '{modifier}' "
                        f"({UNSUPPORTED_MODIFIERS[modifier]})",
                    )
                else:
                    self._add_validation_error(
                        errors, f"{field_spec}: unknown modifier '{modifier}'"
                    )
            return

        flag_modifiers = [m for m in modifiers if m in SUPPORTED_FLAG_MODIFIERS]
        if flag_modifiers and "re" not in modifiers:
            self._add_validation_error(
                errors,
                f"{field_spec}: regex flag modifier(s) {flag_modifiers} "
                "require 're'",
            )

        is_list = isinstance(values, list)
        value_list = values if is_list else [values]

        if "all" in modifiers and not is_list:
            self._add_validation_error(
                errors, f"{field_spec}: 'all' requires a list of values"
            )

        # ``exists`` is a presence check, not a value comparison.
        if "exists" in modifiers:
            if len(value_list) != 1 or not self._is_bool_value(value_list[0]):
                self._add_validation_error(
                    errors,
                    f"{field_spec}: 'exists' requires a single boolean value",
                )
            incompatible = {
                "contains", "startswith", "endswith", "re", "cidr",
                "base64", "base64offset", "wide", "utf16", "utf16le",
                "utf16be", "windash", "gt", "gte", "lt", "lte", "cased",
            }
            if incompatible.intersection(modifiers):
                self._add_validation_error(
                    errors,
                    f"{field_spec}: 'exists' cannot be combined with value "
                    "modifiers",
                )
            return

        # CIDR takes a network, so it cannot be combined with value transforms
        # or string matchers. ``all``/``neq`` operate on the value list and are
        # harmless.
        if "cidr" in modifiers:
            if set(modifiers) - {"cidr", "all", "neq"}:
                self._add_validation_error(
                    errors,
                    f"{field_spec}: 'cidr' is only supported alone "
                    "(plus 'all'/'neq')",
                )
            for value in value_list:
                try:
                    ipaddress.ip_network(str(value), strict=False)
                except ValueError:
                    self._add_validation_error(
                        errors, f"{field_spec}: invalid CIDR value {value!r}"
                    )
            return

        numeric = [m for m in modifiers if m in SUPPORTED_NUMERIC_MODIFIERS]
        if numeric:
            if len(set(numeric)) > 1:
                self._add_validation_error(
                    errors,
                    f"{field_spec}: multiple numeric comparison modifiers",
                )
            if {
                "contains", "startswith", "endswith", "re", "base64",
                "base64offset", "wide", "utf16", "utf16le", "utf16be",
                "windash", "cased",
            }.intersection(modifiers):
                self._add_validation_error(
                    errors,
                    f"{field_spec}: numeric comparisons cannot be combined "
                    "with string modifiers",
                )
            for value in value_list:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    self._add_validation_error(
                        errors,
                        f"{field_spec}: numeric comparison requires numeric "
                        f"values, got {value!r}",
                    )
            return

        # ``re`` must be the first modifier; only flag modifiers may follow.
        if "re" in modifiers:
            if modifiers[0] != "re":
                self._add_validation_error(
                    errors, f"{field_spec}: 're' must be the first modifier"
                )
            extra = [
                m for m in modifiers[1:] if m not in SUPPORTED_FLAG_MODIFIERS
            ]
            if extra:
                self._add_validation_error(
                    errors,
                    f"{field_spec}: 're' cannot be combined with {extra}",
                )
            if "cased" in modifiers:
                self._add_validation_error(
                    errors, f"{field_spec}: 're' cannot be combined with 'cased'"
                )
            for value in value_list:
                if not isinstance(value, str):
                    self._add_validation_error(
                        errors, f"{field_spec}: 're' requires string patterns"
                    )
                    continue
                if len(value) > REGEX_MAX_PATTERN_LENGTH:
                    self._add_validation_error(
                        errors,
                        f"{field_spec}: regex pattern exceeds "
                        f"{REGEX_MAX_PATTERN_LENGTH} characters",
                    )
                else:
                    _compile = getattr(_regex_engine, "compile", None)
                    if _compile is not None:
                        try:
                            _compile(value)
                        except _REGEX_ERROR as exc:
                            self._add_validation_error(
                                errors,
                                f"{field_spec}: invalid regex {value!r}: {exc}",
                            )
            return

        match_modifiers = [
            m for m in modifiers
            if m in ("contains", "startswith", "endswith")
        ]
        if len(match_modifiers) > 1:
            self._add_validation_error(
                errors,
                f"{field_spec}: multiple string match modifiers "
                f"{match_modifiers}",
            )

        # Value transformations are applied left-to-right; a matcher must come
        # after them (otherwise the transform would receive wildcards).
        seen_matcher = False
        for modifier in modifiers:
            if modifier in ("contains", "startswith", "endswith"):
                seen_matcher = True
            elif modifier in SUPPORTED_TRANSFORM_MODIFIERS and seen_matcher:
                self._add_validation_error(
                    errors,
                    f"{field_spec}: transformation '{modifier}' cannot follow "
                    "a match modifier",
                )

        if modifiers and modifiers[-1] in {
            "wide", "utf16", "utf16le", "utf16be",
        }:
            self._add_validation_error(
                errors,
                f"{field_spec}: encoding chain must not terminate with "
                f"'{modifiers[-1]}' (follow it with base64/base64offset or a "
                "match modifier)",
            )

        for modifier in modifiers:
            if modifier in ("base64", "base64offset"):
                for value in value_list:
                    if not isinstance(value, str):
                        self._add_validation_error(
                            errors,
                            f"{field_spec}: '{modifier}' requires string values",
                        )
                    elif "*" in value or "?" in value:
                        self._add_validation_error(
                            errors,
                            f"{field_spec}: '{modifier}' cannot encode "
                            f"wildcard value {value!r}",
                        )
            elif modifier in ("wide", "utf16", "utf16le", "utf16be"):
                for value in value_list:
                    if not isinstance(value, str):
                        self._add_validation_error(
                            errors,
                            f"{field_spec}: '{modifier}' requires string values",
                        )
                    elif not value.isascii():
                        self._add_validation_error(
                            errors,
                            f"{field_spec}: '{modifier}' requires ASCII input, "
                            f"got {value!r}",
                        )
            elif modifier == "windash":
                for value in value_list:
                    if not isinstance(value, str):
                        self._add_validation_error(
                            errors,
                            f"{field_spec}: 'windash' requires string values",
                        )
                        continue
                    count = len(_WINDASH_ELIGIBLE_RE.findall(value))
                    if count > WINDASH_MAX_EXPANSIONS:
                        self._add_validation_error(
                            errors,
                            f"{field_spec}: 'windash' expands {count} dashes "
                            f"(max {WINDASH_MAX_EXPANSIONS})",
                        )

    def _parse_mitre_tags(self):
        """Extract MITRE ATT&CK technique and tactic IDs from tags."""
        for tag in self.tags:
            tag_lower = tag.lower()
            if tag_lower.startswith("attack.t") and not tag_lower.startswith("attack.ta"):
                # Technique ID
                technique = tag_lower.replace("attack.", "").upper()
                self.mitre_techniques.append(technique)
            elif tag_lower.startswith("attack."):
                # Tactic name or ID
                tactic = tag_lower.replace("attack.", "")
                self.mitre_tactics.append(tactic)

    def _determine_platform(self) -> str:
        """Determine the target platform from log source."""
        product = self.log_product.lower() if self.log_product else ""
        if product in LOGSOURCE_PLATFORM_MAP:
            return LOGSOURCE_PLATFORM_MAP[product]
        # Check tags for OS
        for tag in self.tags:
            tl = tag.lower()
            if "windows" in tl:
                return "windows"
            if "linux" in tl:
                return "linux"
            if "macos" in tl:
                return "macos"
        return "generic"

    def matches(
        self, event: dict, context: Optional[SigmaScanContext] = None
    ) -> bool:
        """
        Test if an event matches this Sigma rule.

        Args:
            event: Normalized event dictionary with 'fields' and 'raw' keys.
            context: Optional scan context used to enforce the regex budget and
                collect diagnostics. When omitted, a throwaway context is
                created (single-call compatibility).

        Returns:
            True if the event matches the rule's detection logic.
        """
        ctx = context if context is not None else SigmaScanContext()
        if not self.valid:
            ctx.record_skipped_rule(
                self.id or self.title,
                "invalid_rule",
                "; ".join(self.validation_errors),
            )
            return False
        if not self.detection or not self.condition:
            return False

        try:
            return self._evaluate_condition(self.condition, event, ctx)
        except SigmaEvaluationError as exc:
            ctx.record_rule_error(self.id or self.title, exc)
            return False
        except (ValueError, TypeError, KeyError, OverflowError, re.error) as exc:
            ctx.record_rule_error(self.id or self.title, exc)
            return False
        except Exception as exc:
            # Record unexpected failures instead of silently treating them as
            # a normal non-match. One bad rule must not abort the whole scan.
            ctx.record_rule_error(self.id or self.title, exc, unexpected=True)
            _log_limiter.warning(
                "unexpected_rule_error",
                "Unexpected error evaluating Sigma rule %s: %s",
                self.id or self.title, exc,
            )
            return False

    def matches_line(
        self, line: str, context: Optional[SigmaScanContext] = None
    ) -> bool:
        """
        Test if a raw log line matches this rule.

        Args:
            line: Raw log line string.
            context: Optional scan context for diagnostics and regex budget.

        Returns:
            True if the line matches the rule.
        """
        ctx = context if context is not None else SigmaScanContext()
        if not self.valid:
            ctx.record_skipped_rule(
                self.id or self.title,
                "invalid_rule",
                "; ".join(self.validation_errors),
            )
            return False
        if not self.detection:
            return False

        event = {"raw": line, "fields": {}}
        try:
            if self.condition:
                return self._evaluate_condition(self.condition, event, ctx)
            return self._keyword_match(line)
        except SigmaEvaluationError as exc:
            ctx.record_rule_error(self.id or self.title, exc)
            return False
        except (ValueError, TypeError, KeyError, OverflowError, re.error) as exc:
            ctx.record_rule_error(self.id or self.title, exc)
            return False
        except Exception as exc:
            ctx.record_rule_error(self.id or self.title, exc, unexpected=True)
            _log_limiter.warning(
                "unexpected_rule_error",
                "Unexpected error evaluating Sigma rule %s on a raw line: %s",
                self.id or self.title, exc,
            )
            return False

    def _keyword_match(self, line: str) -> bool:
        """Simple keyword matching fallback for rules with 'keywords' selection."""
        line_lower = line.lower()
        for sel_name, sel_data in self.detection.items():
            if sel_name == "condition":
                continue
            if isinstance(sel_data, list):
                # List of keywords — check if any match
                for keyword in sel_data:
                    if isinstance(keyword, str) and keyword.lower() in line_lower:
                        return True
            elif isinstance(sel_data, dict):
                # Check field values
                for field, values in sel_data.items():
                    if field == "condition":
                        continue
                    field_parts = field.split("|")
                    if isinstance(values, list):
                        for val in values:
                            if isinstance(val, str) and val.lower() in line_lower:
                                return True
                    elif isinstance(values, str) and values.lower() in line_lower:
                        return True
        return False

    def _evaluate_condition(
        self,
        condition: str,
        event: dict,
        context: Optional[SigmaScanContext] = None,
    ) -> bool:
        """
        Evaluate a Sigma condition expression against an event.

        Supports: selection references, and, or, not, 1 of, all of,
        parentheses grouping.

        Args:
            condition: Sigma condition string.
            event: Normalized event dictionary.
            context: Optional scan context for regex budget and diagnostics.

        Returns:
            True if the condition is satisfied.
        """
        condition = condition.strip()

        # Handle 'all of <prefix>*' — anchored so trailing logic is not dropped,
        # and an empty selection set must NOT vacuously match everything.
        all_of_match = re.fullmatch(r"all of (\w+)\*", condition)
        if all_of_match:
            prefix = all_of_match.group(1)
            selections = [
                name for name in self.detection
                if name != "condition" and name.startswith(prefix)
            ]
            if not selections:
                return False
            return all(
                self._evaluate_selection(name, event, context)
                for name in selections
            )

        # Handle '1 of <prefix>*'
        one_of_match = re.fullmatch(r"1 of (\w+)\*", condition)
        if one_of_match:
            prefix = one_of_match.group(1)
            selections = [
                name for name in self.detection
                if name != "condition" and name.startswith(prefix)
            ]
            if not selections:
                return False
            return any(
                self._evaluate_selection(name, event, context)
                for name in selections
            )

        # Handle 'all of them'
        if condition == "all of them":
            selections = [name for name in self.detection if name != "condition"]
            if not selections:
                return False
            return all(
                self._evaluate_selection(name, event, context)
                for name in selections
            )

        # Handle '1 of them'
        if condition == "1 of them":
            selections = [name for name in self.detection if name != "condition"]
            if not selections:
                return False
            return any(
                self._evaluate_selection(name, event, context)
                for name in selections
            )

        # Parse compound conditions with and/or/not
        return self._parse_compound_condition(condition, event, context)

    def _parse_compound_condition(
        self,
        condition: str,
        event: dict,
        context: Optional[SigmaScanContext] = None,
    ) -> bool:
        """
        Parse compound conditions with and/or/not operators.

        Args:
            condition: Condition string.
            event: Event dictionary.

        Returns:
            Boolean result.
        """
        # Tokenize
        tokens = self._tokenize_condition(condition)
        if not tokens:
            return False

        try:
            result, _ = self._parse_or_expr(tokens, 0, event, context)
            return result
        except (IndexError, ValueError):
            # Fallback: try as a simple selection name
            if condition in self.detection and condition != "condition":
                return self._evaluate_selection(condition, event, context)
            return False

    def _tokenize_condition(self, condition: str) -> List[str]:
        """Tokenize a Sigma condition string."""
        tokens = []
        i = 0
        while i < len(condition):
            if condition[i].isspace():
                i += 1
                continue
            if condition[i] == "(":
                tokens.append("(")
                i += 1
            elif condition[i] == ")":
                tokens.append(")")
                i += 1
            else:
                # Read a word
                j = i
                while j < len(condition) and not condition[j].isspace() and condition[j] not in "()":
                    j += 1
                word = condition[i:j]
                tokens.append(word)
                i = j
        return tokens

    def _parse_or_expr(
        self,
        tokens: List[str],
        pos: int,
        event: dict,
        context: Optional[SigmaScanContext] = None,
    ) -> Tuple[bool, int]:
        """Parse OR expression."""
        left, pos = self._parse_and_expr(tokens, pos, event, context)
        while pos < len(tokens) and tokens[pos].lower() == "or":
            pos += 1
            right, pos = self._parse_and_expr(tokens, pos, event, context)
            left = left or right
        return left, pos

    def _parse_and_expr(
        self,
        tokens: List[str],
        pos: int,
        event: dict,
        context: Optional[SigmaScanContext] = None,
    ) -> Tuple[bool, int]:
        """Parse AND expression."""
        left, pos = self._parse_not_expr(tokens, pos, event, context)
        while pos < len(tokens) and tokens[pos].lower() == "and":
            pos += 1
            right, pos = self._parse_not_expr(tokens, pos, event, context)
            left = left and right
        return left, pos

    def _parse_not_expr(
        self,
        tokens: List[str],
        pos: int,
        event: dict,
        context: Optional[SigmaScanContext] = None,
    ) -> Tuple[bool, int]:
        """Parse NOT expression."""
        if pos < len(tokens) and tokens[pos].lower() == "not":
            pos += 1
            result, pos = self._parse_primary(tokens, pos, event, context)
            return not result, pos
        return self._parse_primary(tokens, pos, event, context)

    def _parse_primary(
        self,
        tokens: List[str],
        pos: int,
        event: dict,
        context: Optional[SigmaScanContext] = None,
    ) -> Tuple[bool, int]:
        """Parse primary expression (selection name or parenthesized expression)."""
        if pos >= len(tokens):
            return False, pos

        token = tokens[pos]

        if token == "(":
            pos += 1
            result, pos = self._parse_or_expr(tokens, pos, event, context)
            if pos < len(tokens) and tokens[pos] == ")":
                pos += 1
            return result, pos

        # Handle "1 of selection*" or "all of selection*"
        if token in ("1", "all"):
            if pos + 2 < len(tokens) and tokens[pos + 1].lower() == "of":
                quantifier = token
                pos += 2  # skip "of"
                target = tokens[pos]
                pos += 1

                if target == "them":
                    selections = [n for n in self.detection if n != "condition"]
                elif target.endswith("*"):
                    prefix = target[:-1]
                    selections = [n for n in self.detection if n != "condition" and n.startswith(prefix)]
                else:
                    selections = [target]

                if not selections:
                    return False, pos

                if quantifier == "all":
                    return all(
                        self._evaluate_selection(s, event, context)
                        for s in selections
                    ), pos
                else:
                    return any(
                        self._evaluate_selection(s, event, context)
                        for s in selections
                    ), pos

        # Simple selection name
        pos += 1
        if token in self.detection and token != "condition":
            return self._evaluate_selection(token, event, context), pos
        return False, pos

    def _evaluate_selection(
        self,
        selection_name: str,
        event: dict,
        context: Optional[SigmaScanContext] = None,
    ) -> bool:
        """
        Evaluate a single Sigma selection against an event.

        Args:
            selection_name: Name of the detection selection.
            event: Event dictionary.
            context: Optional scan context for regex budget and diagnostics.

        Returns:
            True if the selection matches.
        """
        selection = self.detection.get(selection_name)
        if selection is None:
            return False

        # List of keywords/strings
        if isinstance(selection, list):
            raw = str(event.get("raw", "")).lower()
            return any(str(kw).lower() in raw for kw in selection if isinstance(kw, str))

        # Dictionary of field conditions
        if isinstance(selection, dict):
            return self._evaluate_field_selection(selection, event, context)

        return False

    def _evaluate_field_selection(
        self,
        selection: dict,
        event: dict,
        context: Optional[SigmaScanContext] = None,
    ) -> bool:
        """
        Evaluate field-based selection conditions.

        Args:
            selection: Dictionary of field -> value conditions.
            event: Event dictionary.
            context: Optional scan context for regex budget and diagnostics.

        Returns:
            True if all field conditions match.
        """
        fields = event.get("fields", {}) or {}
        raw = str(event.get("raw", ""))
        # Case-insensitive field index so rules that use Windows-style names
        # (EventID, Image) still resolve against normalised events.
        lowered = {str(k).lower(): v for k, v in fields.items()}

        for field_spec, expected_values in selection.items():
            field_parts = field_spec.split("|")
            field_name = field_parts[0]
            modifiers = field_parts[1:] if len(field_parts) > 1 else []

            is_list = isinstance(expected_values, list)
            value_list = expected_values if is_list else [expected_values]
            present, field_value = self._resolve_field(
                field_name, event, lowered, raw
            )

            if "exists" in modifiers:
                expected = value_list[0]
                expected_bool = (
                    expected
                    if isinstance(expected, bool)
                    else str(expected).lower() == "true"
                )
                matched = present == expected_bool
            elif not present or field_value is None or field_value == "":
                # A named field absent from the event must NOT match. Falling
                # back to the raw line would turn field-scoped rules into
                # unscoped keyword rules and cause false positives.
                matched = False
            else:
                matcher_modifiers = [m for m in modifiers if m != "neq"]
                if "all" in modifiers:
                    matched = all(
                        self._match_with_modifiers(
                            field_value, val, matcher_modifiers, context
                        )
                        for val in value_list
                    )
                else:
                    matched = any(
                        self._match_with_modifiers(
                            field_value, val, matcher_modifiers, context
                        )
                        for val in value_list
                    )

            if "neq" in modifiers:
                matched = not matched
            if not matched:
                return False

        return True

    @staticmethod
    def _resolve_field(
        field_name: str, event: dict, lowered: Dict[str, Any], raw: str
    ) -> Tuple[bool, Any]:
        """Resolve a field's presence and value (case-insensitive aliases)."""
        name = field_name.lower()
        if name == "keywords":
            return bool(raw), raw
        if name in ("eventid", "event_id"):
            value = event.get("event_id")
            if value is not None and value != "":
                return True, value
            if "eventid" in lowered or "event_id" in lowered:
                value = lowered.get("eventid", lowered.get("event_id"))
                return value is not None, value
            return False, ""
        if name in lowered:
            value = lowered[name]
            return value is not None, value
        return False, ""

    @staticmethod
    def _glob_match(
        pattern: str, text: str, case_sensitive: bool = False
    ) -> bool:
        """
        Sigma default string matching: equality with ``*`` and ``?`` wildcards
        (all other regex metacharacters are literal). Case-insensitive unless
        the ``cased`` modifier is present.
        """
        if pattern == "":
            return text == ""
        parts = []
        for ch in pattern:
            if ch == "*":
                parts.append(".*")
            elif ch == "?":
                parts.append(".")
            else:
                parts.append(re.escape(ch))
        flags = re.DOTALL | (0 if case_sensitive else re.IGNORECASE)
        try:
            return re.fullmatch("".join(parts), text, flags) is not None
        except re.error:
            return False

    def _match_with_modifiers(
        self,
        field_value: Any,
        test_value: Any,
        modifiers: List[str],
        context: Optional[SigmaScanContext] = None,
    ) -> bool:
        """
        Match a field value against a test value using Sigma modifiers.

        Supported value modifiers: contains/startswith/endswith, re (+ i/m/s),
        base64/base64offset, wide/utf16/utf16le/utf16be, windash, cidr,
        cased, exists (handled at field level), all/neq (field level), and
        gt/gte/lt/lte. Unsupported modifiers are rejected during validation.
        """
        if test_value is None:
            return field_value is None or field_value == ""

        field_str = str(field_value)
        test_str = str(test_value)

        if "exists" in modifiers:
            # Defensive: existence is resolved before value matching.
            return False

        if any(m in SUPPORTED_NUMERIC_MODIFIERS for m in modifiers):
            return self._numeric_compare(field_value, test_value, modifiers)

        # ── cidr: match if any IP in the field is inside the network ──
        if "cidr" in modifiers:
            try:
                network = ipaddress.ip_network(test_str, strict=False)
                for candidate in re.findall(r"[0-9A-Fa-f:.]+", field_str):
                    try:
                        if ipaddress.ip_address(candidate) in network:
                            return True
                    except ValueError:
                        continue
            except ValueError:
                return False
            return False

        # ── Apply encoding/expansion modifiers in declared order ──
        transform_modifiers = [
            m for m in modifiers
            if m not in ({"cased"} | SUPPORTED_LIST_MODIFIERS)
        ]
        candidates = self._expand_value(test_str, transform_modifiers)

        cased = "cased" in modifiers

        # Regex flags: Sigma's ``re`` modifier is case-sensitive by default;
        # the ``i``/``ignorecase`` flag opts into case-insensitive matching.
        re_flags = 0
        if _regex_engine is not None:
            if any(m in modifiers for m in ("i", "ignorecase")):
                re_flags |= _regex_engine.IGNORECASE
            if any(m in modifiers for m in ("m", "multiline")):
                re_flags |= _regex_engine.MULTILINE
            if any(m in modifiers for m in ("s", "dotall")):
                re_flags |= _regex_engine.DOTALL

        for cand in candidates:
            if "re" in modifiers:
                if self._regex_match(cand, field_str, re_flags, context):
                    return True
            elif "contains" in modifiers:
                if self._contains(cand, field_str, cased):
                    return True
            elif "startswith" in modifiers:
                if self._startswith(cand, field_str, cased):
                    return True
            elif "endswith" in modifiers:
                if self._endswith(cand, field_str, cased):
                    return True
            else:
                # Default Sigma semantics: equality with ``*``/``?`` wildcard
                # support (NOT substring matching).
                if self._glob_match(cand, field_str, cased):
                    return True

        return False

    @staticmethod
    def _numeric_compare(
        field_value: Any, test_value: Any, modifiers: List[str]
    ) -> bool:
        try:
            left = float(field_value)
            right = float(test_value)
        except (TypeError, ValueError, OverflowError):
            return False
        if "gt" in modifiers:
            return left > right
        if "gte" in modifiers:
            return left >= right
        if "lt" in modifiers:
            return left < right
        if "lte" in modifiers:
            return left <= right
        return False

    @staticmethod
    def _contains(needle: str, haystack: str, cased: bool) -> bool:
        if cased:
            return needle in haystack
        return needle.lower() in haystack.lower()

    @staticmethod
    def _startswith(prefix: str, text: str, cased: bool) -> bool:
        if cased:
            return text.startswith(prefix)
        return text.lower().startswith(prefix.lower())

    @staticmethod
    def _endswith(suffix: str, text: str, cased: bool) -> bool:
        if cased:
            return text.endswith(suffix)
        return text.lower().endswith(suffix.lower())

    @staticmethod
    def _chunked_encode(value: str, encoder) -> str:
        """
        Apply ``encoder`` to each wildcard-free chunk of ``value``.

        Sigma wildcards (``*`` / ``?``) are special characters and are copied
        verbatim rather than being fed through an encoding transform, mirroring
        pySigma's per-part handling of ``wide``/``utf16*``.
        """
        out: List[str] = []
        buf: List[str] = []
        for ch in value:
            if ch in ("*", "?"):
                if buf:
                    out.append(encoder("".join(buf)))
                    buf = []
                out.append(ch)
            else:
                buf.append(ch)
        if buf:
            out.append(encoder("".join(buf)))
        return "".join(out)

    @staticmethod
    def _base64_input_bytes(value: str, utf16_applied: bool) -> bytes:
        """
        Byte sequence fed to the base64 modifiers.

        Mirrors pySigma's ``_base64_input_bytes``: after the ``utf16`` modifier
        the leading U+FEFF is a UTF-16LE BOM (``FF FE``) rather than its UTF-8
        encoding (``EF BB BF``).
        """
        data = value.encode("utf-8")
        if utf16_applied and data.startswith(b"\xef\xbb\xbf"):
            data = b"\xff\xfe" + data[3:]
        return data

    @classmethod
    def _expand_value(cls, test_value: str, modifiers: List[str]) -> List[str]:
        """
        Apply Sigma value/encoding modifiers in declared order.

        Only value-transforming modifiers (``wide``, ``utf16le``, ``utf16be``,
        ``utf16``, ``base64``, ``base64offset``, ``windash``) are handled here;
        matching modifiers (``contains``/``startswith``/``endswith``/``re``)
        are applied by the caller. Returns the list of candidate strings; some
        modifiers (``base64offset``, ``windash``) expand to several.

        The transformations follow the official Sigma semantics:
          * ``wide`` == ``utf16le`` (UTF-16 little-endian, no BOM)
          * ``utf16be``  (UTF-16 big-endian, no BOM)
          * ``utf16``    (UTF-16LE with a leading BOM)
          * ``base64offset`` produces all three byte-alignment variants.
        """
        candidates = [test_value]
        utf16_applied = False

        for modifier in modifiers:
            if modifier in ("wide", "utf16le", "utf16be", "utf16"):
                codec = "utf-16-be" if modifier == "utf16be" else "utf-16-le"
                expanded: List[str] = []
                for cand in candidates:
                    try:
                        encoded = cls._chunked_encode(
                            cand, lambda s, c=codec: s.encode(c).decode("utf-8")
                        )
                    except UnicodeDecodeError:
                        # pySigma rejects non-ASCII input for these modifiers.
                        _log_limiter.warning(
                            "encoding_non_ascii",
                            "Sigma '%s' modifier requires ASCII input; value %r skipped",
                            modifier, _short(cand),
                        )
                        continue
                    if modifier == "utf16":
                        encoded = "\ufeff" + encoded
                        utf16_applied = True
                    if encoded:
                        expanded.append(encoded)
                candidates = expanded

            elif modifier in ("base64", "base64offset"):
                expanded = []
                for cand in candidates:
                    if "*" in cand or "?" in cand:
                        # pySigma rejects base64 encoding of wildcard values.
                        _log_limiter.warning(
                            "encoding_wildcard",
                            "Sigma '%s' modifier cannot encode wildcard value %r",
                            modifier, _short(cand),
                        )
                        continue
                    data = cls._base64_input_bytes(cand, utf16_applied)
                    if modifier == "base64":
                        # Keep RFC 4648 padding: ``base64`` is an exact-value
                        # transformation in Sigma. Rules that match an encoded
                        # fragment must add ``|contains`` explicitly.
                        encoded = base64.b64encode(data).decode("ascii")
                        if encoded:
                            expanded.append(encoded)
                    else:
                        # Three byte-alignment variants (pySigma offsets).
                        start_offsets = (0, 2, 3)
                        end_offsets = (None, -3, -2)
                        for i in range(3):
                            chunk = base64.b64encode(b" " * i + data)[
                                start_offsets[i]:end_offsets[(len(data) + i) % 3]
                            ].decode("ascii")
                            if chunk:
                                expanded.append(chunk)
                candidates = expanded

            elif modifier == "windash":
                expanded = []
                for cand in candidates:
                    # Only dashes/slashes at a parameter-like position are
                    # expanded (``\B[-/]\b``), so ``a-b`` is left untouched.
                    positions = [
                        m.start()
                        for m in _WINDASH_ELIGIBLE_RE.finditer(cand)
                    ]
                    if not positions:
                        expanded.append(cand)
                        continue
                    if len(positions) > WINDASH_MAX_EXPANSIONS:
                        # Bound the expansion instead of producing an
                        # exponential number of candidates.
                        _log_limiter.warning(
                            "windash_expansion_skipped",
                            "Sigma 'windash' value %r has %d eligible "
                            "separators (max %d); expansion skipped",
                            _short(cand), len(positions), WINDASH_MAX_EXPANSIONS,
                        )
                        expanded.append(cand)
                        continue
                    for combo in product(_WINDASH_VARIANTS, repeat=len(positions)):
                        chars = list(cand)
                        for idx, replacement in zip(positions, combo):
                            chars[idx] = replacement
                        expanded.append("".join(chars))
                candidates = expanded

        return candidates

    @staticmethod
    def _regex_match(
        pattern: str,
        text: str,
        flags: int,
        context: Optional[SigmaScanContext] = None,
    ) -> bool:
        """
        Evaluate the ``re`` modifier under the scan-scoped budget and a hard
        per-operation timeout.

        Uses the ``regex`` package, whose ``timeout`` argument bounds
        catastrophic backtracking (unlike the stdlib ``re`` engine). If that
        package is unavailable the pattern is skipped rather than executed
        with the unbounded engine. The full subject is evaluated up to
        ``max_subject_length``; larger inputs are reported as incomplete rather
        than silently truncated.
        """
        ctx = context if context is not None else SigmaScanContext()

        if len(pattern) > REGEX_MAX_PATTERN_LENGTH:
            _log_limiter.warning(
                "regex_pattern_too_long",
                "Sigma 're' pattern exceeds %d characters; skipped",
                REGEX_MAX_PATTERN_LENGTH,
            )
            ctx.record_pattern_too_long(len(pattern))
            return False

        if _regex_engine is None:
            _log_limiter.error(
                "regex_missing_engine",
                "Sigma 're' modifier requires the 'regex' package for bounded "
                "execution; pattern %r skipped (install 'regex')",
                _short(pattern),
            )
            ctx.record_missing_engine(pattern)
            return False

        if len(text) > ctx.max_subject_length:
            # Do not truncate: a match could live in the discarded tail, so
            # report the evaluation as incomplete instead.
            _log_limiter.warning(
                "regex_oversized_subject",
                "Sigma 're' subject length %d exceeds limit %d; evaluation "
                "recorded as incomplete (no truncation)",
                len(text), ctx.max_subject_length,
            )
            ctx.record_oversized_subject(len(text))
            return False

        reason = ctx.regex_budget_reason()
        if reason is not None:
            ctx.record_budget_exhausted(reason)
            return False

        timeout = ctx.effective_timeout()
        if timeout <= 0:
            ctx.record_budget_exhausted("elapsed_time")
            return False

        ctx.regex_evaluations += 1
        start = time.perf_counter()
        try:
            return _regex_engine.search(
                pattern, text, flags, timeout=timeout
            ) is not None
        except TimeoutError:
            _log_limiter.warning(
                "regex_timeout",
                "Sigma 're' pattern %r exceeded the %.3fs timeout; treated "
                "as no-match (evaluation incomplete)",
                _short(pattern), timeout,
            )
            ctx.record_timeout(pattern)
            return False
        except _REGEX_ERROR:
            _log_limiter.warning(
                "regex_invalid_pattern",
                "Sigma 're' pattern %r is invalid; treated as no-match",
                _short(pattern),
            )
            ctx.record_invalid_pattern(pattern)
            return False
        finally:
            ctx.regex_elapsed_seconds += time.perf_counter() - start

    def to_dict(self) -> dict:
        """Serialize the rule to a dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "level": self.level,
            "weight": self.weight,
            "status": self.status,
            "author": self.author,
            "platform": self.platform,
            "log_category": self.log_category,
            "log_product": self.log_product,
            "log_service": self.log_service,
            "mitre_techniques": self.mitre_techniques,
            "mitre_tactics": self.mitre_tactics,
            "tags": self.tags,
            "source_file": self.source_file,
        }


class SigmaEngine:
    """
    Full SigmaHQ rule engine for loading, managing, and matching
    Sigma detection rules against log events.
    """

    def __init__(self, rules_dir: Optional[str] = None):
        """
        Initialize the Sigma engine.

        Args:
            rules_dir: Directory containing Sigma YAML rules. Defaults to config.
        """
        # Always initialise the rule store and stats, even when the optional
        # YAML dependency is missing, so callers (get_stats, match_event,
        # new_scan_context) behave consistently instead of raising.
        if rules_dir:
            self.rules_dir = Path(rules_dir)
        else:
            try:
                from config import SIGMA_RULES_DIR
                self.rules_dir = Path(SIGMA_RULES_DIR)
            except Exception:  # pragma: no cover - config import failure
                self.rules_dir = Path("sigma_rules")

        self.rules: List[SigmaRule] = []
        self.rules_by_id: Dict[str, SigmaRule] = {}
        self.rules_by_technique: Dict[str, List[SigmaRule]] = defaultdict(list)
        self.rules_by_platform: Dict[str, List[SigmaRule]] = defaultdict(list)
        self.rules_by_level: Dict[str, List[SigmaRule]] = defaultdict(list)
        self.rules_by_category: Dict[str, List[SigmaRule]] = defaultdict(list)
        self.invalid_rules: List[dict] = []

        self._stats = {
            "total_loaded": 0,
            "failed": 0,
            "invalid": 0,
            "by_platform": defaultdict(int),
            "by_level": defaultdict(int),
        }

        self.available = bool(YAML_AVAILABLE)
        self.load_status = "not_loaded"
        if not self.available:
            # Explicit unavailable-dependency state: no rules are loaded and
            # nothing will be evaluated, but stats/reporting remain safe.
            self.load_status = "yaml_unavailable"
            logger.warning(
                "PyYAML not installed — Sigma engine disabled (no rules loaded)."
            )

    def new_scan_context(self, **kwargs) -> SigmaScanContext:
        """Create a fresh, isolated context for one analysis/scan."""
        return SigmaScanContext(**kwargs)

    def load_rules(self, recursive: bool = True) -> int:
        """
        Load all Sigma rules from the rules directory.

        Args:
            recursive: Whether to search subdirectories recursively.

        Returns:
            Number of rules successfully loaded.
        """
        if not self.available:
            # Dependency unavailable: report explicitly rather than as "0 rules".
            self.load_status = "yaml_unavailable"
            return 0

        if not self.rules_dir.exists():
            self.load_status = "rules_dir_missing"
            logger.warning(f"Sigma rules directory not found: {self.rules_dir}")
            return 0

        glob_pattern = "**/*.yml" if recursive else "*.yml"
        yaml_files = list(self.rules_dir.glob(glob_pattern))
        yaml_files.extend(self.rules_dir.glob("**/*.yaml" if recursive else "*.yaml"))

        logger.info(f"Found {len(yaml_files)} Sigma rule files in {self.rules_dir}")

        for yml_path in yaml_files:
            try:
                self._load_rule_file(yml_path)
            except Exception as e:
                _log_limiter.debug(
                    "rule_load_failed", "Failed to load %s: %s", yml_path, e,
                )
                self._stats["failed"] += 1

        self.load_status = "ok"
        logger.info(
            f"Loaded {self._stats['total_loaded']} Sigma rules "
            f"({self._stats['failed']} failed, {self._stats['invalid']} invalid)"
        )
        return self._stats["total_loaded"]

    def _load_rule_file(self, filepath: Path):
        """
        Load and parse a single Sigma YAML rule file.

        Handles multi-document YAML files (multiple rules in one file).

        Args:
            filepath: Path to the YAML file.
        """
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        # Handle multi-document YAML
        documents = list(yaml.safe_load_all(content))

        for doc in documents:
            if not isinstance(doc, dict):
                continue
            if "detection" not in doc:
                continue

            try:
                rule = SigmaRule(doc, source_file=str(filepath))
                self._register_rule(rule)
                self._stats["total_loaded"] += 1
                self._stats["by_platform"][rule.platform] += 1
                self._stats["by_level"][rule.level] += 1
                if not rule.valid:
                    self._stats["invalid"] += 1
                    self.invalid_rules.append({
                        "rule_id": rule.id,
                        "title": rule.title,
                        "source_file": rule.source_file,
                        "errors": list(rule.validation_errors),
                    })
                    _log_limiter.warning(
                        "invalid_rule",
                        "Sigma rule %s is invalid and will be skipped: %s",
                        rule.id or rule.title,
                        "; ".join(rule.validation_errors),
                    )
            except Exception as e:
                _log_limiter.debug(
                    "rule_parse_failed",
                    "Failed to parse rule in %s: %s", filepath, e,
                )
                self._stats["failed"] += 1

    def _register_rule(self, rule: SigmaRule):
        """Register a rule in all lookup indexes."""
        self.rules.append(rule)

        if rule.id:
            self.rules_by_id[rule.id] = rule

        for technique in rule.mitre_techniques:
            self.rules_by_technique[technique].append(rule)

        self.rules_by_platform[rule.platform].append(rule)
        self.rules_by_level[rule.level].append(rule)
        self.rules_by_category[rule.log_category or "generic"].append(rule)

    def match_event(
        self, event: dict, context: Optional[SigmaScanContext] = None
    ) -> List[dict]:
        """
        Match a single event against all loaded Sigma rules.

        Args:
            event: Normalized event dictionary.
            context: Optional scan context shared across the whole analysis.

        Returns:
            List of matching rule results.
        """
        ctx = context if context is not None else SigmaScanContext()
        matches = []
        for rule in self.rules:
            try:
                if rule.matches(event, ctx):
                    matches.append({
                        "rule_id": rule.id,
                        "title": rule.title,
                        "description": rule.description,
                        "level": rule.level,
                        "weight": rule.weight,
                        "mitre_techniques": rule.mitre_techniques,
                        "mitre_tactics": rule.mitre_tactics,
                        "platform": rule.platform,
                        "source_file": rule.source_file,
                    })
            except SigmaEvaluationError as exc:
                ctx.record_rule_error(rule.id or rule.title, exc)
            except Exception as exc:
                ctx.record_rule_error(rule.id or rule.title, exc, unexpected=True)
        return matches

    def match_line(
        self, line: str, context: Optional[SigmaScanContext] = None
    ) -> List[dict]:
        """
        Match a raw log line against all loaded Sigma rules.

        Args:
            line: Raw log line string.
            context: Optional scan context shared across the whole analysis.

        Returns:
            List of matching rule results.
        """
        ctx = context if context is not None else SigmaScanContext()
        matches = []
        for rule in self.rules:
            try:
                if rule.matches_line(line, ctx):
                    matches.append({
                        "rule_id": rule.id,
                        "title": rule.title,
                        "description": rule.description,
                        "level": rule.level,
                        "weight": rule.weight,
                        "mitre_techniques": rule.mitre_techniques,
                        "platform": rule.platform,
                    })
            except SigmaEvaluationError as exc:
                ctx.record_rule_error(rule.id or rule.title, exc)
            except Exception as exc:
                ctx.record_rule_error(rule.id or rule.title, exc, unexpected=True)
        return matches

    def get_coverage_matrix(self) -> Dict[str, Dict[str, int]]:
        """
        Generate MITRE ATT&CK coverage matrix.

        Returns:
            Dictionary mapping tactics to techniques with rule counts.
        """
        coverage = defaultdict(lambda: defaultdict(int))
        for rule in self.rules:
            for technique in rule.mitre_techniques:
                for tactic in rule.mitre_tactics:
                    coverage[tactic][technique] += 1
        return dict(coverage)

    def get_stats(
        self, scan_context: Optional[SigmaScanContext] = None
    ) -> dict:
        """Get loading statistics.

        Args:
            scan_context: Optional context from a completed scan. When given,
                its diagnostics (regex budget/timeouts, oversized subjects,
                skipped rules, evaluation errors, incomplete flag) are added
                under the ``"scan"`` key so callers can surface them.
        """
        stats = {
            "available": self.available,
            "yaml_available": bool(YAML_AVAILABLE),
            "load_status": self.load_status,
            "total_rules": len(self.rules),
            "loaded": self._stats["total_loaded"],
            "failed": self._stats["failed"],
            "invalid": self._stats["invalid"],
            "invalid_rules": list(self.invalid_rules),
            "by_platform": dict(self._stats["by_platform"]),
            "by_level": dict(self._stats["by_level"]),
            "by_category": {k: len(v) for k, v in self.rules_by_category.items()},
            "mitre_techniques_covered": len(self.rules_by_technique),
            "log_limiter": _log_limiter.stats(),
        }
        if scan_context is not None:
            stats["scan"] = scan_context.summary()
        return stats

    def search_rules(
        self,
        query: str = "",
        platform: str = "",
        level: str = "",
        technique: str = "",
    ) -> List[dict]:
        """
        Search rules by title, platform, level, or MITRE technique.

        Args:
            query: Text to search in title/description.
            platform: Filter by platform.
            level: Filter by severity level.
            technique: Filter by MITRE technique ID.

        Returns:
            List of matching rule dictionaries.
        """
        results = []
        for rule in self.rules:
            if query and query.lower() not in (rule.title + rule.description).lower():
                continue
            if platform and rule.platform != platform:
                continue
            if level and rule.level != level:
                continue
            if technique and technique.upper() not in [t.upper() for t in rule.mitre_techniques]:
                continue
            results.append(rule.to_dict())
        return results
