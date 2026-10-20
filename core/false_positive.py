"""
ThreatScope V2 — False Positive Suppressor
Author: 0xSABRY

Machine-learning-based false positive identification that learns which
alerts are noise in a given environment and suppresses them automatically.
"""

import json
import logging
from pathlib import Path
from collections import Counter, defaultdict
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger("threatscope.fp_suppressor")


class FalsePositiveSuppressor:
    """
    Learns and suppresses false positive alerts based on historical
    analyst feedback and statistical patterns.
    
    Uses a frequency-based approach:
    - Tracks how often each rule+context combination fires
    - Tracks analyst dismissals (marked as FP)
    - Calculates FP probability and auto-suppresses high-probability FPs
    """

    def __init__(self, model_path: Optional[str] = None, threshold: float = 0.85):
        """
        Initialize the FP suppressor.

        Args:
            model_path: Path to the persistent FP model file.
            threshold: Confidence threshold for auto-suppression (0.0-1.0).
        """
        if model_path:
            self.model_path = Path(model_path)
        else:
            from config import DATA_DIR
            self.model_path = DATA_DIR / "fp_model.json"
        self.threshold = threshold

        # Model data
        self.rule_fp_counts: Dict[str, int] = Counter()
        self.rule_total_counts: Dict[str, int] = Counter()
        self.context_fp_counts: Dict[str, int] = Counter()
        self.whitelisted_patterns: List[str] = []
        self.suppressed_count = 0

        self._load_model()

    def _load_model(self):
        """Load the FP model from disk."""
        if self.model_path.exists():
            try:
                with open(self.model_path, "r") as f:
                    data = json.load(f)
                self.rule_fp_counts = Counter(data.get("rule_fp_counts", {}))
                self.rule_total_counts = Counter(data.get("rule_total_counts", {}))
                self.context_fp_counts = Counter(data.get("context_fp_counts", {}))
                self.whitelisted_patterns = data.get("whitelisted", [])
                logger.info(f"FP model loaded: {len(self.rule_fp_counts)} rule patterns")
            except Exception as e:
                logger.warning(f"Failed to load FP model: {e}")

    def save_model(self):
        """Persist the FP model to disk."""
        try:
            data = {
                "rule_fp_counts": dict(self.rule_fp_counts),
                "rule_total_counts": dict(self.rule_total_counts),
                "context_fp_counts": dict(self.context_fp_counts),
                "whitelisted": self.whitelisted_patterns,
            }
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.model_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save FP model: {e}")

    def record_feedback(self, rule_id: str, is_false_positive: bool,
                        context_key: str = ""):
        """
        Record analyst feedback on an alert.

        Args:
            rule_id: ID of the rule that generated the alert.
            is_false_positive: Whether the analyst marked it as FP.
            context_key: Additional context (e.g., source IP, hostname).
        """
        self.rule_total_counts[rule_id] += 1
        if is_false_positive:
            self.rule_fp_counts[rule_id] += 1
            if context_key:
                self.context_fp_counts[f"{rule_id}:{context_key}"] += 1
        self.save_model()

    def get_fp_probability(self, rule_id: str, context_key: str = "") -> float:
        """
        Calculate the false positive probability for a rule.

        Args:
            rule_id: Rule identifier.
            context_key: Additional context.

        Returns:
            FP probability between 0.0 and 1.0.
        """
        total = self.rule_total_counts.get(rule_id, 0)
        if total < 5:
            return 0.0  # Not enough data

        fp_count = self.rule_fp_counts.get(rule_id, 0)
        base_prob = fp_count / total

        # Boost probability if context also matches
        if context_key:
            ctx_key = f"{rule_id}:{context_key}"
            ctx_count = self.context_fp_counts.get(ctx_key, 0)
            if ctx_count > 3:
                base_prob = min(1.0, base_prob * 1.2)

        return round(base_prob, 3)

    def should_suppress(self, rule_id: str, context_key: str = "") -> Tuple[bool, float]:
        """
        Determine if an alert should be suppressed.

        Args:
            rule_id: Rule identifier.
            context_key: Additional context.

        Returns:
            Tuple of (should_suppress, fp_probability).
        """
        prob = self.get_fp_probability(rule_id, context_key)
        suppress = prob >= self.threshold
        if suppress:
            self.suppressed_count += 1
        return suppress, prob

    def _matches_whitelist(self, finding: dict) -> bool:
        """Return True if the finding matches any operator-supplied whitelist pattern."""
        if not self.whitelisted_patterns:
            return False
        haystack = " ".join(
            str(finding.get(key, ""))
            for key in ("raw", "title", "description", "category", "rule_id")
        ).lower()
        return any(p and p.lower() in haystack for p in self.whitelisted_patterns)

    def filter_findings(self, findings: List[dict]) -> Tuple[List[dict], List[dict]]:
        """
        Filter a list of findings, separating real alerts from likely FPs.

        Findings matching an explicitly whitelisted pattern are always
        suppressed; otherwise the learned FP probability is used.

        Args:
            findings: List of finding dictionaries.

        Returns:
            Tuple of (filtered_findings, suppressed_findings).
        """
        filtered = []
        suppressed = []

        for finding in findings:
            rule_id = finding.get("rule_id", finding.get("category", ""))
            context = finding.get("source_ip", finding.get("hostname", ""))

            if self._matches_whitelist(finding):
                finding["fp_probability"] = 1.0
                finding["suppressed"] = True
                finding["whitelisted"] = True
                self.suppressed_count += 1
                suppressed.append(finding)
                continue

            should_suppress, prob = self.should_suppress(rule_id, context)

            if should_suppress:
                finding["fp_probability"] = prob
                finding["suppressed"] = True
                suppressed.append(finding)
            else:
                finding["fp_probability"] = prob
                finding["suppressed"] = False
                filtered.append(finding)

        return filtered, suppressed

    def add_whitelist(self, pattern: str):
        """Add a pattern to the whitelist (always suppress)."""
        if pattern not in self.whitelisted_patterns:
            self.whitelisted_patterns.append(pattern)
            self.save_model()

    def get_stats(self) -> dict:
        """Get FP suppression statistics."""
        return {
            "rules_tracked": len(self.rule_total_counts),
            "total_feedback": sum(self.rule_total_counts.values()),
            "total_fp_marked": sum(self.rule_fp_counts.values()),
            "suppressed_this_session": self.suppressed_count,
            "top_fp_rules": self._get_top_fp_rules(10),
        }

    def _get_top_fp_rules(self, limit: int = 10) -> List[dict]:
        """Get rules with highest FP rates."""
        rates = []
        for rule_id, total in self.rule_total_counts.items():
            if total >= 5:
                fp_count = self.rule_fp_counts.get(rule_id, 0)
                rates.append({
                    "rule_id": rule_id,
                    "fp_rate": round(fp_count / total, 3),
                    "total": total,
                    "fp_count": fp_count,
                })
        rates.sort(key=lambda x: x["fp_rate"], reverse=True)
        return rates[:limit]
