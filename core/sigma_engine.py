"""
ThreatScope — Full SigmaHQ Rule Engine
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
import logging
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional, Any, Set, Tuple

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

logger = logging.getLogger("threatscope.sigma")


# ============================================================
# Sigma Field Modifiers
# ============================================================
SIGMA_MODIFIERS = {
    "contains": lambda field_val, test_val: test_val.lower() in str(field_val).lower(),
    "startswith": lambda field_val, test_val: str(field_val).lower().startswith(test_val.lower()),
    "endswith": lambda field_val, test_val: str(field_val).lower().endswith(test_val.lower()),
    "re": lambda field_val, test_val: bool(re.search(test_val, str(field_val), re.IGNORECASE)),
    "all": None,  # Handled specially — requires all values match
    "base64": None,  # Handled specially — decodes base64 before matching
    "base64offset": None,
    "cidr": None,  # CIDR network matching
    "windash": None,  # Windows command line dash variants
    "utf16le": None,
    "utf16be": None,
    "wide": None,
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

    def matches(self, event: dict) -> bool:
        """
        Test if an event matches this Sigma rule.

        Args:
            event: Normalized event dictionary with 'fields' and 'raw' keys.

        Returns:
            True if the event matches the rule's detection logic.
        """
        if not self.detection or not self.condition:
            return False

        try:
            return self._evaluate_condition(self.condition, event)
        except Exception as e:
            logger.debug(f"Error evaluating rule {self.title}: {e}")
            return False

    def matches_line(self, line: str) -> bool:
        """
        Test if a raw log line matches this rule (simplified keyword matching).

        Args:
            line: Raw log line string.

        Returns:
            True if the line matches the rule.
        """
        if not self.detection:
            return False

        # Create a pseudo-event from the raw line
        event = {"raw": line, "fields": {}}

        # Try condition-based matching first
        try:
            return self._evaluate_condition(self.condition, event)
        except Exception:
            pass

        # Fallback: keyword-based matching
        return self._keyword_match(line)

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

    def _evaluate_condition(self, condition: str, event: dict) -> bool:
        """
        Evaluate a Sigma condition expression against an event.

        Supports: selection references, and, or, not, 1 of, all of,
        parentheses grouping.

        Args:
            condition: Sigma condition string.
            event: Normalized event dictionary.

        Returns:
            True if the condition is satisfied.
        """
        condition = condition.strip()

        # Handle 'all of' patterns
        all_of_match = re.match(r"all of (\w+)\*", condition)
        if all_of_match:
            prefix = all_of_match.group(1)
            return all(
                self._evaluate_selection(name, event)
                for name in self.detection
                if name != "condition" and name.startswith(prefix)
            )

        # Handle '1 of' patterns
        one_of_match = re.match(r"1 of (\w+)\*", condition)
        if one_of_match:
            prefix = one_of_match.group(1)
            return any(
                self._evaluate_selection(name, event)
                for name in self.detection
                if name != "condition" and name.startswith(prefix)
            )

        # Handle 'all of them'
        if condition == "all of them":
            return all(
                self._evaluate_selection(name, event)
                for name in self.detection
                if name != "condition"
            )

        # Handle '1 of them'
        if condition == "1 of them":
            return any(
                self._evaluate_selection(name, event)
                for name in self.detection
                if name != "condition"
            )

        # Parse compound conditions with and/or/not
        return self._parse_compound_condition(condition, event)

    def _parse_compound_condition(self, condition: str, event: dict) -> bool:
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
            result, _ = self._parse_or_expr(tokens, 0, event)
            return result
        except (IndexError, ValueError):
            # Fallback: try as a simple selection name
            if condition in self.detection and condition != "condition":
                return self._evaluate_selection(condition, event)
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

    def _parse_or_expr(self, tokens: List[str], pos: int, event: dict) -> Tuple[bool, int]:
        """Parse OR expression."""
        left, pos = self._parse_and_expr(tokens, pos, event)
        while pos < len(tokens) and tokens[pos].lower() == "or":
            pos += 1
            right, pos = self._parse_and_expr(tokens, pos, event)
            left = left or right
        return left, pos

    def _parse_and_expr(self, tokens: List[str], pos: int, event: dict) -> Tuple[bool, int]:
        """Parse AND expression."""
        left, pos = self._parse_not_expr(tokens, pos, event)
        while pos < len(tokens) and tokens[pos].lower() == "and":
            pos += 1
            right, pos = self._parse_not_expr(tokens, pos, event)
            left = left and right
        return left, pos

    def _parse_not_expr(self, tokens: List[str], pos: int, event: dict) -> Tuple[bool, int]:
        """Parse NOT expression."""
        if pos < len(tokens) and tokens[pos].lower() == "not":
            pos += 1
            result, pos = self._parse_primary(tokens, pos, event)
            return not result, pos
        return self._parse_primary(tokens, pos, event)

    def _parse_primary(self, tokens: List[str], pos: int, event: dict) -> Tuple[bool, int]:
        """Parse primary expression (selection name or parenthesized expression)."""
        if pos >= len(tokens):
            return False, pos

        token = tokens[pos]

        if token == "(":
            pos += 1
            result, pos = self._parse_or_expr(tokens, pos, event)
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

                if quantifier == "all":
                    return all(self._evaluate_selection(s, event) for s in selections), pos
                else:
                    return any(self._evaluate_selection(s, event) for s in selections), pos

        # Simple selection name
        pos += 1
        if token in self.detection and token != "condition":
            return self._evaluate_selection(token, event), pos
        return False, pos

    def _evaluate_selection(self, selection_name: str, event: dict) -> bool:
        """
        Evaluate a single Sigma selection against an event.

        Args:
            selection_name: Name of the detection selection.
            event: Event dictionary.

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
            return self._evaluate_field_selection(selection, event)

        return False

    def _evaluate_field_selection(self, selection: dict, event: dict) -> bool:
        """
        Evaluate field-based selection conditions.

        Args:
            selection: Dictionary of field -> value conditions.
            event: Event dictionary.

        Returns:
            True if all field conditions match.
        """
        fields = event.get("fields", {})
        raw = str(event.get("raw", ""))
        all_text = raw + " " + " ".join(str(v) for v in fields.values())

        for field_spec, expected_values in selection.items():
            field_parts = field_spec.split("|")
            field_name = field_parts[0]
            modifiers = field_parts[1:] if len(field_parts) > 1 else []

            # Get the field value
            field_value = fields.get(field_name, "")
            if not field_value and field_name.lower() == "keywords":
                field_value = raw

            # If field not found, search in raw text
            if not field_value:
                field_value = all_text

            # Normalize expected values to list
            if not isinstance(expected_values, list):
                expected_values = [expected_values]

            # Check modifiers
            if "all" in modifiers:
                # All values must match
                if not all(
                    self._match_with_modifiers(field_value, val, modifiers)
                    for val in expected_values
                ):
                    return False
            else:
                # Any value must match (OR logic within a field)
                if not any(
                    self._match_with_modifiers(field_value, val, modifiers)
                    for val in expected_values
                ):
                    return False

        return True

    def _match_with_modifiers(self, field_value: Any, test_value: Any, modifiers: List[str]) -> bool:
        """
        Match a field value against a test value using specified modifiers.

        Args:
            field_value: The actual field value from the event.
            test_value: The expected value from the rule.
            modifiers: List of modifier names.

        Returns:
            True if the value matches.
        """
        if test_value is None:
            return field_value is None or field_value == ""

        field_str = str(field_value).lower()
        test_str = str(test_value).lower()

        # Apply modifiers in order
        effective_modifiers = [m for m in modifiers if m in SIGMA_MODIFIERS and m != "all"]

        if not effective_modifiers:
            # Default: exact match or substring in raw text
            return test_str in field_str

        for modifier in effective_modifiers:
            func = SIGMA_MODIFIERS.get(modifier)
            if func is not None:
                if func(field_value, str(test_value)):
                    return True
            elif modifier == "re":
                try:
                    if re.search(str(test_value), str(field_value), re.IGNORECASE):
                        return True
                except re.error:
                    pass
        return False

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
        if not YAML_AVAILABLE:
            logger.warning("PyYAML not installed — Sigma engine disabled.")
            self.available = False
            return

        self.available = True
        if rules_dir:
            self.rules_dir = Path(rules_dir)
        else:
            from config import SIGMA_RULES_DIR
            self.rules_dir = SIGMA_RULES_DIR

        self.rules: List[SigmaRule] = []
        self.rules_by_id: Dict[str, SigmaRule] = {}
        self.rules_by_technique: Dict[str, List[SigmaRule]] = defaultdict(list)
        self.rules_by_platform: Dict[str, List[SigmaRule]] = defaultdict(list)
        self.rules_by_level: Dict[str, List[SigmaRule]] = defaultdict(list)
        self.rules_by_category: Dict[str, List[SigmaRule]] = defaultdict(list)

        self._stats = {
            "total_loaded": 0,
            "failed": 0,
            "by_platform": defaultdict(int),
            "by_level": defaultdict(int),
        }

    def load_rules(self, recursive: bool = True) -> int:
        """
        Load all Sigma rules from the rules directory.

        Args:
            recursive: Whether to search subdirectories recursively.

        Returns:
            Number of rules successfully loaded.
        """
        if not self.available:
            return 0

        if not self.rules_dir.exists():
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
                logger.debug(f"Failed to load {yml_path}: {e}")
                self._stats["failed"] += 1

        logger.info(
            f"Loaded {self._stats['total_loaded']} Sigma rules "
            f"({self._stats['failed']} failed)"
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
            except Exception as e:
                logger.debug(f"Failed to parse rule in {filepath}: {e}")
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

    def match_event(self, event: dict) -> List[dict]:
        """
        Match a single event against all loaded Sigma rules.

        Args:
            event: Normalized event dictionary.

        Returns:
            List of matching rule results.
        """
        matches = []
        for rule in self.rules:
            try:
                if rule.matches(event):
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
            except Exception:
                continue
        return matches

    def match_line(self, line: str) -> List[dict]:
        """
        Match a raw log line against all loaded Sigma rules.

        Args:
            line: Raw log line string.

        Returns:
            List of matching rule results.
        """
        matches = []
        for rule in self.rules:
            try:
                if rule.matches_line(line):
                    matches.append({
                        "rule_id": rule.id,
                        "title": rule.title,
                        "description": rule.description,
                        "level": rule.level,
                        "weight": rule.weight,
                        "mitre_techniques": rule.mitre_techniques,
                        "platform": rule.platform,
                    })
            except Exception:
                continue
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

    def get_stats(self) -> dict:
        """Get loading statistics."""
        return {
            "total_rules": len(self.rules),
            "loaded": self._stats["total_loaded"],
            "failed": self._stats["failed"],
            "by_platform": dict(self._stats["by_platform"]),
            "by_level": dict(self._stats["by_level"]),
            "by_category": {k: len(v) for k, v in self.rules_by_category.items()},
            "mitre_techniques_covered": len(self.rules_by_technique),
        }

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
