"""
ThreatScope — YARA Rules Integration Engine
Author: 0xSABRY

Scans files, memory dumps, and executables with YARA rules.
Merges YARA findings with Sigma results in unified reports.
"""

import os
import logging
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger("threatscope.yara")

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.info("yara-python not installed — YARA engine disabled. Install with: pip install yara-python")


class YaraEngine:
    """
    YARA rule scanning engine for files, memory dumps, and executables.
    Integrates with ThreatScope's unified findings report.
    """

    def __init__(self, rules_dir: Optional[str] = None):
        """
        Initialize the YARA engine.

        Args:
            rules_dir: Directory containing YARA rule files (.yar, .yara).
        """
        self.available = YARA_AVAILABLE
        if rules_dir:
            self.rules_dir = Path(rules_dir)
        else:
            from config import YARA_RULES_DIR
            self.rules_dir = YARA_RULES_DIR

        self.compiled_rules = []
        self.rule_count = 0
        self.findings: List[dict] = []
        self._stats = {"files_scanned": 0, "matches": 0, "errors": 0}

    def load_rules(self) -> int:
        """
        Load and compile all YARA rules from the rules directory.

        Returns:
            Number of rule files successfully compiled.
        """
        if not self.available:
            logger.warning("YARA not available — cannot load rules")
            return 0

        if not self.rules_dir.exists():
            logger.info(f"YARA rules directory not found: {self.rules_dir}")
            return 0

        rule_files = list(self.rules_dir.glob("**/*.yar"))
        rule_files.extend(self.rules_dir.glob("**/*.yara"))

        for rule_file in rule_files:
            try:
                compiled = yara.compile(filepath=str(rule_file))
                self.compiled_rules.append({
                    "compiled": compiled,
                    "source": str(rule_file),
                    "name": rule_file.stem,
                })
                self.rule_count += 1
            except Exception as e:
                logger.debug(f"Failed to compile YARA rule {rule_file}: {e}")
                self._stats["errors"] += 1

        logger.info(f"Loaded {self.rule_count} YARA rule files")
        return self.rule_count

    def scan_file(self, filepath: str, timeout: int = 60) -> List[dict]:
        """
        Scan a single file with all loaded YARA rules.

        Args:
            filepath: Path to the file to scan.
            timeout: Scan timeout in seconds.

        Returns:
            List of YARA match results.
        """
        if not self.available or not self.compiled_rules:
            return []

        matches = []
        self._stats["files_scanned"] += 1
        filepath = str(filepath)

        for rule_set in self.compiled_rules:
            try:
                yara_matches = rule_set["compiled"].match(
                    filepath=filepath,
                    timeout=timeout,
                )
                for match in yara_matches:
                    result = {
                        "type": "yara",
                        "rule_name": match.rule,
                        "rule_file": rule_set["source"],
                        "tags": list(match.tags),
                        "meta": dict(match.meta) if match.meta else {},
                        "strings_matched": [],
                        "file": filepath,
                        "severity": self._determine_severity(match),
                    }

                    for string_match in match.strings:
                        for instance in string_match.instances:
                            result["strings_matched"].append({
                                "identifier": string_match.identifier,
                                "offset": instance.offset,
                                "data": instance.matched_data[:100].hex()
                                    if isinstance(instance.matched_data, bytes)
                                    else str(instance.matched_data)[:100],
                            })

                    matches.append(result)
                    self._stats["matches"] += 1
                    self.findings.append(result)

            except Exception as e:
                logger.debug(f"YARA scan error on {filepath}: {e}")
                self._stats["errors"] += 1

        return matches

    def scan_data(self, data: bytes, source_name: str = "memory") -> List[dict]:
        """
        Scan raw data (memory dump, binary blob) with YARA rules.

        Args:
            data: Raw bytes to scan.
            source_name: Name to identify the source.

        Returns:
            List of YARA match results.
        """
        if not self.available or not self.compiled_rules:
            return []

        matches = []
        for rule_set in self.compiled_rules:
            try:
                yara_matches = rule_set["compiled"].match(data=data)
                for match in yara_matches:
                    result = {
                        "type": "yara",
                        "rule_name": match.rule,
                        "rule_file": rule_set["source"],
                        "tags": list(match.tags),
                        "meta": dict(match.meta) if match.meta else {},
                        "strings_matched": len(match.strings),
                        "source": source_name,
                        "severity": self._determine_severity(match),
                    }
                    matches.append(result)
                    self._stats["matches"] += 1
                    self.findings.append(result)
            except Exception as e:
                logger.debug(f"YARA data scan error: {e}")
                self._stats["errors"] += 1

        return matches

    def scan_directory(self, directory: str, extensions: List[str] = None,
                       timeout: int = 60) -> List[dict]:
        """
        Scan all files in a directory recursively.

        Args:
            directory: Directory path to scan.
            extensions: File extensions to include (e.g., ['.exe', '.dll']).
            timeout: Timeout per file.

        Returns:
            List of all YARA matches found.
        """
        all_matches = []
        dir_path = Path(directory)

        if not dir_path.exists():
            return []

        for filepath in dir_path.rglob("*"):
            if filepath.is_file():
                if extensions and filepath.suffix.lower() not in extensions:
                    continue
                try:
                    matches = self.scan_file(str(filepath), timeout=timeout)
                    all_matches.extend(matches)
                except Exception as e:
                    logger.debug(f"Error scanning {filepath}: {e}")

        return all_matches

    def _determine_severity(self, match) -> str:
        """Determine severity from YARA rule metadata."""
        meta = match.meta if match.meta else {}
        severity = meta.get("severity", meta.get("threat_level", "")).lower()
        if severity in ("critical", "high", "medium", "low"):
            return severity

        # Infer from tags
        tags = [t.lower() for t in match.tags] if match.tags else []
        if any(t in tags for t in ["apt", "malware", "ransomware", "exploit"]):
            return "critical"
        if any(t in tags for t in ["trojan", "backdoor", "rat"]):
            return "high"
        if any(t in tags for t in ["suspicious", "packer", "dropper"]):
            return "medium"
        return "medium"

    def get_summary(self) -> dict:
        """Get YARA scan summary."""
        return {
            "available": self.available,
            "rules_loaded": self.rule_count,
            "files_scanned": self._stats["files_scanned"],
            "total_matches": self._stats["matches"],
            "errors": self._stats["errors"],
            "findings": self.findings,
        }
