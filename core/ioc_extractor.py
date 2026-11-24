"""
ThreatScope — IOC Extraction Engine
Author: 0xSABRY

Extracts Indicators of Compromise (IOCs) from log data including
IP addresses, hashes, domains, URLs, emails, and CVEs.
"""

import re
from collections import defaultdict
from typing import Dict, Set, List, Optional


# ============================================================
# IOC Extraction Patterns
# ============================================================
IOC_PATTERNS = {
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    "ipv6": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
    "url": re.compile(r"https?://[^\s\"'<>]+"),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"+(?:com|net|org|io|xyz|info|ru|cn|tk|top|cc|pw|biz|me|co|uk|de|fr|"
        r"gov|edu|mil|int|eu|us|ca|au|br|jp|kr|in|za|ng|ke|onion|bit)\b"
    ),
    "email": re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    "cve": re.compile(r"CVE-\d{4}-\d{4,7}"),
    "registry_key": re.compile(
        r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s\"']+\b"
    ),
    "file_path_windows": re.compile(r"[A-Za-z]:\\(?:[^\s\\\"']+\\)*[^\s\\\"']+"),
    "file_path_unix": re.compile(r"(?:/(?:usr|etc|var|tmp|opt|home|root|bin|sbin|proc|sys)/[^\s\"']+)"),
    "mac_address": re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
    "bitcoin_address": re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    "base64_blob": re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
}

# IPs to exclude (private, loopback, link-local)
PRIVATE_IP_PREFIXES = (
    "0.", "10.", "127.", "169.254.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "192.168.", "255.", "224.", "239.",
)

# Common hash exclusions (known false positives)
HASH_EXCLUSIONS = {
    "0" * 32, "f" * 32, "0" * 40, "f" * 40, "0" * 64, "f" * 64,
    "d41d8cd98f00b204e9800998ecf8427e",  # MD5 of empty string
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1 of empty string
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 of empty
}


class IOCExtractor:
    """
    Extracts and categorizes Indicators of Compromise from log data.
    
    Supports extraction of: IP addresses, file hashes, domains, URLs,
    email addresses, CVEs, registry keys, file paths, MAC addresses,
    Bitcoin addresses, and suspicious base64 blobs.
    """

    def __init__(self, exclude_private_ips: bool = True):
        """
        Initialize the IOC extractor.

        Args:
            exclude_private_ips: Whether to filter out private/reserved IP addresses.
        """
        self.exclude_private_ips = exclude_private_ips
        self.iocs: Dict[str, Set[str]] = defaultdict(set)
        self.ioc_context: Dict[str, List[dict]] = defaultdict(list)
        self._stats = {"lines_processed": 0, "total_iocs": 0}

    def extract_from_line(self, line: str, line_number: int = 0, source: str = "") -> Dict[str, Set[str]]:
        """
        Extract IOCs from a single line of log data.

        Args:
            line: The log line to analyze.
            line_number: Line number in the original file.
            source: Source file or identifier.

        Returns:
            Dictionary of IOC type -> set of extracted values.
        """
        if not isinstance(line, str) or not line.strip():
            return {}

        self._stats["lines_processed"] += 1
        line_iocs: Dict[str, Set[str]] = defaultdict(set)

        for ioc_type, pattern in IOC_PATTERNS.items():
            for match in pattern.finditer(line):
                value = match.group(0)

                # Apply filters
                if not self._validate_ioc(ioc_type, value):
                    continue

                line_iocs[ioc_type].add(value)
                self.iocs[ioc_type].add(value)
                self._stats["total_iocs"] += 1

                # Store context for enrichment
                self.ioc_context[value].append({
                    "line_number": line_number,
                    "source": source,
                    "line_preview": line[:200].strip(),
                    "ioc_type": ioc_type,
                })

        return dict(line_iocs)

    def extract_from_lines(self, lines: List[str], source: str = "") -> Dict[str, Set[str]]:
        """
        Extract IOCs from multiple lines of log data.

        Args:
            lines: List of log lines.
            source: Source file identifier.

        Returns:
            Aggregated dictionary of all IOCs found.
        """
        for i, line in enumerate(lines, 1):
            self.extract_from_line(line, line_number=i, source=source)
        return dict(self.iocs)

    def extract_from_event(self, event: dict) -> Dict[str, Set[str]]:
        """
        Extract IOCs from a normalized event dictionary.

        Args:
            event: Normalized event with 'raw' and 'fields' keys.

        Returns:
            Dictionary of IOCs found.
        """
        raw = event.get("raw", "")
        fields = event.get("fields", {})

        line_iocs = self.extract_from_line(
            raw,
            line_number=event.get("line_number", 0),
            source=event.get("source", ""),
        )

        # Also extract from field values
        for key, value in fields.items():
            if isinstance(value, str) and len(value) > 3:
                self.extract_from_line(
                    value,
                    line_number=event.get("line_number", 0),
                    source=f"{event.get('source', '')}:{key}",
                )

        return line_iocs

    def _validate_ioc(self, ioc_type: str, value: str) -> bool:
        """
        Validate an IOC value, filtering out known false positives.

        Args:
            ioc_type: Type of IOC (ipv4, md5, etc.).
            value: The extracted value.

        Returns:
            True if the IOC is valid, False if it should be excluded.
        """
        if ioc_type == "ipv4" and self.exclude_private_ips:
            if value.startswith(PRIVATE_IP_PREFIXES):
                return False

        if ioc_type in ("md5", "sha1", "sha256"):
            if value.lower() in HASH_EXCLUSIONS:
                return False
            # Filter hex strings that are too uniform
            unique_chars = len(set(value.lower()))
            if unique_chars <= 3:
                return False

        if ioc_type == "domain":
            # Filter common false positive domains
            if value.lower() in (
                "windows.com", "microsoft.com", "google.com",
                "schema.org", "w3.org", "example.com",
            ):
                return False

        if ioc_type == "base64_blob":
            # Only keep suspicious base64 (potential encoded commands)
            if len(value) < 50:
                return False

        return True

    def get_summary(self) -> dict:
        """
        Get a summary of all extracted IOCs.

        Returns:
            Dictionary with IOC counts and top values.
        """
        summary = {
            "total_iocs": sum(len(v) for v in self.iocs.values()),
            "by_type": {k: len(v) for k, v in self.iocs.items() if v},
            "top_ips": self._get_top_values("ipv4", 20),
            "top_domains": self._get_top_values("domain", 20),
            "hashes": {
                "md5": list(self.iocs.get("md5", set()))[:50],
                "sha1": list(self.iocs.get("sha1", set()))[:50],
                "sha256": list(self.iocs.get("sha256", set()))[:50],
            },
            "cves": sorted(self.iocs.get("cve", set())),
            "urls": list(self.iocs.get("url", set()))[:50],
            "emails": list(self.iocs.get("email", set()))[:50],
        }
        return summary

    def _get_top_values(self, ioc_type: str, limit: int = 10) -> List[str]:
        """Get top IOC values sorted by frequency of context appearances."""
        values = self.iocs.get(ioc_type, set())
        scored = [(v, len(self.ioc_context.get(v, []))) for v in values]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [v for v, _ in scored[:limit]]

    def get_all_iocs_flat(self) -> List[dict]:
        """
        Get all IOCs as a flat list with context.

        Returns:
            List of IOC dictionaries with type, value, and context.
        """
        result = []
        for ioc_type, values in self.iocs.items():
            for value in values:
                contexts = self.ioc_context.get(value, [])
                result.append({
                    "type": ioc_type,
                    "value": value,
                    "occurrences": len(contexts),
                    "first_seen": contexts[0] if contexts else None,
                })
        return sorted(result, key=lambda x: x["occurrences"], reverse=True)

    def reset(self):
        """Clear all extracted IOCs and context."""
        self.iocs.clear()
        self.ioc_context.clear()
        self._stats = {"lines_processed": 0, "total_iocs": 0}
