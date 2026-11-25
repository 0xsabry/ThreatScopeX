"""
ThreatScope — Dynamic Rule Generator
Author: 0xSABRY

Automatically constructs valid Sigma YAML rules and YARA signatures
from deobfuscated payloads, behavioral patterns, and analysis findings.

Generated rules include:
  - Proper Sigma condition syntax with field selections
  - MITRE ATT&CK technique mapping
  - YARA rules with string/hex/regex patterns and conditions
  - Metadata (author, date, severity, description)
"""

import re
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set

logger = logging.getLogger("threatscope.rule_gen")

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


# ============================================================
# Sigma Rule Generator
# ============================================================

class SigmaRuleGenerator:
    """
    Generate valid Sigma YAML detection rules from behavioral
    patterns, deobfuscated payloads, and analysis findings.

    Produces rules compatible with SigmaHQ format, including:
      - logsource specification
      - detection with field selections
      - condition logic
      - MITRE ATT&CK tags
      - metadata (title, description, author, level, status)

    Example:
        >>> gen = SigmaRuleGenerator()
        >>> rule = gen.from_finding(finding_dict)
        >>> gen.save_rule(rule, "rules/custom_detection.yml")
    """

    def __init__(self, author: str = "ThreatScope AutoGen") -> None:
        """
        Initialize the Sigma rule generator.

        Args:
            author: Author name for generated rules.
        """
        self.author = author
        self._generated_rules: List[Dict[str, Any]] = []

    def from_cmdline(
        self,
        cmdline: str,
        title: str = "",
        description: str = "",
        severity: str = "high",
        mitre_techniques: Optional[List[str]] = None,
        logsource: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a Sigma rule from a suspicious command line.

        Args:
            cmdline: The suspicious command line string.
            title: Rule title (auto-generated if empty).
            description: Rule description.
            severity: Sigma level (critical, high, medium, low, informational).
            mitre_techniques: List of MITRE ATT&CK technique IDs.
            logsource: Sigma logsource dict (auto-detected if None).

        Returns:
            Sigma rule dictionary.
        """
        # Extract key tokens from the command line
        tokens = self._extract_cmdline_tokens(cmdline)

        if not title:
            title = f"ThreatScope: Suspicious Command — {tokens[0] if tokens else 'Unknown'}"

        if not description:
            description = (
                f"Auto-generated detection rule for suspicious command line "
                f"containing: {', '.join(tokens[:5])}"
            )

        # Auto-detect logsource
        if logsource is None:
            logsource = self._detect_logsource(cmdline)

        # Build detection
        selection: Dict[str, Any] = {}
        if tokens:
            selection["CommandLine|contains|all"] = tokens[:10]

        # Extract process name
        proc_name = self._extract_process_name(cmdline)
        if proc_name:
            selection["Image|endswith"] = f"\\{proc_name}"

        rule_id = self._generate_rule_id(title)

        rule: Dict[str, Any] = {
            "title": title,
            "id": rule_id,
            "status": "experimental",
            "description": description,
            "author": self.author,
            "date": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
            "logsource": logsource,
            "detection": {
                "selection": selection,
                "condition": "selection",
            },
            "level": severity,
            "falsepositives": ["Legitimate administrative activity"],
        }

        # Add MITRE tags
        if mitre_techniques:
            rule["tags"] = [f"attack.{t.lower()}" for t in mitre_techniques]

        self._generated_rules.append(rule)
        return rule

    def from_finding(
        self,
        finding: Dict[str, Any],
        logsource: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a Sigma rule from a ThreatScope finding.

        Args:
            finding: Finding dictionary from core/analyzer.py.
            logsource: Override logsource.

        Returns:
            Sigma rule dictionary.
        """
        title = f"ThreatScope: {finding.get('title', 'Detection')}"
        description = finding.get("description", "")
        severity = finding.get("severity", "medium")
        mitre = finding.get("mitre", "")
        raw = finding.get("raw", "")
        pattern = finding.get("matched_pattern", "")

        mitre_techniques = [m.strip() for m in mitre.split(",") if m.strip()] if mitre else []

        if logsource is None:
            logsource = self._detect_logsource(raw)

        # Build detection from matched pattern or raw content
        selection: Dict[str, Any] = {}
        if pattern:
            selection["CommandLine|re"] = pattern
        elif raw:
            tokens = self._extract_cmdline_tokens(raw)
            if tokens:
                selection["CommandLine|contains"] = tokens[:5]

        rule_id = self._generate_rule_id(title)

        rule: Dict[str, Any] = {
            "title": title,
            "id": rule_id,
            "status": "experimental",
            "description": description[:500],
            "author": self.author,
            "date": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
            "logsource": logsource,
            "detection": {
                "selection": selection,
                "condition": "selection",
            },
            "level": severity,
            "falsepositives": ["Requires validation"],
        }

        if mitre_techniques:
            rule["tags"] = [f"attack.{t.lower()}" for t in mitre_techniques]

        self._generated_rules.append(rule)
        return rule

    def from_deobfuscation(
        self,
        deobfuscation_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Generate a Sigma rule from a deobfuscation result.

        Args:
            deobfuscation_result: Result dict from DeobfuscationPipeline.

        Returns:
            Sigma rule dictionary.
        """
        original = deobfuscation_result.get("original", "")
        deobfuscated = deobfuscation_result.get("deobfuscated", "")
        c2 = deobfuscation_result.get("c2_indicators", {})
        language = deobfuscation_result.get("language", "")

        title = f"ThreatScope: Deobfuscated {language.title()} Payload"
        description = (
            f"Detection rule for obfuscated {language} payload. "
            f"Deobfuscation revealed: {deobfuscated[:200]}"
        )

        # Extract stable tokens from the original (obfuscated) form
        tokens = self._extract_cmdline_tokens(original)

        logsource = {
            "category": "process_creation",
            "product": "windows" if language == "powershell" else "linux",
        }

        selection: Dict[str, Any] = {}
        if tokens:
            selection["CommandLine|contains|all"] = tokens[:8]

        # Add C2 domain/IP detection
        filter_c2: Dict[str, Any] = {}
        if c2.get("ips"):
            filter_c2["DestinationIp"] = c2["ips"][:5]
        if c2.get("domains"):
            filter_c2["DestinationHostname|contains"] = c2["domains"][:5]

        detection: Dict[str, Any] = {"selection": selection, "condition": "selection"}
        if filter_c2:
            detection["filter_c2"] = filter_c2
            detection["condition"] = "selection or filter_c2"

        rule: Dict[str, Any] = {
            "title": title,
            "id": self._generate_rule_id(title),
            "status": "experimental",
            "description": description,
            "author": self.author,
            "date": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
            "logsource": logsource,
            "detection": detection,
            "level": "high",
            "tags": ["attack.t1027", "attack.defense_evasion"],
            "falsepositives": ["Requires validation"],
        }

        self._generated_rules.append(rule)
        return rule

    def save_rule(self, rule: Dict[str, Any], filepath: str) -> str:
        """
        Save a generated Sigma rule to a YAML file.

        Args:
            rule: Sigma rule dictionary.
            filepath: Output file path.

        Returns:
            Path to the saved file.
        """
        if not YAML_AVAILABLE:
            # Fallback: write manual YAML
            return self._save_rule_manual(rule, filepath)

        with open(filepath, "w", encoding="utf-8") as f:
            yaml.dump(rule, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

        logger.info(f"Sigma rule saved to {filepath}")
        return filepath

    def get_all_rules(self) -> List[Dict[str, Any]]:
        """Get all generated rules."""
        return self._generated_rules

    def _extract_cmdline_tokens(self, cmdline: str) -> List[str]:
        """Extract meaningful tokens from a command line for detection."""
        if not cmdline:
            return []

        tokens: List[str] = []
        # Extract flags, paths, and keywords
        for match in re.finditer(r"[-/][a-zA-Z]{2,20}", cmdline):
            token = match.group(0)
            if len(token) >= 3:
                tokens.append(token)

        # Extract suspicious strings
        for keyword in [
            "invoke-", "iex", "bypass", "hidden", "downloadstring",
            "downloadfile", "webclient", "net.sockets", "encodedcommand",
            "mimikatz", "rubeus", "sharphound", "-exec bypass",
            "certutil", "bitsadmin", "rundll32", "regsvr32",
        ]:
            if keyword.lower() in cmdline.lower():
                # Find exact case version
                idx = cmdline.lower().index(keyword.lower())
                tokens.append(cmdline[idx:idx + len(keyword)])

        # Deduplicate while preserving order
        seen: Set[str] = set()
        unique: List[str] = []
        for t in tokens:
            if t.lower() not in seen:
                seen.add(t.lower())
                unique.append(t)

        return unique

    @staticmethod
    def _extract_process_name(cmdline: str) -> str:
        """Extract the process name from a command line."""
        match = re.match(r'(?:"([^"]+)"|(\S+))', cmdline)
        if match:
            path = match.group(1) or match.group(2)
            return path.replace("\\", "/").split("/")[-1]
        return ""

    @staticmethod
    def _detect_logsource(content: str) -> Dict[str, str]:
        """Auto-detect Sigma logsource from content."""
        content_lower = content.lower()
        if any(kw in content_lower for kw in ["powershell", "cmd.exe", "wscript", ".exe"]):
            return {"category": "process_creation", "product": "windows"}
        if any(kw in content_lower for kw in ["bash", "/bin/sh", "sudo", "ssh"]):
            return {"category": "process_creation", "product": "linux"}
        if "event_id" in content_lower or "evtx" in content_lower:
            return {"product": "windows", "service": "security"}
        return {"category": "process_creation", "product": "windows"}

    @staticmethod
    def _generate_rule_id(title: str) -> str:
        """Generate a deterministic UUID-like ID from the title."""
        h = hashlib.sha256(title.encode()).hexdigest()
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

    def _save_rule_manual(self, rule: Dict[str, Any], filepath: str) -> str:
        """Save rule as YAML without the yaml library."""
        lines = []
        for key, value in rule.items():
            if isinstance(value, str):
                lines.append(f"{key}: {value}")
            elif isinstance(value, list):
                lines.append(f"{key}:")
                for item in value:
                    lines.append(f"  - {item}")
            elif isinstance(value, dict):
                lines.append(f"{key}:")
                for k2, v2 in value.items():
                    if isinstance(v2, dict):
                        lines.append(f"  {k2}:")
                        for k3, v3 in v2.items():
                            if isinstance(v3, list):
                                lines.append(f"    {k3}:")
                                for item in v3:
                                    lines.append(f"      - '{item}'")
                            else:
                                lines.append(f"    {k3}: {v3}")
                    elif isinstance(v2, list):
                        lines.append(f"  {k2}:")
                        for item in v2:
                            lines.append(f"    - '{item}'")
                    else:
                        lines.append(f"  {k2}: {v2}")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return filepath


# ============================================================
# YARA Rule Generator
# ============================================================

class YaraRuleGenerator:
    """
    Generate YARA signature rules from payloads, IOCs, and findings.

    Produces valid YARA rules with:
      - String patterns (text, hex, regex)
      - Condition logic
      - Metadata (author, date, description, severity)
      - Tags for categorization

    Example:
        >>> gen = YaraRuleGenerator()
        >>> rule = gen.from_strings(["mimikatz", "sekurlsa"], name="mimikatz_detection")
        >>> gen.save_rule(rule, "yara_rules/custom.yar")
    """

    def __init__(self, author: str = "ThreatScope AutoGen") -> None:
        """
        Initialize the YARA rule generator.

        Args:
            author: Author name for generated rules.
        """
        self.author = author
        self._generated_rules: List[str] = []

    def from_strings(
        self,
        strings: List[str],
        name: str = "",
        description: str = "",
        condition: str = "any",
        tags: Optional[List[str]] = None,
        severity: str = "medium",
    ) -> str:
        """
        Generate a YARA rule from a list of string patterns.

        Args:
            strings: List of string patterns to match.
            name: Rule name (auto-generated if empty).
            description: Rule description.
            condition: "any" (any of them) or "all" (all of them).
            tags: List of YARA tags.
            severity: Rule severity for metadata.

        Returns:
            YARA rule as a string.
        """
        if not strings:
            return ""

        if not name:
            name = f"autogen_{hashlib.md5('_'.join(strings).encode()).hexdigest()[:12]}"

        # Sanitize rule name
        name = re.sub(r"[^a-zA-Z0-9_]", "_", name)

        # Build strings section
        string_lines: List[str] = []
        for i, s in enumerate(strings):
            safe = s.replace("\\", "\\\\").replace('"', '\\"')
            string_lines.append(f'        $s{i} = "{safe}" ascii wide nocase')

        # Build condition
        if condition == "all":
            cond = "all of them"
        elif condition == "any":
            cond = "any of them"
        else:
            cond = condition

        # Build tags string
        tags_str = ""
        if tags:
            tags_str = " : " + " ".join(tags)

        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        rule = f"""rule {name}{tags_str}
{{
    meta:
        author = "{self.author}"
        date = "{date}"
        description = "{description or 'Auto-generated YARA rule'}"
        severity = "{severity}"
        generated_by = "ThreatScope"

    strings:
{chr(10).join(string_lines)}

    condition:
        {cond}
}}"""

        self._generated_rules.append(rule)
        return rule

    def from_hex_patterns(
        self,
        hex_patterns: List[str],
        name: str = "",
        description: str = "",
    ) -> str:
        """
        Generate a YARA rule from hex byte patterns.

        Args:
            hex_patterns: List of hex pattern strings (e.g., "4D 5A 90 00").
            name: Rule name.
            description: Rule description.

        Returns:
            YARA rule as a string.
        """
        if not hex_patterns:
            return ""

        if not name:
            name = f"hex_autogen_{hashlib.md5(hex_patterns[0].encode()).hexdigest()[:12]}"

        name = re.sub(r"[^a-zA-Z0-9_]", "_", name)

        string_lines = []
        for i, pattern in enumerate(hex_patterns):
            # Ensure hex formatting
            clean = re.sub(r"[^0-9a-fA-F? ]", "", pattern)
            string_lines.append(f"        $hex{i} = {{ {clean} }}")

        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        rule = f"""rule {name}
{{
    meta:
        author = "{self.author}"
        date = "{date}"
        description = "{description or 'Hex pattern detection'}"
        generated_by = "ThreatScope"

    strings:
{chr(10).join(string_lines)}

    condition:
        any of them
}}"""

        self._generated_rules.append(rule)
        return rule

    def from_deobfuscation(
        self,
        deobfuscation_result: Dict[str, Any],
    ) -> str:
        """
        Generate a YARA rule from deobfuscation results.

        Uses both original obfuscated patterns and extracted C2 indicators.

        Args:
            deobfuscation_result: Result from DeobfuscationPipeline.

        Returns:
            YARA rule string.
        """
        original = deobfuscation_result.get("original", "")
        deobfuscated = deobfuscation_result.get("deobfuscated", "")
        c2 = deobfuscation_result.get("c2_indicators", {})
        language = deobfuscation_result.get("language", "unknown")

        strings: List[str] = []

        # Add C2 indicators
        for ip in c2.get("ips", [])[:5]:
            strings.append(ip)
        for domain in c2.get("domains", [])[:5]:
            strings.append(domain)
        for url in c2.get("urls", [])[:3]:
            strings.append(url)

        # Add key tokens from deobfuscated content
        for token in re.findall(r"\b[a-zA-Z]{5,30}\b", deobfuscated):
            if token.lower() not in {"the", "and", "for", "with", "this", "that", "from"}:
                strings.append(token)
                if len(strings) >= 15:
                    break

        if not strings:
            return ""

        name = f"deobfuscated_{language}_{hashlib.md5(original[:100].encode()).hexdigest()[:8]}"

        return self.from_strings(
            strings=strings,
            name=name,
            description=f"Detection for deobfuscated {language} payload with C2 indicators",
            condition="any",
            tags=["deobfuscation", language],
            severity="high",
        )

    def from_finding(self, finding: Dict[str, Any]) -> str:
        """
        Generate a YARA rule from a ThreatScope finding.

        Args:
            finding: Finding dictionary from core/analyzer.py.

        Returns:
            YARA rule string.
        """
        title = finding.get("title", "Unknown")
        raw = finding.get("raw", "")
        pattern = finding.get("matched_pattern", "")
        category = finding.get("category", "")

        strings: List[str] = []

        # Extract meaningful strings from the raw content
        if raw:
            for token in re.findall(r"\b[a-zA-Z_]{4,25}\b", raw):
                if token not in strings and len(strings) < 10:
                    strings.append(token)

        if not strings:
            return ""

        name = f"finding_{re.sub(r'[^a-zA-Z0-9]', '_', category)}"

        return self.from_strings(
            strings=strings,
            name=name,
            description=f"Auto-generated from finding: {title}",
            condition="any",
            severity=finding.get("severity", "medium"),
        )

    def save_rule(self, rule_text: str, filepath: str) -> str:
        """
        Save a YARA rule to a file.

        Args:
            rule_text: The YARA rule string.
            filepath: Output file path.

        Returns:
            Path to the saved file.
        """
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(rule_text)
        logger.info(f"YARA rule saved to {filepath}")
        return filepath

    def save_all_rules(self, filepath: str) -> str:
        """
        Save all generated rules to a single YARA file.

        Args:
            filepath: Output file path.

        Returns:
            Path to the saved file.
        """
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"// Auto-generated by ThreatScope — {self.author}\n")
            f.write(f"// Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
            for rule in self._generated_rules:
                f.write(rule)
                f.write("\n\n")
        logger.info(f"Saved {len(self._generated_rules)} YARA rules to {filepath}")
        return filepath

    def get_all_rules(self) -> List[str]:
        """Get all generated YARA rules as strings."""
        return self._generated_rules
