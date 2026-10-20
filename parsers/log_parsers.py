"""
ThreatScope V2 — Multi-Platform Log Parsers
Author: 0xSABRY

Unified parsers for Windows EVTX, Sysmon, Linux auditd, macOS unified logs,
AWS CloudTrail, Azure Activity, and GCP Audit logs.
All parsers normalize events into a common schema.
"""

import re
import os
import json
import struct
import logging
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Generator
from collections import Counter

logger = logging.getLogger("threatscope.parsers")

# Optional EVTX library
try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    EVTX_LIB = True
except ImportError:
    EVTX_LIB = False


def normalize_event(timestamp: str = "", source: str = "", event_id: str = "",
                    fields: dict = None, raw: str = "", line_number: int = 0,
                    category: str = "", platform: str = "") -> dict:
    """
    Create a normalized event dictionary.

    Args:
        timestamp: ISO8601 timestamp string.
        source: Source identifier (filename, service name).
        event_id: Event ID if applicable.
        fields: Dictionary of parsed field values.
        raw: Original raw log line/entry.
        line_number: Line number in source file.
        category: Log category.
        platform: Platform identifier.

    Returns:
        Normalized event dictionary.
    """
    return {
        "timestamp": timestamp,
        "source": source,
        "event_id": str(event_id),
        "fields": fields or {},
        "raw": raw,
        "line_number": line_number,
        "category": category,
        "platform": platform,
    }


# ============================================================
# Windows EVTX Parser
# ============================================================
class EVTXParser:
    """Parse Windows Event Log (.evtx) files into normalized events."""

    # Important Windows Event IDs
    CRITICAL_EVENT_IDS = {
        "1": "Process Create (Sysmon)",
        "3": "Network Connection (Sysmon)",
        "4624": "Successful Logon",
        "4625": "Failed Logon",
        "4648": "Explicit Credential Logon",
        "4672": "Special Privileges Assigned",
        "4688": "Process Created",
        "4689": "Process Terminated",
        "4697": "Service Installed",
        "4698": "Scheduled Task Created",
        "4720": "User Account Created",
        "4722": "User Account Enabled",
        "4724": "Password Reset Attempt",
        "4728": "Member Added to Security Group",
        "4732": "Member Added to Local Group",
        "4738": "User Account Changed",
        "4740": "Account Locked Out",
        "4756": "Member Added to Universal Group",
        "4768": "Kerberos TGT Requested",
        "4769": "Kerberos Service Ticket",
        "4771": "Kerberos Pre-Auth Failed",
        "4776": "NTLM Authentication",
        "5140": "Network Share Accessed",
        "5156": "Windows Filtering Platform Connection",
        "7045": "Service Installed",
        "1102": "Audit Log Cleared",
    }

    def __init__(self):
        self.stats = {"events_parsed": 0, "errors": 0}

    def parse(self, filepath: str) -> List[dict]:
        """
        Parse an EVTX file into normalized events.

        Args:
            filepath: Path to the .evtx file.

        Returns:
            List of normalized event dictionaries.
        """
        events = []
        filepath = str(filepath)

        if EVTX_LIB:
            events = self._parse_with_lib(filepath)
        else:
            events = self._parse_native(filepath)

        self.stats["events_parsed"] = len(events)
        logger.info(f"Parsed {len(events)} events from {filepath}")
        return events

    def _parse_with_lib(self, filepath: str) -> List[dict]:
        """Parse EVTX using python-evtx library."""
        events = []
        try:
            with Evtx(filepath) as evtx:
                for xml_str, record in evtx_file_xml_view(evtx.get_file_header()):
                    try:
                        event = self._parse_xml_event(xml_str)
                        if event:
                            events.append(event)
                    except Exception:
                        self.stats["errors"] += 1
        except Exception as e:
            logger.error(f"EVTX library parse error: {e}")
            events = self._parse_native(filepath)
        return events

    def _parse_xml_event(self, xml_str: str) -> Optional[dict]:
        """Parse a single XML event record."""
        fields = {}

        # Extract EventID
        eid_match = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml_str)
        event_id = eid_match.group(1) if eid_match else ""

        # Extract timestamp
        ts_match = re.search(
            r'SystemTime="([^"]+)"', xml_str
        ) or re.search(r"<TimeCreated[^>]*>([^<]+)", xml_str)
        timestamp = ts_match.group(1) if ts_match else ""

        # Extract Computer
        comp_match = re.search(r"<Computer>([^<]+)", xml_str)
        if comp_match:
            fields["Computer"] = comp_match.group(1)

        # Extract Channel
        chan_match = re.search(r"<Channel>([^<]+)", xml_str)
        if chan_match:
            fields["Channel"] = chan_match.group(1)

        # Extract all Data fields
        for data_match in re.finditer(r'<Data Name="([^"]+)">([^<]*)</Data>', xml_str):
            fields[data_match.group(1)] = data_match.group(2)

        # Extract Provider
        prov_match = re.search(r'<Provider Name="([^"]+)"', xml_str)
        if prov_match:
            fields["Provider"] = prov_match.group(1)

        return normalize_event(
            timestamp=timestamp,
            source="evtx",
            event_id=event_id,
            fields=fields,
            raw=xml_str,
            platform="windows",
            category=self.CRITICAL_EVENT_IDS.get(event_id, ""),
        )

    def _parse_native(self, filepath: str) -> List[dict]:
        """
        Parse EVTX using native binary parsing (no external library needed).
        Extracts text content from the binary EVTX format.
        """
        events = []
        max_bytes = 100 * 1024 * 1024
        max_events = 50000
        try:
            try:
                size = os.path.getsize(filepath)
            except OSError:
                size = 0
            if size > max_bytes:
                logger.warning(
                    f"EVTX file {filepath} is {size} bytes; capping native read at "
                    f"{max_bytes} bytes to bound memory use"
                )
            with open(filepath, "rb") as f:
                data = f.read(max_bytes)

            # Find XML-like content in the binary
            text = data.decode("utf-8", errors="replace")
            lines = text.split("\n")

            for i, line in enumerate(lines):
                if len(events) >= max_events:
                    logger.warning(f"EVTX native parse capped at {max_events} events")
                    break
                line = line.strip()
                if not line:
                    continue
                # Extract readable content
                clean = re.sub(r"[^\x20-\x7E]", " ", line).strip()
                if len(clean) > 10:
                    # Try to extract event ID
                    eid_match = re.search(r"EventID[=: ]+(\d+)", clean, re.IGNORECASE)
                    event_id = eid_match.group(1) if eid_match else ""

                    # Try to extract timestamp
                    ts_match = re.search(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", clean)
                    timestamp = ts_match.group(0) if ts_match else ""

                    events.append(normalize_event(
                        timestamp=timestamp,
                        source="evtx_native",
                        event_id=event_id,
                        raw=clean,
                        line_number=i + 1,
                        platform="windows",
                    ))
        except Exception as e:
            logger.error(f"Native EVTX parse error: {e}")

        return events


# ============================================================
# Sysmon Parser
# ============================================================
class SysmonParser:
    """Parse Sysmon event logs with detailed field extraction."""

    SYSMON_EVENTS = {
        "1": {"name": "Process Create", "key_fields": ["Image", "CommandLine", "ParentImage", "User", "Hashes"]},
        "2": {"name": "File Creation Time Changed", "key_fields": ["Image", "TargetFilename"]},
        "3": {"name": "Network Connection", "key_fields": ["Image", "DestinationIp", "DestinationPort", "Protocol"]},
        "5": {"name": "Process Terminated", "key_fields": ["Image"]},
        "6": {"name": "Driver Loaded", "key_fields": ["ImageLoaded", "Signature", "Signed"]},
        "7": {"name": "Image Loaded", "key_fields": ["Image", "ImageLoaded", "Signed"]},
        "8": {"name": "CreateRemoteThread", "key_fields": ["SourceImage", "TargetImage"]},
        "10": {"name": "ProcessAccess", "key_fields": ["SourceImage", "TargetImage", "GrantedAccess"]},
        "11": {"name": "File Create", "key_fields": ["Image", "TargetFilename"]},
        "12": {"name": "Registry Event (Create/Delete)", "key_fields": ["Image", "TargetObject"]},
        "13": {"name": "Registry Value Set", "key_fields": ["Image", "TargetObject", "Details"]},
        "15": {"name": "FileCreateStreamHash", "key_fields": ["Image", "TargetFilename"]},
        "17": {"name": "Pipe Created", "key_fields": ["Image", "PipeName"]},
        "22": {"name": "DNS Query", "key_fields": ["Image", "QueryName", "QueryResults"]},
        "23": {"name": "File Delete", "key_fields": ["Image", "TargetFilename"]},
        "25": {"name": "Process Tampering", "key_fields": ["Image", "Type"]},
    }

    def parse(self, filepath: str) -> List[dict]:
        """Parse Sysmon logs."""
        # Sysmon events come through EVTX — use EVTX parser with Sysmon-specific enrichment
        evtx_parser = EVTXParser()
        events = evtx_parser.parse(filepath)

        enriched = []
        for event in events:
            eid = event.get("event_id", "")
            if eid in self.SYSMON_EVENTS:
                event["category"] = f"Sysmon: {self.SYSMON_EVENTS[eid]['name']}"
                event["sysmon_event"] = True
            enriched.append(event)

        return enriched


# ============================================================
# Linux Auditd Parser
# ============================================================
class LinuxAuditdParser:
    """Parse Linux auditd log files."""

    AUDIT_PATTERN = re.compile(
        r"type=(\w+)\s+msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)"
    )

    INTERESTING_TYPES = {
        "SYSCALL", "EXECVE", "PATH", "CWD", "PROCTITLE",
        "USER_AUTH", "USER_LOGIN", "USER_CMD", "ADD_USER",
        "DEL_USER", "ADD_GROUP", "USER_CHAUTHTOK",
        "ANOM_PROMISCUOUS", "AVC", "SELINUX_ERR",
        "CONFIG_CHANGE", "MAC_POLICY_LOAD",
    }

    def parse(self, filepath: str) -> List[dict]:
        """
        Parse a Linux auditd log file.

        Args:
            filepath: Path to the audit.log file.

        Returns:
            List of normalized events.
        """
        events = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, 1):
                    event = self._parse_line(line.strip(), i)
                    if event:
                        events.append(event)
        except Exception as e:
            logger.error(f"Auditd parse error: {e}")

        logger.info(f"Parsed {len(events)} auditd events from {filepath}")
        return events

    def _parse_line(self, line: str, line_number: int) -> Optional[dict]:
        """Parse a single auditd log line."""
        match = self.AUDIT_PATTERN.match(line)
        if not match:
            return None

        audit_type = match.group(1)
        timestamp_epoch = float(match.group(2))
        audit_id = match.group(3)
        data = match.group(4)

        # Parse key=value pairs
        fields = {"audit_type": audit_type, "audit_id": audit_id}
        for kv_match in re.finditer(r'(\w+)=("(?:[^"\\]|\\.)*"|[^\s]+)', data):
            key = kv_match.group(1)
            value = kv_match.group(2).strip('"')
            fields[key] = value

        try:
            timestamp = datetime.utcfromtimestamp(timestamp_epoch).isoformat()
        except Exception:
            timestamp = str(timestamp_epoch)

        return normalize_event(
            timestamp=timestamp,
            source="auditd",
            event_id=audit_type,
            fields=fields,
            raw=line,
            line_number=line_number,
            platform="linux",
            category=f"Audit: {audit_type}",
        )


# ============================================================
# macOS Unified Log Parser
# ============================================================
class MacOSLogParser:
    """Parse macOS unified logs (JSON format from 'log show' command)."""

    def parse(self, filepath: str) -> List[dict]:
        """
        Parse macOS unified log export.

        Args:
            filepath: Path to the log file (JSON or text format).

        Returns:
            List of normalized events.
        """
        events = []
        filepath = Path(filepath)

        if filepath.suffix.lower() == ".json":
            events = self._parse_json(filepath)
        else:
            events = self._parse_text(filepath)

        logger.info(f"Parsed {len(events)} macOS log events from {filepath}")
        return events

    def _parse_json(self, filepath: Path) -> List[dict]:
        """Parse JSON-formatted macOS log export."""
        events = []
        try:
            with open(filepath, "r") as f:
                data = json.load(f)

            entries = data if isinstance(data, list) else [data]
            for i, entry in enumerate(entries, 1):
                fields = {
                    "process": entry.get("processImagePath", ""),
                    "subsystem": entry.get("subsystem", ""),
                    "category": entry.get("category", ""),
                    "sender": entry.get("senderImagePath", ""),
                    "pid": entry.get("processID", ""),
                }
                events.append(normalize_event(
                    timestamp=entry.get("timestamp", ""),
                    source="macos_unified",
                    event_id=entry.get("messageType", ""),
                    fields=fields,
                    raw=entry.get("eventMessage", json.dumps(entry)),
                    line_number=i,
                    platform="macos",
                    category=entry.get("category", ""),
                ))
        except Exception as e:
            logger.error(f"macOS JSON parse error: {e}")
        return events

    def _parse_text(self, filepath: Path) -> List[dict]:
        """Parse text-formatted macOS log export."""
        events = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    ts_match = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", line)
                    events.append(normalize_event(
                        timestamp=ts_match.group(1) if ts_match else "",
                        source="macos_text",
                        raw=line,
                        line_number=i,
                        platform="macos",
                    ))
        except Exception as e:
            logger.error(f"macOS text parse error: {e}")
        return events


# ============================================================
# AWS CloudTrail Parser
# ============================================================
class CloudTrailParser:
    """Parse AWS CloudTrail JSON logs."""

    SUSPICIOUS_EVENTS = {
        "ConsoleLogin", "AssumeRole", "CreateUser", "AttachUserPolicy",
        "PutBucketPolicy", "CreateAccessKey", "RunInstances",
        "AuthorizeSecurityGroupIngress", "CreateKeyPair",
        "StopLogging", "DeleteTrail", "PutEventSelectors",
        "CreateFunction20150331", "UpdateFunctionCode20150331v2",
    }

    def parse(self, filepath: str) -> List[dict]:
        """
        Parse AWS CloudTrail log file.

        Args:
            filepath: Path to CloudTrail JSON file.

        Returns:
            List of normalized events.
        """
        events = []
        try:
            with open(filepath, "r") as f:
                data = json.load(f)

            if isinstance(data, list):
                records = data
            elif isinstance(data, dict):
                records = data.get("Records") or data.get("records") or [data]
            else:
                records = []

            for i, record in enumerate(records, 1):
                if not isinstance(record, dict):
                    continue
                fields = {
                    "eventName": record.get("eventName", ""),
                    "eventSource": record.get("eventSource", ""),
                    "awsRegion": record.get("awsRegion", ""),
                    "sourceIPAddress": record.get("sourceIPAddress", ""),
                    "userAgent": record.get("userAgent", ""),
                    "userIdentity": json.dumps(record.get("userIdentity", {})),
                    "requestParameters": json.dumps(record.get("requestParameters", {})),
                    "responseElements": json.dumps(record.get("responseElements", {})),
                    "errorCode": record.get("errorCode", ""),
                    "errorMessage": record.get("errorMessage", ""),
                }

                event_name = record.get("eventName", "")
                is_suspicious = event_name in self.SUSPICIOUS_EVENTS

                events.append(normalize_event(
                    timestamp=record.get("eventTime", ""),
                    source="cloudtrail",
                    event_id=event_name,
                    fields=fields,
                    raw=json.dumps(record),
                    line_number=i,
                    platform="aws",
                    category=f"CloudTrail: {event_name}" + (" ⚠️" if is_suspicious else ""),
                ))
        except Exception as e:
            logger.error(f"CloudTrail parse error: {e}")

        logger.info(f"Parsed {len(events)} CloudTrail events from {filepath}")
        return events


# ============================================================
# Azure Activity Log Parser
# ============================================================
class AzureActivityParser:
    """Parse Azure Activity Log JSON exports."""

    def parse(self, filepath: str) -> List[dict]:
        """Parse Azure Activity Log file."""
        events = []
        try:
            with open(filepath, "r") as f:
                data = json.load(f)

            if isinstance(data, list):
                records = data
            elif isinstance(data, dict):
                records = data.get("value") or data.get("records") or [data]
            else:
                records = []

            for i, record in enumerate(records, 1):
                if not isinstance(record, dict):
                    continue
                fields = {
                    "operationName": record.get("operationName", {}).get("value", "")
                        if isinstance(record.get("operationName"), dict)
                        else record.get("operationName", ""),
                    "status": record.get("status", {}).get("value", "")
                        if isinstance(record.get("status"), dict)
                        else record.get("status", ""),
                    "caller": record.get("caller", ""),
                    "category": record.get("category", {}).get("value", "")
                        if isinstance(record.get("category"), dict)
                        else record.get("category", ""),
                    "level": record.get("level", ""),
                    "resourceId": record.get("resourceId", ""),
                    "correlationId": record.get("correlationId", ""),
                }

                events.append(normalize_event(
                    timestamp=record.get("eventTimestamp", record.get("time", "")),
                    source="azure_activity",
                    event_id=fields["operationName"],
                    fields=fields,
                    raw=json.dumps(record),
                    line_number=i,
                    platform="azure",
                    category=f"Azure: {fields['operationName']}",
                ))
        except Exception as e:
            logger.error(f"Azure Activity parse error: {e}")

        logger.info(f"Parsed {len(events)} Azure Activity events from {filepath}")
        return events


# ============================================================
# GCP Audit Log Parser
# ============================================================
class GCPAuditParser:
    """Parse GCP Cloud Audit Log JSON exports."""

    def parse(self, filepath: str) -> List[dict]:
        """Parse GCP Audit Log file."""
        events = []
        try:
            with open(filepath, "r") as f:
                data = json.load(f)

            entries = data if isinstance(data, list) else data.get("entries", [data])

            for i, entry in enumerate(entries, 1):
                proto_payload = entry.get("protoPayload", {})
                fields = {
                    "methodName": proto_payload.get("methodName", ""),
                    "serviceName": proto_payload.get("serviceName", ""),
                    "callerIp": proto_payload.get("requestMetadata", {}).get("callerIp", ""),
                    "principalEmail": proto_payload.get("authenticationInfo", {}).get("principalEmail", ""),
                    "resourceName": entry.get("resource", {}).get("labels", {}).get("project_id", ""),
                    "severity": entry.get("severity", ""),
                }

                events.append(normalize_event(
                    timestamp=entry.get("timestamp", ""),
                    source="gcp_audit",
                    event_id=fields["methodName"],
                    fields=fields,
                    raw=json.dumps(entry),
                    line_number=i,
                    platform="gcp",
                    category=f"GCP: {fields['methodName']}",
                ))
        except Exception as e:
            logger.error(f"GCP Audit parse error: {e}")

        logger.info(f"Parsed {len(events)} GCP audit events from {filepath}")
        return events


# ============================================================
# Generic Text Log Parser
# ============================================================
class TextLogParser:
    """Parse generic text log files (.log, .txt, .syslog)."""

    TIMESTAMP_PATTERNS = [
        re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)"),
        re.compile(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),  # Syslog format
        re.compile(r"(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?)"),  # Apache format
        re.compile(r"(\d{10,13})"),  # Unix timestamp
    ]

    def parse(self, filepath: str) -> List[dict]:
        """Parse a generic text log file."""
        events = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    timestamp = ""
                    for pattern in self.TIMESTAMP_PATTERNS:
                        ts_match = pattern.search(line)
                        if ts_match:
                            timestamp = ts_match.group(1)
                            break

                    # Try to extract event ID if present
                    eid_match = re.search(r"EventID[=: ]+(\d+)", line, re.IGNORECASE)
                    event_id = eid_match.group(1) if eid_match else ""

                    fields = {}
                    # Extract username
                    for user_match in re.finditer(
                        r"(?:user|username|account)[=: ]+([a-zA-Z0-9_\-\.]+)", line, re.IGNORECASE
                    ):
                        fields["username"] = user_match.group(1)

                    # Extract IPs
                    for ip_match in re.finditer(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", line):
                        if "source_ip" not in fields:
                            fields["source_ip"] = ip_match.group(1)
                        else:
                            fields["dest_ip"] = ip_match.group(1)

                    events.append(normalize_event(
                        timestamp=timestamp,
                        source="text",
                        event_id=event_id,
                        fields=fields,
                        raw=line,
                        line_number=i,
                        platform="generic",
                    ))
        except Exception as e:
            logger.error(f"Text log parse error: {e}")

        logger.info(f"Parsed {len(events)} lines from {filepath}")
        return events


# ============================================================
# Parser Factory
# ============================================================
def get_parser(filepath: str):
    """
    Get the appropriate parser based on file extension and content.

    Auto-detects log types including Windows EVTX, Sysmon, Linux syslog,
    auth.log, journald, Apache/Nginx, firewall, cloud logs, and macOS.

    Args:
        filepath: Path to the log file.

    Returns:
        A parser instance appropriate for the file type.
    """
    # Lazy import Linux parsers to avoid circular imports
    from parsers.linux_parsers import (
        SyslogParser, AuthLogParser, JournaldParser,
        ApacheNginxParser, FirewallLogParser,
    )

    path = Path(filepath)
    ext = path.suffix.lower()
    name = path.name.lower()

    # --- Windows ---
    if ext == ".evtx":
        return EVTXParser()

    if "sysmon" in name:
        return SysmonParser()

    # --- JSON-based logs ---
    if ext == ".json":
        try:
            with open(filepath, "r") as f:
                start = f.read(2000)
            # AWS CloudTrail
            if "Records" in start and "eventSource" in start:
                return CloudTrailParser()
            # Azure Activity
            if "operationName" in start and ("azure" in start.lower() or "microsoft" in start.lower()):
                return AzureActivityParser()
            # GCP Audit
            if "protoPayload" in start or "gcp" in name:
                return GCPAuditParser()
            # macOS Unified Logs
            if "processImagePath" in start or "subsystem" in start:
                return MacOSLogParser()
            # Journald JSON export
            if "__REALTIME_TIMESTAMP" in start or "_SYSTEMD_UNIT" in start or "SYSLOG_IDENTIFIER" in start:
                return JournaldParser()
        except Exception:
            pass
        return TextLogParser()

    # --- Linux logs ---
    # Auth log (auth.log, secure)
    if any(x in name for x in ["auth.log", "secure", "auth_log"]):
        return AuthLogParser()

    # Auditd
    if "audit" in name and ext in (".log", ".txt", ""):
        return LinuxAuditdParser()

    # Firewall logs (ufw, iptables, firewall, kern)
    if any(x in name for x in ["ufw", "firewall", "iptables", "nftables", "kern.log"]):
        return FirewallLogParser()

    # Apache/Nginx access and error logs
    if any(x in name for x in ["access.log", "error.log", "apache", "nginx", "httpd"]):
        return ApacheNginxParser()

    # Syslog / messages
    if any(x in name for x in ["syslog", "messages", "daemon.log", "mail.log"]):
        return SyslogParser()

    # --- Content-based detection for .log and .txt ---
    if ext in (".log", ".txt", ".syslog", ""):
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                sample = f.read(3000)
            # Check for firewall patterns
            if "IN=" in sample and "OUT=" in sample and "SRC=" in sample:
                return FirewallLogParser()
            # Check for auth patterns
            if ("sshd[" in sample or "sudo:" in sample or "pam_unix" in sample):
                return AuthLogParser()
            # Check for web server patterns
            if re.search(r'"\s*(GET|POST|PUT|DELETE|HEAD)\s+/', sample):
                return ApacheNginxParser()
            # Check for syslog format
            if re.search(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+", sample):
                return SyslogParser()
        except Exception:
            pass

    return TextLogParser()


def compute_file_hashes(filepath: str) -> Dict[str, str]:
    """
    Compute MD5 and SHA256 hashes of a file.

    Args:
        filepath: Path to the file.

    Returns:
        Dictionary with 'md5' and 'sha256' keys.
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)

    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}
