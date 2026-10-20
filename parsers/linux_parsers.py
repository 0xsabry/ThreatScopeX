"""
ThreatScope V3 — Linux Log Parsers
Author: 0xSABRY

Dedicated parsers for Linux log sources:
  - Syslog (/var/log/syslog, /var/log/messages)
  - Auth log (/var/log/auth.log, /var/log/secure)
  - Journald (journalctl --output=json exports)
  - Apache / Nginx access & error logs
  - Firewall logs (iptables, ufw, nftables)

All parsers produce normalized events compatible with the
ThreatScope analyzer pipeline.
"""

import re
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

logger = logging.getLogger("threatscope.parsers.linux")

# Re-use normalize_event from the main parsers module
from parsers.log_parsers import normalize_event


# ============================================================
# Syslog Parser (RFC 3164 / RFC 5424)
# ============================================================
class SyslogParser:
    """
    Parse standard Linux syslog files (/var/log/syslog, /var/log/messages).

    Handles both RFC 3164 (BSD) and RFC 5424 (IETF) syslog formats with
    facility/severity extraction and process/PID parsing.
    """

    # RFC 3164: "Mon DD HH:MM:SS hostname process[pid]: message"
    RFC3164_PATTERN = re.compile(
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
        r"(\S+)\s+"                                       # hostname
        r"(\S+?)(?:\[(\d+)\])?:\s+"                       # process[pid]
        r"(.*)$"                                          # message
    )

    # RFC 5424: "<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG"
    RFC5424_PATTERN = re.compile(
        r"^<(\d{1,3})>"                                    # PRI
        r"(\d+)\s+"                                        # VERSION
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*)\s+"   # TIMESTAMP
        r"(\S+)\s+"                                        # HOSTNAME
        r"(\S+)\s+"                                        # APP-NAME
        r"(\S+)\s+"                                        # PROCID
        r"(\S+)\s+"                                        # MSGID
        r"(.*)$"                                           # MESSAGE
    )

    SYSLOG_FACILITIES = {
        0: "kern", 1: "user", 2: "mail", 3: "daemon",
        4: "auth", 5: "syslog", 6: "lpr", 7: "news",
        8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
        16: "local0", 17: "local1", 18: "local2", 19: "local3",
        20: "local4", 21: "local5", 22: "local6", 23: "local7",
    }

    SYSLOG_SEVERITIES = {
        0: "emerg", 1: "alert", 2: "crit", 3: "err",
        4: "warning", 5: "notice", 6: "info", 7: "debug",
    }

    def parse(self, filepath: str) -> List[dict]:
        """
        Parse a syslog file into normalized events.

        Args:
            filepath: Path to the syslog file.

        Returns:
            List of normalized event dictionaries.
        """
        events = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    event = self._parse_line(line, i)
                    if event:
                        events.append(event)
        except Exception as e:
            logger.error(f"Syslog parse error: {e}")

        logger.info(f"Parsed {len(events)} syslog events from {filepath}")
        return events

    def _parse_line(self, line: str, line_number: int) -> Optional[dict]:
        """Parse a single syslog line."""
        # Try RFC 5424 first (more specific)
        match = self.RFC5424_PATTERN.match(line)
        if match:
            pri = int(match.group(1))
            facility_code = pri >> 3
            severity_code = pri & 0x07
            fields = {
                "hostname": match.group(4),
                "process": match.group(5),
                "pid": match.group(6) if match.group(6) != "-" else "",
                "msgid": match.group(7) if match.group(7) != "-" else "",
                "facility": self.SYSLOG_FACILITIES.get(facility_code, str(facility_code)),
                "severity": self.SYSLOG_SEVERITIES.get(severity_code, str(severity_code)),
                "syslog_version": match.group(2),
            }
            return normalize_event(
                timestamp=match.group(3),
                source="syslog_rfc5424",
                event_id=fields["process"],
                fields=fields,
                raw=line,
                line_number=line_number,
                platform="linux",
                category=f"Syslog: {fields['process']}",
            )

        # Try RFC 3164
        match = self.RFC3164_PATTERN.match(line)
        if match:
            fields = {
                "hostname": match.group(2),
                "process": match.group(3),
                "pid": match.group(4) or "",
                "message": match.group(5),
            }
            return normalize_event(
                timestamp=match.group(1),
                source="syslog_rfc3164",
                event_id=fields["process"],
                fields=fields,
                raw=line,
                line_number=line_number,
                platform="linux",
                category=f"Syslog: {fields['process']}",
            )

        # Fallback — unstructured syslog line
        return normalize_event(
            timestamp="",
            source="syslog_raw",
            raw=line,
            line_number=line_number,
            platform="linux",
        )


# ============================================================
# Auth Log Parser (/var/log/auth.log, /var/log/secure)
# ============================================================
class AuthLogParser:
    """
    Parse Linux authentication logs for SSH, sudo, PAM, and account events.

    Extracts:
      - SSH login successes/failures with IP, user, port, auth method
      - sudo commands with user and target user
      - PAM authentication events
      - su session opens/closes
      - Account creation/modification/deletion
      - Password change attempts
    """

    # SSH auth patterns
    SSH_ACCEPTED = re.compile(
        r"sshd\[(\d+)\]:\s+Accepted\s+(\w+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
    )
    SSH_FAILED = re.compile(
        r"sshd\[(\d+)\]:\s+Failed\s+(\w+)\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
    )
    SSH_INVALID_USER = re.compile(
        r"sshd\[(\d+)\]:\s+Invalid\s+user\s+(\S+)\s+from\s+(\S+)"
    )
    SSH_DISCONNECT = re.compile(
        r"sshd\[(\d+)\]:\s+Disconnected\s+from\s+(?:authenticating\s+)?user\s+(\S+)\s+(\S+)"
    )
    SSH_MAX_AUTH = re.compile(
        r"sshd\[(\d+)\]:\s+error:\s+maximum\s+authentication\s+attempts\s+exceeded\s+for\s+(?:invalid\s+user\s+)?(\S+)"
    )

    # Sudo patterns
    SUDO_CMD = re.compile(
        r"sudo\S*:\s+(\S+)\s+:\s+TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)"
    )
    SUDO_FAIL = re.compile(
        r"sudo\S*:\s+(\S+)\s+:\s+.*authentication\s+failure"
    )

    # PAM patterns
    PAM_AUTH = re.compile(
        r"pam_unix\((\S+):(\w+)\):\s+(.*)"
    )

    # Account management
    USERADD = re.compile(r"useradd\[\d+\]:\s+new\s+user:\s+name=(\S+)")
    USERDEL = re.compile(r"userdel\[\d+\]:\s+delete\s+user\s+'(\S+)'")
    PASSWD_CHANGE = re.compile(r"passwd\[\d+\]:\s+pam_unix.*:\s+password\s+changed\s+for\s+(\S+)")
    GROUPADD = re.compile(r"groupadd\[\d+\]:\s+new\s+group:\s+name=(\S+)")

    # Timestamp pattern (syslog-style)
    TIMESTAMP_RE = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

    def parse(self, filepath: str) -> List[dict]:
        """
        Parse an auth.log / secure log file.

        Args:
            filepath: Path to the auth log file.

        Returns:
            List of normalized events.
        """
        events = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    event = self._parse_line(line, i)
                    if event:
                        events.append(event)
        except Exception as e:
            logger.error(f"Auth log parse error: {e}")

        logger.info(f"Parsed {len(events)} auth log events from {filepath}")
        return events

    def _parse_line(self, line: str, line_number: int) -> Optional[dict]:
        """Parse a single auth log line with specific pattern matching."""
        # Extract timestamp
        ts_match = self.TIMESTAMP_RE.search(line)
        timestamp = ts_match.group(1) if ts_match else ""

        fields = {}
        category = "Auth"
        event_id = ""

        # SSH Accepted
        m = self.SSH_ACCEPTED.search(line)
        if m:
            fields = {
                "pid": m.group(1), "auth_method": m.group(2),
                "username": m.group(3), "source_ip": m.group(4),
                "port": m.group(5), "action": "accepted",
            }
            category = "SSH: Login Success"
            event_id = "ssh_accepted"

        # SSH Failed
        if not fields:
            m = self.SSH_FAILED.search(line)
            if m:
                fields = {
                    "pid": m.group(1), "auth_method": m.group(2),
                    "username": m.group(3), "source_ip": m.group(4),
                    "port": m.group(5), "action": "failed",
                }
                category = "SSH: Login Failed"
                event_id = "ssh_failed"

        # SSH Invalid User
        if not fields:
            m = self.SSH_INVALID_USER.search(line)
            if m:
                fields = {
                    "pid": m.group(1), "username": m.group(2),
                    "source_ip": m.group(3), "action": "invalid_user",
                }
                category = "SSH: Invalid User"
                event_id = "ssh_invalid_user"

        # SSH Max Auth
        if not fields:
            m = self.SSH_MAX_AUTH.search(line)
            if m:
                fields = {
                    "pid": m.group(1), "username": m.group(2),
                    "action": "max_auth_exceeded",
                }
                category = "SSH: Max Auth Exceeded"
                event_id = "ssh_max_auth"

        # Sudo Command
        if not fields:
            m = self.SUDO_CMD.search(line)
            if m:
                fields = {
                    "username": m.group(1), "tty": m.group(2),
                    "pwd": m.group(3), "target_user": m.group(4),
                    "command": m.group(5).strip(), "action": "sudo_command",
                }
                category = "Sudo: Command Executed"
                event_id = "sudo_command"

        # Sudo Failure
        if not fields:
            m = self.SUDO_FAIL.search(line)
            if m:
                fields = {"username": m.group(1), "action": "sudo_auth_failure"}
                category = "Sudo: Auth Failure"
                event_id = "sudo_failure"

        # PAM events
        if not fields:
            m = self.PAM_AUTH.search(line)
            if m:
                fields = {
                    "pam_service": m.group(1), "pam_type": m.group(2),
                    "pam_message": m.group(3), "action": "pam_event",
                }
                category = f"PAM: {m.group(1)}"
                event_id = "pam_event"

        # User/group management
        if not fields:
            for pattern, action, cat in [
                (self.USERADD, "user_created", "Account: User Created"),
                (self.USERDEL, "user_deleted", "Account: User Deleted"),
                (self.PASSWD_CHANGE, "password_changed", "Account: Password Changed"),
                (self.GROUPADD, "group_created", "Account: Group Created"),
            ]:
                m = pattern.search(line)
                if m:
                    fields = {"username": m.group(1), "action": action}
                    category = cat
                    event_id = action
                    break

        # Fallback for unmatched auth lines
        if not fields:
            fields = {"message": line}
            category = "Auth: Other"
            event_id = "auth_other"

        return normalize_event(
            timestamp=timestamp,
            source="auth_log",
            event_id=event_id,
            fields=fields,
            raw=line,
            line_number=line_number,
            platform="linux",
            category=category,
        )


# ============================================================
# Journald Parser (journalctl --output=json)
# ============================================================
class JournaldParser:
    """
    Parse systemd journal exports in JSON format.

    Expects output from:
        journalctl --output=json > journal_export.json
    or  journalctl --output=json-pretty > journal_export.json

    Extracts full systemd metadata including unit, priority,
    boot ID, transport, and structured fields.
    """

    PRIORITY_MAP = {
        "0": "emerg", "1": "alert", "2": "crit", "3": "err",
        "4": "warning", "5": "notice", "6": "info", "7": "debug",
    }

    def parse(self, filepath: str) -> List[dict]:
        """
        Parse a journald JSON export.

        Args:
            filepath: Path to the JSON journal export.

        Returns:
            List of normalized events.
        """
        events = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read().strip()

            # Handle JSON Lines (one JSON object per line) or JSON array
            if content.startswith("["):
                entries = json.loads(content)
            else:
                entries = []
                for line in content.split("\n"):
                    line = line.strip().rstrip(",")
                    if line and line.startswith("{"):
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

            for i, entry in enumerate(entries, 1):
                event = self._parse_entry(entry, i)
                if event:
                    events.append(event)

        except Exception as e:
            logger.error(f"Journald parse error: {e}")

        logger.info(f"Parsed {len(events)} journald events from {filepath}")
        return events

    def _parse_entry(self, entry: dict, line_number: int) -> Optional[dict]:
        """Parse a single journald JSON entry."""
        # Timestamp: __REALTIME_TIMESTAMP is in microseconds since epoch
        timestamp = ""
        rt = entry.get("__REALTIME_TIMESTAMP", "")
        if rt:
            try:
                ts_seconds = int(rt) / 1_000_000
                timestamp = datetime.utcfromtimestamp(ts_seconds).isoformat()
            except (ValueError, OSError):
                timestamp = str(rt)

        priority_str = str(entry.get("PRIORITY", "6"))
        fields = {
            "unit": entry.get("_SYSTEMD_UNIT", entry.get("UNIT", "")),
            "process": entry.get("_COMM", entry.get("SYSLOG_IDENTIFIER", "")),
            "pid": str(entry.get("_PID", "")),
            "uid": str(entry.get("_UID", "")),
            "gid": str(entry.get("_GID", "")),
            "hostname": entry.get("_HOSTNAME", ""),
            "boot_id": entry.get("_BOOT_ID", ""),
            "priority": self.PRIORITY_MAP.get(priority_str, priority_str),
            "transport": entry.get("_TRANSPORT", ""),
            "exe": entry.get("_EXE", ""),
            "cmdline": entry.get("_CMDLINE", ""),
        }

        message = entry.get("MESSAGE", "")
        if isinstance(message, list):
            # Binary message encoded as list of ints
            try:
                message = bytes(message).decode("utf-8", errors="replace")
            except Exception:
                message = str(message)

        return normalize_event(
            timestamp=timestamp,
            source="journald",
            event_id=fields["process"],
            fields=fields,
            raw=message if message else json.dumps(entry),
            line_number=line_number,
            platform="linux",
            category=f"Journal: {fields.get('unit', fields.get('process', 'unknown'))}",
        )


# ============================================================
# Apache / Nginx Access & Error Log Parser
# ============================================================
class ApacheNginxParser:
    """
    Parse Apache Combined/Common and Nginx access/error logs.

    Supports:
      - Apache Common Log Format (CLF)
      - Apache Combined Log Format
      - Nginx access logs (default format)
      - Apache/Nginx error logs
    """

    # Combined/Common log format:
    # 192.168.1.1 - user [10/Oct/2023:13:55:36 -0700] "GET /page HTTP/1.1" 200 2326 "referer" "user-agent"
    COMBINED_PATTERN = re.compile(
        r'^(\S+)\s+'            # IP
        r'(\S+)\s+'             # ident
        r'(\S+)\s+'             # user
        r'\[([^\]]+)\]\s+'      # timestamp
        r'"(\S+)\s+'            # method
        r'(\S+)\s+'             # path
        r'(\S+)"\s+'            # protocol
        r'(\d{3})\s+'           # status
        r'(\S+)'                # size
        r'(?:\s+"([^"]*)")?'    # referer
        r'(?:\s+"([^"]*)")?'    # user-agent
    )

    # Error log: [timestamp] [module:level] [pid N] [client IP:port] message
    ERROR_PATTERN = re.compile(
        r'^\[([^\]]+)\]\s+'      # timestamp
        r'\[([^\]]*)\]\s+'       # module:level
        r'(?:\[pid\s+(\d+)\]\s+)?'  # pid (optional)
        r'(?:\[client\s+([^\]]+)\]\s+)?'  # client IP (optional)
        r'(.*)$'                 # message
    )

    # Suspicious status codes and paths
    SUSPICIOUS_STATUSES = {"400", "401", "403", "404", "405", "500", "502", "503"}
    SUSPICIOUS_PATHS = {
        "/admin", "/wp-admin", "/wp-login.php", "/phpmyadmin",
        "/shell", "/cmd", "/eval", "/.env", "/config",
        "/etc/passwd", "/etc/shadow", "../", "..%2f",
        "/cgi-bin/", "/manager/html",
    }

    def parse(self, filepath: str) -> List[dict]:
        """
        Parse an Apache or Nginx log file.

        Args:
            filepath: Path to the access or error log file.

        Returns:
            List of normalized events.
        """
        events = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    event = self._parse_access_line(line, i)
                    if not event:
                        event = self._parse_error_line(line, i)
                    if event:
                        events.append(event)
        except Exception as e:
            logger.error(f"Apache/Nginx parse error: {e}")

        logger.info(f"Parsed {len(events)} web server events from {filepath}")
        return events

    def _parse_access_line(self, line: str, line_number: int) -> Optional[dict]:
        """Parse a combined/common log format line."""
        m = self.COMBINED_PATTERN.match(line)
        if not m:
            return None

        ip = m.group(1)
        method = m.group(5)
        path = m.group(6)
        status = m.group(8)
        size = m.group(9) if m.group(9) != "-" else "0"
        referer = m.group(10) or ""
        user_agent = m.group(11) or ""

        # Flag suspicious requests
        is_suspicious = (
            status in self.SUSPICIOUS_STATUSES
            or any(s in path.lower() for s in self.SUSPICIOUS_PATHS)
        )

        fields = {
            "source_ip": ip,
            "ident": m.group(2),
            "username": m.group(3) if m.group(3) != "-" else "",
            "method": method,
            "path": path,
            "protocol": m.group(7),
            "status_code": status,
            "response_size": size,
            "referer": referer,
            "user_agent": user_agent,
            "suspicious": is_suspicious,
        }

        return normalize_event(
            timestamp=m.group(4),
            source="webserver_access",
            event_id=f"{method}_{status}",
            fields=fields,
            raw=line,
            line_number=line_number,
            platform="linux",
            category=f"Web: {method} {status}" + (" ⚠️" if is_suspicious else ""),
        )

    def _parse_error_line(self, line: str, line_number: int) -> Optional[dict]:
        """Parse an Apache/Nginx error log line."""
        m = self.ERROR_PATTERN.match(line)
        if not m:
            return None

        fields = {
            "module_level": m.group(2),
            "pid": m.group(3) or "",
            "client_ip": m.group(4) or "",
            "error_message": m.group(5),
        }

        return normalize_event(
            timestamp=m.group(1),
            source="webserver_error",
            event_id="error",
            fields=fields,
            raw=line,
            line_number=line_number,
            platform="linux",
            category=f"Web Error: {fields['module_level']}",
        )


# ============================================================
# Firewall Log Parser (iptables / ufw / nftables)
# ============================================================
class FirewallLogParser:
    """
    Parse Linux firewall log entries from iptables, ufw, and nftables.

    Typically found in /var/log/kern.log, /var/log/syslog, or /var/log/ufw.log.
    Extracts source/dest IP, ports, protocol, action (ACCEPT/DROP/REJECT),
    interface, and flags.
    """

    # iptables/nftables kernel log pattern
    IPTABLES_PATTERN = re.compile(
        r"(?:kernel:\s+)?\[?\s*[\d.]*\]?\s*"
        r"(?:\[UFW\s+(\w+)\]\s*)?"                     # UFW action
        r"(?:(\w+)\s+)?"                                 # chain/prefix
        r"IN=(\S*)\s+"                                   # input interface
        r"OUT=(\S*)\s+"                                  # output interface
        r"(?:MAC=(\S+)\s+)?"                             # MAC
        r"SRC=(\S+)\s+"                                  # source IP
        r"DST=(\S+)\s+"                                  # dest IP
        r"LEN=(\d+)\s+"                                  # length
        r".*?"
        r"PROTO=(\w+)"                                   # protocol
        r"(?:.*?SPT=(\d+))?"                             # source port
        r"(?:.*?DPT=(\d+))?"                             # dest port
    )

    # UFW simple pattern
    UFW_PATTERN = re.compile(
        r"\[UFW\s+(\w+)\]\s+"
        r"IN=(\S*)\s+OUT=(\S*)\s+.*?"
        r"SRC=(\S+)\s+DST=(\S+)\s+.*?"
        r"PROTO=(\w+)"
        r"(?:.*?SPT=(\d+))?"
        r"(?:.*?DPT=(\d+))?"
    )

    TIMESTAMP_RE = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

    def parse(self, filepath: str) -> List[dict]:
        """
        Parse a firewall log file.

        Args:
            filepath: Path to the firewall log.

        Returns:
            List of normalized events.
        """
        events = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    event = self._parse_line(line, i)
                    if event:
                        events.append(event)
        except Exception as e:
            logger.error(f"Firewall log parse error: {e}")

        logger.info(f"Parsed {len(events)} firewall events from {filepath}")
        return events

    def _parse_line(self, line: str, line_number: int) -> Optional[dict]:
        """Parse a single firewall log line."""
        # Extract timestamp
        ts_match = self.TIMESTAMP_RE.search(line)
        timestamp = ts_match.group(1) if ts_match else ""

        # Try iptables pattern first, then fall back to the UFW pattern.
        m = self.IPTABLES_PATTERN.search(line)
        is_iptables = m is not None
        if not m:
            m = self.UFW_PATTERN.search(line)
            if not m:
                return None  # Not a firewall log line

        # Extract based on which pattern matched. ``lastindex`` is unreliable
        # here because trailing groups are optional, so track the pattern
        # explicitly instead of inferring it from the match object.
        if is_iptables:
            # Full iptables/nftables pattern
            ufw_action = m.group(1) or ""
            chain = m.group(2) or ""
            in_iface = m.group(3) or ""
            out_iface = m.group(4) or ""
            src_ip = m.group(6)
            dst_ip = m.group(7)
            length = m.group(8)
            proto = m.group(9)
            spt = m.group(10) or ""
            dpt = m.group(11) or ""
            action = ufw_action or chain
        else:
            # UFW pattern
            action = m.group(1) or "UNKNOWN"
            in_iface = m.group(2) or ""
            out_iface = m.group(3) or ""
            src_ip = m.group(4)
            dst_ip = m.group(5)
            proto = m.group(6)
            spt = m.group(7) or ""
            dpt = m.group(8) or ""
            length = ""

        fields = {
            "action": action.upper(),
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "source_port": spt,
            "dest_port": dpt,
            "protocol": proto.upper(),
            "in_interface": in_iface,
            "out_interface": out_iface,
            "length": length,
        }

        # Determine severity based on action
        is_blocked = action.upper() in ("DROP", "BLOCK", "REJECT", "DENY")
        category_prefix = "Firewall: BLOCKED" if is_blocked else "Firewall: ALLOWED"

        return normalize_event(
            timestamp=timestamp,
            source="firewall",
            event_id=f"fw_{action.lower()}",
            fields=fields,
            raw=line,
            line_number=line_number,
            platform="linux",
            category=f"{category_prefix} {proto} {src_ip}:{spt} → {dst_ip}:{dpt}",
        )
