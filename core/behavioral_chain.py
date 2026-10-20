"""
ThreatScope V2 — Behavioral Chaining Engine
Author: 0xSABRY

Detects multi-stage attacks by correlating events within configurable
time windows. If Event A happens within X minutes of Event B, triggers
a high-confidence composite alert.
"""

import logging
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger("threatscope.behavioral_chain")


# ============================================================
# Behavioral Chain Definitions
# ============================================================
BEHAVIORAL_CHAINS = [
    {
        "id": "BC-001",
        "name": "Reconnaissance to Exploitation",
        "description": "Port scan or vulnerability scan followed by exploitation attempt",
        "stages": [
            {"event_type": "port_scan", "labels": ["discovery", "network_scan"]},
            {"event_type": "exploitation", "labels": ["exploit", "initial_access"]},
        ],
        "window_minutes": 30,
        "severity": "critical",
        "confidence": 0.85,
        "mitre_chain": ["TA0043", "TA0001"],
    },
    {
        "id": "BC-002",
        "name": "Brute Force to Login Success",
        "description": "Multiple failed logins followed by successful authentication",
        "stages": [
            {"event_type": "failed_login", "labels": ["brute_force", "auth_failure"], "min_count": 5},
            {"event_type": "successful_login", "labels": ["auth_success", "logon"]},
        ],
        "window_minutes": 15,
        "severity": "high",
        "confidence": 0.90,
        "mitre_chain": ["TA0006", "TA0001"],
    },
    {
        "id": "BC-003",
        "name": "Credential Dump to Lateral Movement",
        "description": "Credential dumping tool executed followed by remote access to another host",
        "stages": [
            {"event_type": "credential_dump", "labels": ["mimikatz", "lsass", "credential_dumping", "hashdump"]},
            {"event_type": "lateral_move", "labels": ["psexec", "wmi_remote", "lateral_movement", "rdp_session"]},
        ],
        "window_minutes": 60,
        "severity": "critical",
        "confidence": 0.92,
        "mitre_chain": ["TA0006", "TA0008"],
    },
    {
        "id": "BC-004",
        "name": "Malware Download to Execution",
        "description": "File download from suspicious source followed by process execution",
        "stages": [
            {"event_type": "download", "labels": ["file_download", "web_download", "certutil", "bitsadmin"]},
            {"event_type": "execution", "labels": ["process_create", "script_execution", "powershell_exec"]},
        ],
        "window_minutes": 10,
        "severity": "high",
        "confidence": 0.80,
        "mitre_chain": ["TA0001", "TA0002"],
    },
    {
        "id": "BC-005",
        "name": "Defense Evasion to Persistence",
        "description": "Security tool disabled followed by persistence mechanism creation",
        "stages": [
            {"event_type": "defense_evasion", "labels": ["av_tamper", "firewall_disable", "etw_tamper"]},
            {"event_type": "persistence", "labels": ["scheduled_task", "registry_run", "service_create", "persistence"]},
        ],
        "window_minutes": 20,
        "severity": "critical",
        "confidence": 0.88,
        "mitre_chain": ["TA0005", "TA0003"],
    },
    {
        "id": "BC-006",
        "name": "Privilege Escalation to Data Access",
        "description": "Privilege escalation followed by access to sensitive data stores",
        "stages": [
            {"event_type": "priv_esc", "labels": ["privilege_escalation", "token_manipulation", "uac_bypass"]},
            {"event_type": "data_access", "labels": ["file_access", "database_query", "share_access", "collection"]},
        ],
        "window_minutes": 30,
        "severity": "high",
        "confidence": 0.78,
        "mitre_chain": ["TA0004", "TA0009"],
    },
    {
        "id": "BC-007",
        "name": "C2 Beacon to Exfiltration",
        "description": "Command & control beacon activity followed by data exfiltration",
        "stages": [
            {"event_type": "c2_beacon", "labels": ["command_and_control", "dns_tunnel", "beacon", "c2"]},
            {"event_type": "exfiltration", "labels": ["data_exfiltration", "large_upload", "dns_exfil"]},
        ],
        "window_minutes": 120,
        "severity": "critical",
        "confidence": 0.85,
        "mitre_chain": ["TA0011", "TA0010"],
    },
    {
        "id": "BC-008",
        "name": "Phishing to Payload Execution",
        "description": "Phishing email opened followed by suspicious attachment/macro execution",
        "stages": [
            {"event_type": "phishing", "labels": ["phishing_url", "email_attachment", "phishing"]},
            {"event_type": "macro_exec", "labels": ["macro_execution", "office_child_process", "script_execution"]},
        ],
        "window_minutes": 5,
        "severity": "critical",
        "confidence": 0.90,
        "mitre_chain": ["TA0001", "TA0002"],
    },
    {
        "id": "BC-009",
        "name": "Account Creation to Privilege Grant",
        "description": "New account created followed by admin privilege assignment",
        "stages": [
            {"event_type": "account_create", "labels": ["user_creation", "account_created"]},
            {"event_type": "priv_grant", "labels": ["admin_added", "group_membership", "privilege_grant"]},
        ],
        "window_minutes": 10,
        "severity": "high",
        "confidence": 0.82,
        "mitre_chain": ["TA0003", "TA0004"],
    },
    {
        "id": "BC-010",
        "name": "Log Clearing to Attack Activity",
        "description": "Event log cleared followed by suspicious activity — covering tracks before attack",
        "stages": [
            {"event_type": "log_clear", "labels": ["log_tampering", "event_log_cleared", "log_deletion"]},
            {"event_type": "attack_activity", "labels": ["lateral_movement", "credential_dumping", "data_exfiltration"]},
        ],
        "window_minutes": 60,
        "severity": "critical",
        "confidence": 0.88,
        "mitre_chain": ["TA0005", "TA0008"],
    },
    # V3 — Extended Behavioral Chains
    {
        "id": "BC-011",
        "name": "SSH Brute Force to Privilege Escalation",
        "description": "Repeated SSH auth failures followed by privilege escalation — Linux compromise chain",
        "stages": [
            {"event_type": "ssh_bruteforce", "labels": ["ssh_brute_force", "auth_failure", "failed_login"], "min_count": 10},
            {"event_type": "linux_priv_esc", "labels": ["linux_privesc", "privilege_escalation", "suid_abuse"]},
        ],
        "window_minutes": 30,
        "severity": "critical",
        "confidence": 0.90,
        "mitre_chain": ["TA0006", "TA0004"],
    },
    {
        "id": "BC-012",
        "name": "Cloud Credential Theft to IAM Abuse",
        "description": "Cloud credential compromise followed by IAM policy changes",
        "stages": [
            {"event_type": "cloud_cred", "labels": ["cloud_credential_theft", "credential_dumping", "access_key_theft"]},
            {"event_type": "iam_abuse", "labels": ["cloud_iam_abuse", "iam_policy_change", "role_creation"]},
        ],
        "window_minutes": 120,
        "severity": "critical",
        "confidence": 0.85,
        "mitre_chain": ["TA0006", "TA0004"],
    },
    {
        "id": "BC-013",
        "name": "Fileless to Memory Injection",
        "description": "AMSI bypass or LOLBin execution followed by process memory injection",
        "stages": [
            {"event_type": "fileless", "labels": ["fileless_malware", "amsi_bypass", "lolbin"]},
            {"event_type": "mem_inject", "labels": ["memory_injection", "process_hollowing", "reflective_dll"]},
        ],
        "window_minutes": 10,
        "severity": "critical",
        "confidence": 0.92,
        "mitre_chain": ["TA0005", "TA0004"],
    },
    {
        "id": "BC-014",
        "name": "Cryptojacking with Cron Persistence",
        "description": "Crypto mining activity followed by cron job creation for persistence",
        "stages": [
            {"event_type": "crypto", "labels": ["cryptojacking", "crypto_miner", "xmrig"]},
            {"event_type": "cron_persist", "labels": ["linux_cron_persistence", "cron_job", "scheduled_task"]},
        ],
        "window_minutes": 60,
        "severity": "high",
        "confidence": 0.85,
        "mitre_chain": ["TA0040", "TA0003"],
    },
    {
        "id": "BC-015",
        "name": "DNS Tunnel to Data Exfil",
        "description": "DNS tunnel establishment followed by data exfiltration via DNS",
        "stages": [
            {"event_type": "dns_tunnel", "labels": ["dns_tunneling", "dns_tunnel", "covert_channel"]},
            {"event_type": "dns_exfil", "labels": ["data_exfiltration", "dns_exfil", "large_upload"]},
        ],
        "window_minutes": 180,
        "severity": "critical",
        "confidence": 0.82,
        "mitre_chain": ["TA0011", "TA0010"],
    },
]


class TimeWindowEvent:
    """Represents an event in the behavioral chain timeline."""

    def __init__(self, timestamp: datetime, event_type: str, labels: List[str],
                 raw_data: dict = None, line_number: int = 0):
        self.timestamp = timestamp
        self.event_type = event_type
        self.labels = set(labels)
        self.raw_data = raw_data or {}
        self.line_number = line_number


class BehavioralChainEngine:
    """
    Detects multi-stage attacks by correlating events within time windows.
    Uses configurable chain definitions to catch attack patterns that
    single rules miss.
    """

    def __init__(self, custom_chains: Optional[List[dict]] = None,
                 default_window_minutes: int = 15):
        """
        Initialize the behavioral chaining engine.

        Args:
            custom_chains: Optional list of custom chain definitions.
            default_window_minutes: Default time window if not specified in chain.
        """
        self.chains = BEHAVIORAL_CHAINS.copy()
        if custom_chains:
            self.chains.extend(custom_chains)
        self.default_window = default_window_minutes
        self.events: List[TimeWindowEvent] = []
        self.triggered_chains: List[dict] = []

    def add_event(self, timestamp: datetime, labels: List[str],
                  raw_data: dict = None, line_number: int = 0):
        """
        Add an event to the timeline for chain analysis.

        Args:
            timestamp: Event timestamp.
            labels: Category labels associated with the event.
            raw_data: Original event data.
            line_number: Source line number.
        """
        event = TimeWindowEvent(
            timestamp=timestamp,
            event_type="|".join(labels),
            labels=labels,
            raw_data=raw_data,
            line_number=line_number,
        )
        self.events.append(event)

    @staticmethod
    def _parse_timestamp(value) -> Optional[datetime]:
        """
        Parse a timestamp from findings/timeline into a naive ``datetime``.

        Accepts ``datetime`` objects and the common ISO-8601 / log formats.
        Returns ``None`` when the value cannot be parsed (instead of silently
        dropping the whole feed on the first bad record).
        """
        if isinstance(value, datetime):
            return value.replace(tzinfo=None) if value.tzinfo else value
        if not isinstance(value, str) or not value.strip():
            return None

        s = value.strip()
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00").replace("z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            pass

        for fmt, length in (
            ("%Y-%m-%dT%H:%M:%S.%f", 26),
            ("%Y-%m-%dT%H:%M:%S", 19),
            ("%Y-%m-%d %H:%M:%S.%f", 26),
            ("%Y-%m-%d %H:%M:%S", 19),
            ("%d/%b/%Y:%H:%M:%S", 20),
        ):
            try:
                return datetime.strptime(s[:length], fmt)
            except (ValueError, TypeError):
                continue
        return None

    @staticmethod
    def _derive_labels(category: str, entry: dict) -> List[str]:
        """
        Build the label set for a finding/timeline entry.

        Stage labels are snake_case rule identifiers (e.g. ``brute_force``),
        which match the analyzer's builtin rule IDs and the ``category`` /
        ``rule_id`` values carried by findings.
        """
        labels = set()
        if category:
            labels.add(str(category).lower())
        rule_id = entry.get("rule_id")
        if rule_id:
            labels.add(str(rule_id).lower())
        return list(labels)

    def add_events_from_findings(self, findings: Dict[str, list], timeline: List[dict]):
        """
        Bulk add events from analysis findings and timeline.

        Findings are preferred (they carry ``rule_id`` and ``timestamp``);
        timeline entries are only used when no findings are available so that
        events are not double-counted (which would inflate ``min_count``).

        Args:
            findings: Category -> list of findings from the analyzer.
            timeline: Chronological list of timeline events.
        """
        added = 0
        for category, finding_list in (findings or {}).items():
            for finding in finding_list or []:
                ts = self._parse_timestamp(finding.get("timestamp"))
                if ts is None:
                    continue
                self.add_event(
                    ts,
                    self._derive_labels(category, finding),
                    raw_data=finding,
                    line_number=finding.get("line_number", 0),
                )
                added += 1

        if added:
            return

        for entry in timeline or []:
            ts = self._parse_timestamp(entry.get("timestamp"))
            if ts is None:
                continue
            self.add_event(
                ts,
                self._derive_labels(entry.get("category", ""), entry),
                raw_data=entry,
                line_number=entry.get("line_number", 0),
            )

    def analyze(self) -> List[dict]:
        """
        Run behavioral chain analysis on all collected events.

        Returns:
            List of triggered chain alerts with evidence.
        """
        self.triggered_chains = []

        if len(self.events) < 2:
            return []

        # Sort events by timestamp
        self.events.sort(key=lambda e: e.timestamp)

        for chain in self.chains:
            matches = self._check_chain(chain)
            if matches:
                self.triggered_chains.extend(matches)

        # Sort by confidence
        self.triggered_chains.sort(key=lambda c: c["confidence"], reverse=True)
        return self.triggered_chains

    def _check_chain(self, chain: dict) -> List[dict]:
        """
        Check if a specific behavioral chain pattern exists in the events.

        Args:
            chain: Chain definition dictionary.

        Returns:
            List of matches for this chain.
        """
        stages = chain["stages"]
        window = timedelta(minutes=chain.get("window_minutes", self.default_window))
        matches = []

        if len(stages) < 2:
            return []

        # Find first-stage events and walk the chain forward in time.
        n_events = len(self.events)
        for i, event in enumerate(self.events):
            if not self._event_matches_stage(event, stages[0]):
                continue

            chain_evidence: List[TimeWindowEvent] = []
            current_stage = 0
            stage_count = 0
            window_start = event.timestamp

            for j in range(i, n_events):
                candidate = self.events[j]

                # Enforce the chain's time window
                if candidate.timestamp - window_start > window:
                    break

                if self._event_matches_stage(candidate, stages[current_stage]):
                    chain_evidence.append(candidate)
                    stage_count += 1
                    required = int(stages[current_stage].get("min_count", 1) or 1)
                    if stage_count >= required:
                        current_stage += 1
                        stage_count = 0

                if current_stage >= len(stages):
                    match = {
                        "chain_id": chain["id"],
                        "name": chain["name"],
                        "description": chain["description"],
                        "severity": chain["severity"],
                        "confidence": chain["confidence"],
                        "mitre_chain": chain.get("mitre_chain", []),
                        "window_minutes": chain.get("window_minutes", self.default_window),
                        "start_time": chain_evidence[0].timestamp.isoformat(),
                        "end_time": chain_evidence[-1].timestamp.isoformat(),
                        "duration_seconds": (
                            chain_evidence[-1].timestamp - chain_evidence[0].timestamp
                        ).total_seconds(),
                        "stages_matched": len(stages),
                        "evidence": [
                            {
                                "timestamp": e.timestamp.isoformat(),
                                "labels": list(e.labels),
                                "line_number": e.line_number,
                                "preview": str(e.raw_data.get("raw", ""))[:200],
                            }
                            for e in chain_evidence
                        ],
                    }
                    matches.append(match)
                    break

        return matches

    def _event_matches_stage(self, event: TimeWindowEvent, stage: dict) -> bool:
        """
        Check if an event matches a chain stage definition.

        Args:
            event: The event to check.
            stage: Stage definition with labels.

        Returns:
            True if the event matches the stage.
        """
        stage_labels = set(stage.get("labels", []))
        return bool(event.labels & stage_labels)

    def get_summary(self) -> dict:
        """Get a summary of behavioral chain analysis results."""
        return {
            "total_events": len(self.events),
            "chains_triggered": len(self.triggered_chains),
            "critical_chains": len([c for c in self.triggered_chains if c["severity"] == "critical"]),
            "high_chains": len([c for c in self.triggered_chains if c["severity"] == "high"]),
            "chains": self.triggered_chains,
        }
