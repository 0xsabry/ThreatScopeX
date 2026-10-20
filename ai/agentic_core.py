"""
ThreatScope V3.5 — Hypothesis-Driven Agentic AI Copilot
Author: 0xSABRY

Next-generation AI analysis engine that operates as an autonomous
investigation agent rather than a simple Q&A bot:
  - AgenticCopilot: Orchestrates multi-step investigation workflows
  - HypothesisEngine: Generates, scores, and refines hypotheses from findings
  - EvidenceCollector: Systematically gathers and grades supporting evidence

Extends ai/ai_core.py AICore with structured reasoning, hypothesis
trees, and autonomous investigation loops. Uses OpenAI API with
graceful degradation to offline heuristic mode.
"""

import json
import logging
import hashlib
import re
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from typing import (
    Dict, List, Optional, Set, Tuple, Any, Generator,
)
from enum import Enum

logger = logging.getLogger("threatscope.agentic")

# Import the base AICore for LLM access
try:
    from ai.ai_core import AICore
    AI_CORE_AVAILABLE = True
except ImportError:
    AI_CORE_AVAILABLE = False
    logger.warning("ai.ai_core not available — agentic AI will use offline mode")

# MITRE technique → tactic mappings (shared with the purple-team verifier)
try:
    from core.atomic_verifier import TECHNIQUE_TACTIC_MAP, MITRE_TACTICS
except ImportError:
    TECHNIQUE_TACTIC_MAP: Dict[str, List[str]] = {}
    MITRE_TACTICS: Dict[str, Dict[str, Any]] = {}


# ============================================================
# Enums & Constants
# ============================================================

class HypothesisStatus(Enum):
    """Status of a hypothesis in the investigation."""
    PROPOSED = "proposed"
    INVESTIGATING = "investigating"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class EvidenceGrade(Enum):
    """Evidence quality grading."""
    STRONG = "strong"          # Direct, unambiguous indicator
    MODERATE = "moderate"      # Circumstantial but supportive
    WEAK = "weak"              # Tangential or noisy
    CONTRADICTORY = "contradictory"  # Contradicts hypothesis


class InvestigationPhase(Enum):
    """Phases of the agentic investigation lifecycle."""
    TRIAGE = "triage"
    HYPOTHESIS_GENERATION = "hypothesis_generation"
    EVIDENCE_COLLECTION = "evidence_collection"
    ANALYSIS = "analysis"
    CONCLUSION = "conclusion"
    REPORTING = "reporting"


# Mapping from MITRE tactics to investigation priorities
TACTIC_PRIORITY = {
    "Initial Access":       8,
    "Execution":            9,
    "Persistence":          7,
    "Privilege Escalation": 9,
    "Defense Evasion":      8,
    "Credential Access":    10,
    "Discovery":            5,
    "Lateral Movement":     9,
    "Collection":           6,
    "Exfiltration":         10,
    "Command and Control":  9,
    "Impact":               10,
    "Resource Development": 4,
    "Reconnaissance":       3,
}


# ============================================================
# Evidence Item
# ============================================================

class Evidence:
    """
    A single piece of evidence supporting or refuting a hypothesis.

    Attributes:
        evidence_id: Unique evidence identifier.
        description: What was found.
        source: Where it came from (finding, IOC, timeline, etc.).
        grade: Evidence quality grade.
        confidence: Confidence score (0.0 – 1.0).
        data: Raw data or reference to the source item.
        timestamp: When the evidence was recorded.
        tags: Associated tags (MITRE techniques, categories).
    """

    __slots__ = (
        "evidence_id", "description", "source", "grade",
        "confidence", "data", "timestamp", "tags",
        "supports_hypothesis",
    )

    def __init__(
        self,
        description: str,
        source: str,
        grade: EvidenceGrade = EvidenceGrade.MODERATE,
        confidence: float = 0.5,
        data: Optional[Any] = None,
        tags: Optional[List[str]] = None,
        supports_hypothesis: bool = True,
    ) -> None:
        self.description = description
        self.source = source
        self.grade = grade
        self.confidence = max(0.0, min(1.0, confidence))
        self.data = data
        self.tags = tags or []
        self.supports_hypothesis = supports_hypothesis
        self.timestamp = datetime.now(timezone.utc).isoformat()

        seed = f"{description}:{source}:{self.timestamp}"
        self.evidence_id = hashlib.md5(seed.encode()).hexdigest()[:10]

    @property
    def weight(self) -> float:
        """Compute weighted score: grade factor × confidence."""
        grade_factors = {
            EvidenceGrade.STRONG: 1.0,
            EvidenceGrade.MODERATE: 0.6,
            EvidenceGrade.WEAK: 0.3,
            EvidenceGrade.CONTRADICTORY: -0.8,
        }
        factor = grade_factors.get(self.grade, 0.5)
        if not self.supports_hypothesis:
            factor = -abs(factor)
        return factor * self.confidence

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "evidence_id": self.evidence_id,
            "description": self.description,
            "source": self.source,
            "grade": self.grade.value,
            "confidence": round(self.confidence, 3),
            "weight": round(self.weight, 3),
            "supports_hypothesis": self.supports_hypothesis,
            "tags": self.tags,
            "timestamp": self.timestamp,
        }


# ============================================================
# Hypothesis
# ============================================================

class Hypothesis:
    """
    An investigative hypothesis about an incident.

    Attributes:
        hypothesis_id: Unique identifier.
        title: Short summary of the hypothesis.
        description: Detailed statement of the hypothesis.
        status: Current investigation status.
        priority: Priority score (higher = investigate first).
        confidence: Overall confidence (0.0 – 1.0), auto-computed.
        evidence: List of supporting/refuting evidence.
        mitre_techniques: Related MITRE technique IDs.
        parent_id: Parent hypothesis ID (for hypothesis trees).
        sub_hypotheses: Child hypothesis IDs.
        investigation_notes: Analyst/AI notes.
    """

    def __init__(
        self,
        title: str,
        description: str,
        priority: int = 5,
        mitre_techniques: Optional[List[str]] = None,
        parent_id: Optional[str] = None,
    ) -> None:
        self.title = title
        self.description = description
        self.status = HypothesisStatus.PROPOSED
        self.priority = priority
        self.evidence: List[Evidence] = []
        self.mitre_techniques = mitre_techniques or []
        self.parent_id = parent_id
        self.sub_hypotheses: List[str] = []
        self.investigation_notes: List[str] = []
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = self.created_at

        seed = f"{title}:{self.created_at}"
        self.hypothesis_id = hashlib.md5(seed.encode()).hexdigest()[:10]

    @property
    def confidence(self) -> float:
        """Compute confidence from evidence weights."""
        if not self.evidence:
            return 0.0
        total_weight = sum(e.weight for e in self.evidence)
        max_possible = len(self.evidence)
        if max_possible == 0:
            return 0.0
        # Normalize to 0-1 range
        raw = (total_weight + max_possible) / (2 * max_possible)
        return max(0.0, min(1.0, raw))

    @property
    def evidence_summary(self) -> Dict[str, int]:
        """Count evidence by grade."""
        counts: Dict[str, int] = defaultdict(int)
        for e in self.evidence:
            counts[e.grade.value] += 1
        return dict(counts)

    def add_evidence(self, evidence: Evidence) -> None:
        """Add a piece of evidence and update timestamp."""
        self.evidence.append(evidence)
        self.updated_at = datetime.now(timezone.utc).isoformat()
        self._auto_update_status()

    def _auto_update_status(self) -> None:
        """Auto-update status based on evidence."""
        if not self.evidence:
            return

        confidence = self.confidence
        contradictions = sum(
            1 for e in self.evidence
            if e.grade == EvidenceGrade.CONTRADICTORY or not e.supports_hypothesis
        )
        supporting = sum(
            1 for e in self.evidence
            if e.supports_hypothesis and e.grade != EvidenceGrade.CONTRADICTORY
        )

        if self.status == HypothesisStatus.PROPOSED:
            self.status = HypothesisStatus.INVESTIGATING

        if supporting >= 3 and confidence >= 0.7:
            self.status = HypothesisStatus.SUPPORTED
        elif contradictions >= 3 and confidence <= 0.3:
            self.status = HypothesisStatus.REFUTED
        elif len(self.evidence) >= 5 and 0.3 < confidence < 0.6:
            self.status = HypothesisStatus.INCONCLUSIVE

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "hypothesis_id": self.hypothesis_id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "priority": self.priority,
            "confidence": round(self.confidence, 3),
            "evidence_count": len(self.evidence),
            "evidence_summary": self.evidence_summary,
            "evidence": [e.to_dict() for e in self.evidence],
            "mitre_techniques": self.mitre_techniques,
            "parent_id": self.parent_id,
            "sub_hypotheses": self.sub_hypotheses,
            "investigation_notes": self.investigation_notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


# ============================================================
# Hypothesis Engine
# ============================================================

class HypothesisEngine:
    """
    Generates, manages, and refines investigative hypotheses from
    analysis findings. Operates in both AI-powered and offline
    heuristic modes.

    The engine builds a hypothesis tree where top-level hypotheses
    represent primary attack theories and sub-hypotheses represent
    more specific claims to investigate.

    Example:
        >>> engine = HypothesisEngine()
        >>> engine.generate_from_results(analysis_results)
        >>> print(engine.get_ranked_hypotheses())
        >>> engine.refine_hypothesis(hyp_id, new_evidence)
    """

    # Hypothesis generation templates for offline mode
    HYPOTHESIS_TEMPLATES = {
        "credential_theft": {
            "title": "Credential Theft & Account Compromise",
            "description": (
                "An attacker has compromised user credentials through "
                "{method} and is using them for unauthorized access."
            ),
            "triggers": ["T1003", "T1110", "T1558", "T1555", "credential", "mimikatz",
                         "lsass", "hashdump", "brute_force", "kerberoast"],
            "priority": 9,
        },
        "ransomware_attack": {
            "title": "Ransomware Deployment In Progress",
            "description": (
                "A ransomware actor is preparing to or has already encrypted "
                "systems, with evidence of shadow copy deletion and "
                "recovery disabling."
            ),
            "triggers": ["T1486", "T1490", "T1489", "ransomware", "encrypt",
                         "vssadmin", "shadow", "wbadmin", "bcdedit"],
            "priority": 10,
        },
        "lateral_movement": {
            "title": "Active Lateral Movement Campaign",
            "description": (
                "An attacker is moving laterally across the network using "
                "{method}, potentially expanding their footprint."
            ),
            "triggers": ["T1021", "T1570", "T1080", "psexec", "wmiexec",
                         "lateral_movement", "evil-winrm", "smbexec"],
            "priority": 9,
        },
        "data_exfiltration": {
            "title": "Data Exfiltration Attempt",
            "description": (
                "Sensitive data is being staged and/or exfiltrated from "
                "the network through {method}."
            ),
            "triggers": ["T1041", "T1048", "T1567", "T1560", "exfiltrat",
                         "rclone", "megacmd", "data_exfiltration"],
            "priority": 10,
        },
        "persistence_established": {
            "title": "Persistence Mechanisms Established",
            "description": (
                "An attacker has established persistence through {method}, "
                "ensuring continued access to compromised systems."
            ),
            "triggers": ["T1547", "T1543", "T1053", "T1136", "T1505",
                         "persistence", "schtasks", "reg add", "service"],
            "priority": 7,
        },
        "defense_evasion": {
            "title": "Active Defense Evasion & Anti-Forensics",
            "description": (
                "The attacker is actively attempting to evade detection "
                "and remove evidence of compromise."
            ),
            "triggers": ["T1070", "T1027", "T1562", "T1036", "log_tampering",
                         "wevtutil", "clear-eventlog", "disable", "obfuscat"],
            "priority": 8,
        },
        "c2_channel": {
            "title": "Active C2 Communication Channel",
            "description": (
                "A command-and-control channel is active, allowing remote "
                "attacker interaction with compromised systems."
            ),
            "triggers": ["T1071", "T1105", "T1573", "T1572", "T1090",
                         "beacon", "cobalt", "meterpreter", "c2", "empire",
                         "command_and_control"],
            "priority": 9,
        },
        "initial_compromise": {
            "title": "Initial Compromise Vector Identified",
            "description": (
                "The initial entry vector appears to be {method}, suggesting "
                "a targeted or opportunistic attack."
            ),
            "triggers": ["T1566", "T1190", "T1195", "phishing", "exploit",
                         "supply_chain", "initial_access"],
            "priority": 8,
        },
        "insider_threat": {
            "title": "Potential Insider Threat Activity",
            "description": (
                "Patterns suggest unauthorized access by an insider, "
                "including off-hours activity and unusual data access."
            ),
            "triggers": ["off_hours", "unusual_access", "privilege_abuse",
                         "data_access", "bulk_download"],
            "priority": 7,
        },
        "apt_campaign": {
            "title": "Advanced Persistent Threat (APT) Campaign",
            "description": (
                "Multiple kill-chain stages detected suggest a coordinated "
                "APT campaign with {method} as primary TTPs."
            ),
            "triggers": ["apt", "kill_chain", "multi_stage", "advanced",
                         "nation_state"],
            "priority": 10,
        },
    }

    def __init__(self, ai_core: Optional[Any] = None) -> None:
        """
        Initialize the hypothesis engine.

        Args:
            ai_core: Optional AICore instance for LLM-powered generation.
                     Falls back to heuristic mode if not provided.
        """
        self.ai_core = ai_core
        self.hypotheses: Dict[str, Hypothesis] = {}
        self._generation_context: str = ""

    def generate_from_results(self, results: Dict[str, Any]) -> List[Hypothesis]:
        """
        Generate investigative hypotheses from analysis results.

        Uses LLM if available, otherwise falls back to heuristic
        pattern matching against HYPOTHESIS_TEMPLATES.

        Args:
            results: Complete ThreatScope analysis results dict.

        Returns:
            List of generated Hypothesis objects, ranked by priority.
        """
        self._generation_context = self._build_context(results)

        # Try AI-powered generation first
        if self.ai_core and hasattr(self.ai_core, "_call_openai") and self.ai_core.available:
            ai_hypotheses = self._generate_ai_hypotheses(results)
            if ai_hypotheses:
                return ai_hypotheses

        # Fallback: heuristic generation
        return self._generate_heuristic_hypotheses(results)

    def _build_context(self, results: Dict[str, Any]) -> str:
        """Build concise context string for hypothesis generation."""
        parts = []

        summary = results.get("summary", {})
        parts.append(
            f"Threat Score: {results.get('threat_score', 0)}% "
            f"({results.get('threat_level', 'Unknown')})"
        )
        parts.append(
            f"Findings: {summary.get('total_findings', 0)} total — "
            f"{summary.get('critical', 0)} critical, "
            f"{summary.get('high', 0)} high"
        )
        parts.append(f"MITRE Techniques: {summary.get('mitre_techniques', 0)}")

        # Key findings
        findings = results.get("findings", [])[:20]
        if findings:
            parts.append("\nKey Findings:")
            for f in findings:
                parts.append(
                    f"  - [{f.get('severity', '').upper()}] {f.get('title', '')} "
                    f"(MITRE: {f.get('mitre', 'N/A')})"
                )

        # MITRE hits
        mitre_hits = results.get("mitre_hits", {})
        if mitre_hits:
            parts.append(f"\nMITRE Techniques Hit: {', '.join(list(mitre_hits.keys())[:15])}")

        # Correlations
        corrs = results.get("correlations", {}).get("correlations", [])
        if corrs:
            parts.append("\nCorrelations:")
            for c in corrs[:5]:
                parts.append(f"  - {c.get('name', '')}: {c.get('description', '')}")

        # IOCs
        ioc_data = results.get("iocs", {})
        if ioc_data.get("top_ips"):
            parts.append(f"\nTop IPs: {', '.join(ioc_data['top_ips'][:5])}")
        if ioc_data.get("top_domains"):
            parts.append(f"Top Domains: {', '.join(ioc_data['top_domains'][:5])}")

        return "\n".join(parts)

    def _generate_ai_hypotheses(self, results: Dict[str, Any]) -> List[Hypothesis]:
        """Generate hypotheses using LLM."""
        system_prompt = """You are an expert DFIR analyst generating investigative hypotheses.
Given the analysis data, generate 3-5 ranked hypotheses about what attack is occurring.

For each hypothesis, provide:
1. title: Short hypothesis title
2. description: Detailed hypothesis statement
3. priority: 1-10 (10 = highest)
4. mitre_techniques: List of relevant MITRE ATT&CK technique IDs
5. evidence_needed: What additional evidence would support or refute this

Respond ONLY with valid JSON array. Example:
[
  {
    "title": "Ransomware Deployment",
    "description": "Evidence suggests ransomware...",
    "priority": 10,
    "mitre_techniques": ["T1486", "T1490"],
    "evidence_needed": ["Check for encrypted files", "Verify shadow copies"]
  }
]"""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analyze this incident data and generate hypotheses:\n\n{self._generation_context}"},
        ]

        try:
            response = self.ai_core._call_openai(
                messages, max_tokens=2000, temperature=0.4
            )
        except Exception as exc:
            # A custom/broken provider must not abort the investigation; fall
            # back to the heuristic generator at this narrow boundary.
            logger.warning(
                "AI provider failed during hypothesis generation; using "
                "heuristics: %s", exc,
            )
            return []
        if not response:
            # Provider returned nothing (unavailable/failed); let the caller
            # fall back to heuristic hypothesis generation.
            return []

        try:
            # Parse JSON out of the model's response.
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if not json_match:
                return []

            hypotheses_data = json.loads(json_match.group())
            if not isinstance(hypotheses_data, list):
                logger.warning("AI hypothesis generation returned non-list JSON")
                return []

            hypotheses = []

            for hd in hypotheses_data:
                if not isinstance(hd, dict):
                    continue

                # Model output is untrusted: coerce/validate fields so a
                # malformed value cannot crash analysis.
                try:
                    priority = int(hd.get("priority", 5))
                except (TypeError, ValueError):
                    priority = 5
                mitre_techniques = hd.get("mitre_techniques", [])
                if not isinstance(mitre_techniques, list):
                    mitre_techniques = []
                evidence_needed = hd.get("evidence_needed", [])
                if not isinstance(evidence_needed, list):
                    evidence_needed = []

                hyp = Hypothesis(
                    title=str(hd.get("title") or "AI Hypothesis"),
                    description=str(hd.get("description") or ""),
                    priority=priority,
                    mitre_techniques=mitre_techniques,
                )
                # Add investigation notes from AI
                for note in evidence_needed:
                    hyp.investigation_notes.append(f"[AI] Look for: {note}")

                self.hypotheses[hyp.hypothesis_id] = hyp
                hypotheses.append(hyp)

            hypotheses.sort(key=lambda h: h.priority, reverse=True)
            logger.info(f"AI generated {len(hypotheses)} hypotheses")
            return hypotheses

        except (json.JSONDecodeError, ValueError, re.error) as e:
            # Only malformed/unparseable model output is tolerated here; genuine
            # programming errors are intentionally allowed to propagate.
            logger.warning(f"AI hypothesis generation returned unparseable output: {e}")
            return []

    def _generate_heuristic_hypotheses(self, results: Dict[str, Any]) -> List[Hypothesis]:
        """Generate hypotheses using rule-based heuristics."""
        hypotheses = []

        # Collect all trigger signals from results
        signals = set()

        # From MITRE hits
        for technique_id in results.get("mitre_hits", {}).keys():
            signals.add(technique_id)
            # Also add parent technique
            parent = technique_id.split(".")[0]
            signals.add(parent)

        # From finding categories and titles
        for finding in results.get("findings", []):
            category = finding.get("category", "").lower().replace(" ", "_")
            if category:
                signals.add(category)
            title_lower = finding.get("title", "").lower()
            # Extract keywords
            for word in re.findall(r'[a-z_]+', title_lower):
                if len(word) > 3:
                    signals.add(word)
            # Add MITRE from finding
            mitre = finding.get("mitre", "")
            if mitre:
                signals.add(mitre)

        # From correlations
        for corr in results.get("correlations", {}).get("correlations", []):
            name_lower = corr.get("name", "").lower().replace(" ", "_")
            signals.add(name_lower)

        # Match templates against signals
        for template_key, template in self.HYPOTHESIS_TEMPLATES.items():
            matched_triggers = [
                t for t in template["triggers"]
                if any(t.lower() in s.lower() for s in signals)
            ]

            if not matched_triggers:
                continue

            # Determine the method placeholder
            method = ", ".join(matched_triggers[:3])

            description = template["description"]
            if "{method}" in description:
                description = description.replace("{method}", method)

            # Boost priority if many triggers match
            priority = template["priority"]
            if len(matched_triggers) >= 3:
                priority = min(priority + 1, 10)

            # Collect relevant MITRE techniques
            mitre_techs = [
                t for t in matched_triggers
                if re.match(r'^T\d{4}', t)
            ]

            hyp = Hypothesis(
                title=template["title"],
                description=description,
                priority=priority,
                mitre_techniques=mitre_techs,
            )

            # Add auto-evidence from matching findings
            for finding in results.get("findings", []):
                finding_text = json.dumps(finding, default=str).lower()
                if any(t.lower() in finding_text for t in matched_triggers[:3]):
                    evidence = Evidence(
                        description=f"{finding.get('title', 'Finding')}: {finding.get('description', '')[:100]}",
                        source="analysis_finding",
                        grade=self._severity_to_grade(finding.get("severity", "medium")),
                        confidence=self._severity_to_confidence(finding.get("severity", "medium")),
                        data={"finding_title": finding.get("title"), "mitre": finding.get("mitre")},
                        tags=[finding.get("mitre", "")] if finding.get("mitre") else [],
                    )
                    hyp.add_evidence(evidence)

            self.hypotheses[hyp.hypothesis_id] = hyp
            hypotheses.append(hyp)

        hypotheses.sort(key=lambda h: h.priority, reverse=True)
        logger.info(f"Heuristic engine generated {len(hypotheses)} hypotheses")
        return hypotheses

    def _severity_to_grade(self, severity: str) -> EvidenceGrade:
        """Map severity to evidence grade."""
        mapping = {
            "critical": EvidenceGrade.STRONG,
            "high": EvidenceGrade.STRONG,
            "medium": EvidenceGrade.MODERATE,
            "low": EvidenceGrade.WEAK,
            "informational": EvidenceGrade.WEAK,
        }
        return mapping.get(severity.lower(), EvidenceGrade.MODERATE)

    def _severity_to_confidence(self, severity: str) -> float:
        """Map severity to confidence score."""
        mapping = {
            "critical": 0.95,
            "high": 0.85,
            "medium": 0.6,
            "low": 0.35,
            "informational": 0.2,
        }
        return mapping.get(severity.lower(), 0.5)

    def get_ranked_hypotheses(self) -> List[Dict[str, Any]]:
        """
        Get all hypotheses ranked by priority and confidence.

        Returns:
            List of hypothesis dictionaries, highest priority first.
        """
        ranked = sorted(
            self.hypotheses.values(),
            key=lambda h: (h.priority, h.confidence),
            reverse=True,
        )
        return [h.to_dict() for h in ranked]

    def get_hypothesis(self, hypothesis_id: str) -> Optional[Hypothesis]:
        """Get a hypothesis by ID."""
        return self.hypotheses.get(hypothesis_id)

    def add_evidence_to_hypothesis(
        self,
        hypothesis_id: str,
        evidence: Evidence,
    ) -> bool:
        """
        Add evidence to a specific hypothesis.

        Args:
            hypothesis_id: Target hypothesis ID.
            evidence: Evidence to add.

        Returns:
            True if evidence was added successfully.
        """
        hyp = self.hypotheses.get(hypothesis_id)
        if not hyp:
            logger.warning(f"Hypothesis {hypothesis_id} not found")
            return False
        hyp.add_evidence(evidence)
        return True

    def create_sub_hypothesis(
        self,
        parent_id: str,
        title: str,
        description: str,
        priority: Optional[int] = None,
    ) -> Optional[Hypothesis]:
        """
        Create a sub-hypothesis under an existing hypothesis.

        Args:
            parent_id: Parent hypothesis ID.
            title: Sub-hypothesis title.
            description: Sub-hypothesis description.
            priority: Optional priority override.

        Returns:
            The new sub-hypothesis, or None if parent not found.
        """
        parent = self.hypotheses.get(parent_id)
        if not parent:
            return None

        sub = Hypothesis(
            title=title,
            description=description,
            priority=priority or parent.priority - 1,
            mitre_techniques=parent.mitre_techniques.copy(),
            parent_id=parent_id,
        )
        parent.sub_hypotheses.append(sub.hypothesis_id)
        self.hypotheses[sub.hypothesis_id] = sub
        return sub

    def get_summary(self) -> Dict[str, Any]:
        """Get hypothesis engine summary statistics."""
        total = len(self.hypotheses)
        by_status: Dict[str, int] = defaultdict(int)
        for h in self.hypotheses.values():
            by_status[h.status.value] += 1

        top_hypothesis = None
        if self.hypotheses:
            best = max(self.hypotheses.values(), key=lambda h: (h.priority, h.confidence))
            top_hypothesis = {
                "title": best.title,
                "confidence": round(best.confidence, 3),
                "status": best.status.value,
            }

        return {
            "total_hypotheses": total,
            "by_status": dict(by_status),
            "top_hypothesis": top_hypothesis,
            "total_evidence": sum(len(h.evidence) for h in self.hypotheses.values()),
        }


# ============================================================
# Evidence Collector
# ============================================================

class EvidenceCollector:
    """
    Systematically collects and grades evidence from ThreatScope
    analysis results to support or refute hypotheses.

    Evidence is gathered from:
      - Analysis findings (categorized by severity)
      - IOC extractions (IPs, domains, hashes)
      - Timeline events (chronological sequence)
      - Correlation matches (multi-signal patterns)
      - Behavioral chain triggers (attack sequences)
      - MITRE ATT&CK technique hits

    Example:
        >>> collector = EvidenceCollector(results)
        >>> evidence = collector.collect_for_technique("T1003")
        >>> evidence = collector.collect_for_keywords(["mimikatz", "lsass"])
    """

    def __init__(self, results: Dict[str, Any]) -> None:
        """
        Initialize the evidence collector with analysis results.

        Args:
            results: Complete ThreatScope analysis results dict.
        """
        self.results = results
        self.findings = results.get("findings", [])
        self.timeline = results.get("timeline", [])
        self.iocs = results.get("iocs", {})
        self.correlations = results.get("correlations", {}).get("correlations", [])
        self.mitre_hits = results.get("mitre_hits", {})
        self._collected: List[Evidence] = []

    def collect_for_technique(self, technique_id: str) -> List[Evidence]:
        """
        Collect all evidence related to a MITRE technique.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., T1003).

        Returns:
            List of Evidence objects.
        """
        evidence = []
        tid_upper = technique_id.upper()
        parent_tid = tid_upper.split(".")[0]

        # From findings
        for finding in self.findings:
            fmit = finding.get("mitre", "").upper()
            if fmit == tid_upper or fmit == parent_tid or fmit.startswith(parent_tid + "."):
                sev = finding.get("severity", "medium")
                ev = Evidence(
                    description=f"[Finding] {finding.get('title', 'Unknown')}: {finding.get('description', '')[:120]}",
                    source="finding",
                    grade=self._severity_to_grade(sev),
                    confidence=self._severity_to_confidence(sev),
                    data=finding,
                    tags=[fmit, finding.get("category", "")],
                )
                evidence.append(ev)

        # From MITRE hits directly
        if tid_upper in self.mitre_hits:
            count = self.mitre_hits[tid_upper]
            ev = Evidence(
                description=f"[MITRE] Technique {tid_upper} triggered {count} time(s)",
                source="mitre_hit",
                grade=EvidenceGrade.MODERATE if count < 3 else EvidenceGrade.STRONG,
                confidence=min(0.5 + count * 0.1, 0.95),
                data={"technique": tid_upper, "count": count},
                tags=[tid_upper],
            )
            evidence.append(ev)

        # From correlations
        for corr in self.correlations:
            corr_text = json.dumps(corr, default=str).lower()
            if tid_upper.lower() in corr_text or parent_tid.lower() in corr_text:
                ev = Evidence(
                    description=f"[Correlation] {corr.get('name', 'Unknown')}: {corr.get('description', '')[:100]}",
                    source="correlation",
                    grade=self._severity_to_grade(corr.get("severity", "medium")),
                    confidence=0.8,
                    data=corr,
                    tags=[tid_upper],
                )
                evidence.append(ev)

        self._collected.extend(evidence)
        return evidence

    def collect_for_keywords(self, keywords: List[str]) -> List[Evidence]:
        """
        Collect evidence matching keyword patterns across all data.

        Args:
            keywords: List of keywords or patterns to search.

        Returns:
            List of Evidence objects.
        """
        evidence = []
        patterns = [re.compile(re.escape(kw), re.IGNORECASE) for kw in keywords]

        # Search findings
        for finding in self.findings:
            finding_text = f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('raw_log', '')}"
            for pattern in patterns:
                if pattern.search(finding_text):
                    sev = finding.get("severity", "medium")
                    ev = Evidence(
                        description=f"[Keyword Match] '{pattern.pattern}' in finding: {finding.get('title', '')[:80]}",
                        source="keyword_search",
                        grade=self._severity_to_grade(sev),
                        confidence=self._severity_to_confidence(sev),
                        data=finding,
                        tags=[pattern.pattern],
                    )
                    evidence.append(ev)
                    break  # One match per finding

        # Search timeline
        for event in self.timeline[:200]:
            event_text = json.dumps(event, default=str)
            for pattern in patterns:
                if pattern.search(event_text):
                    ev = Evidence(
                        description=f"[Timeline] '{pattern.pattern}' at {event.get('timestamp', '?')}: {event.get('description', '')[:80]}",
                        source="timeline_event",
                        grade=EvidenceGrade.MODERATE,
                        confidence=0.6,
                        data=event,
                        tags=[pattern.pattern],
                    )
                    evidence.append(ev)
                    break

        self._collected.extend(evidence)
        return evidence

    def collect_ioc_evidence(self) -> List[Evidence]:
        """
        Collect evidence from extracted IOCs.

        Returns:
            List of Evidence from IPs, domains, URLs, and hashes.
        """
        evidence = []

        # Suspicious IPs
        top_ips = self.iocs.get("top_ips", [])
        if top_ips:
            ev = Evidence(
                description=f"[IOC] {len(top_ips)} suspicious IPs identified: {', '.join(top_ips[:5])}",
                source="ioc_extraction",
                grade=EvidenceGrade.MODERATE,
                confidence=0.7,
                data={"ips": top_ips},
                tags=["ioc", "ip_address"],
            )
            evidence.append(ev)

        # Suspicious domains
        top_domains = self.iocs.get("top_domains", [])
        if top_domains:
            ev = Evidence(
                description=f"[IOC] {len(top_domains)} suspicious domains: {', '.join(top_domains[:5])}",
                source="ioc_extraction",
                grade=EvidenceGrade.MODERATE,
                confidence=0.7,
                data={"domains": top_domains},
                tags=["ioc", "domain"],
            )
            evidence.append(ev)

        # URLs
        urls = self.iocs.get("urls", [])
        if urls:
            ev = Evidence(
                description=f"[IOC] {len(urls)} suspicious URLs extracted",
                source="ioc_extraction",
                grade=EvidenceGrade.STRONG if len(urls) > 5 else EvidenceGrade.MODERATE,
                confidence=0.75,
                data={"urls": urls[:10]},
                tags=["ioc", "url"],
            )
            evidence.append(ev)

        # File hashes (ioc_extractor emits {"md5": [...], "sha1": [...], "sha256": [...]})
        hashes = self.iocs.get("hashes", {})
        if isinstance(hashes, dict):
            hash_count = sum(len(v) for v in hashes.values() if v)
            hash_sample = {k: v[:10] for k, v in hashes.items() if v}
        else:
            hash_count = len(hashes)
            hash_sample = hashes[:10]
        if hash_count:
            ev = Evidence(
                description=f"[IOC] {hash_count} file hashes extracted",
                source="ioc_extraction",
                grade=EvidenceGrade.STRONG,
                confidence=0.85,
                data={"hashes": hash_sample},
                tags=["ioc", "hash"],
            )
            evidence.append(ev)

        self._collected.extend(evidence)
        return evidence

    def collect_timeline_anomalies(
        self,
        off_hours_start: int = 22,
        off_hours_end: int = 6,
    ) -> List[Evidence]:
        """
        Collect evidence of timeline anomalies like off-hours activity
        and burst patterns.

        Args:
            off_hours_start: Start hour of off-hours window (24h).
            off_hours_end: End hour of off-hours window (24h).

        Returns:
            List of Evidence for timeline anomalies.
        """
        evidence = []
        off_hours_events = []
        burst_windows: Dict[str, int] = defaultdict(int)

        for event in self.timeline:
            ts = event.get("timestamp", "")
            if not ts:
                continue

            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                hour = dt.hour

                # Off-hours detection
                if hour >= off_hours_start or hour < off_hours_end:
                    off_hours_events.append(event)

                # Burst detection (events per minute)
                minute_key = dt.strftime("%Y-%m-%d %H:%M")
                burst_windows[minute_key] += 1

            except (ValueError, AttributeError):
                continue

        # Off-hours evidence
        if off_hours_events:
            ev = Evidence(
                description=(
                    f"[Timeline] {len(off_hours_events)} events during off-hours "
                    f"({off_hours_start}:00-{off_hours_end}:00)"
                ),
                source="timeline_analysis",
                grade=EvidenceGrade.MODERATE,
                confidence=0.6 if len(off_hours_events) < 10 else 0.8,
                data={"off_hours_count": len(off_hours_events)},
                tags=["anomaly", "off_hours"],
            )
            evidence.append(ev)

        # Burst activity evidence
        high_bursts = {k: v for k, v in burst_windows.items() if v > 50}
        if high_bursts:
            max_burst = max(high_bursts.values())
            ev = Evidence(
                description=(
                    f"[Timeline] Activity burst detected: {len(high_bursts)} "
                    f"windows with 50+ events/min (peak: {max_burst})"
                ),
                source="timeline_analysis",
                grade=EvidenceGrade.MODERATE,
                confidence=0.7,
                data={"burst_windows": len(high_bursts), "peak": max_burst},
                tags=["anomaly", "burst"],
            )
            evidence.append(ev)

        self._collected.extend(evidence)
        return evidence

    def get_all_collected(self) -> List[Evidence]:
        """Get all evidence collected so far."""
        return self._collected

    def get_evidence_summary(self) -> Dict[str, Any]:
        """Summarize all collected evidence."""
        by_grade: Dict[str, int] = defaultdict(int)
        by_source: Dict[str, int] = defaultdict(int)
        for e in self._collected:
            by_grade[e.grade.value] += 1
            by_source[e.source] += 1

        return {
            "total_evidence": len(self._collected),
            "by_grade": dict(by_grade),
            "by_source": dict(by_source),
            "avg_confidence": round(
                sum(e.confidence for e in self._collected) / max(len(self._collected), 1), 3
            ),
        }

    def _severity_to_grade(self, severity: str) -> EvidenceGrade:
        """Map severity to evidence grade."""
        mapping = {
            "critical": EvidenceGrade.STRONG,
            "high": EvidenceGrade.STRONG,
            "medium": EvidenceGrade.MODERATE,
            "low": EvidenceGrade.WEAK,
            "informational": EvidenceGrade.WEAK,
        }
        return mapping.get(severity.lower(), EvidenceGrade.MODERATE)

    def _severity_to_confidence(self, severity: str) -> float:
        """Map severity to confidence score."""
        mapping = {
            "critical": 0.95,
            "high": 0.85,
            "medium": 0.6,
            "low": 0.35,
            "informational": 0.2,
        }
        return mapping.get(severity.lower(), 0.5)


# ============================================================
# Agentic Copilot (Orchestrator)
# ============================================================

class AgenticCopilot:
    """
    Autonomous investigation agent that orchestrates multi-step
    analysis workflows using HypothesisEngine and EvidenceCollector.

    Unlike the basic AnalystCopilot in ai_core.py, this agent:
      - Proactively generates and ranks hypotheses
      - Systematically collects evidence for each hypothesis
      - Refines hypotheses as new evidence is gathered
      - Produces structured investigation reports
      - Supports interactive drill-down conversations

    Example:
        >>> copilot = AgenticCopilot()
        >>> report = copilot.investigate(analysis_results)
        >>> print(report["executive_summary"])
        >>> copilot.ask("What evidence supports credential theft?")
    """

    SYSTEM_PROMPT = """You are ThreatScope Agentic Copilot — an expert autonomous DFIR investigator.
You conduct structured hypothesis-driven investigations:

1. TRIAGE: Assess the overall threat landscape from the data
2. HYPOTHESIZE: Generate ranked hypotheses about what attacks occurred
3. EVIDENCE: Systematically collect and grade evidence for each hypothesis
4. ANALYZE: Determine which hypotheses are supported, refuted, or inconclusive
5. REPORT: Produce a structured investigation report with confidence levels

When answering questions:
- Reference specific evidence and confidence levels
- Distinguish between confirmed facts, strong indicators, and speculation
- Recommend next investigative steps
- Be precise about MITRE ATT&CK technique mappings

You have access to the full investigation context including hypotheses,
evidence grades, and timeline data."""

    def __init__(self, api_key: str = "", model: str = "") -> None:
        """
        Initialize the Agentic Copilot.

        Args:
            api_key: Optional OpenAI API key override.
            model: Optional model name override.
        """
        self.ai_core: Optional[Any] = None
        if AI_CORE_AVAILABLE:
            try:
                self.ai_core = AICore(api_key=api_key, model=model)
            except Exception as e:
                logger.warning(f"Failed to initialize AICore: {e}")

        self.hypothesis_engine = HypothesisEngine(ai_core=self.ai_core)
        self.evidence_collector: Optional[EvidenceCollector] = None
        self.phase = InvestigationPhase.TRIAGE
        self._investigation_report: Optional[Dict[str, Any]] = None
        self._chat_history: List[Dict[str, str]] = []
        self._results: Optional[Dict[str, Any]] = None

    def investigate(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run a full autonomous investigation on analysis results.

        Follows the investigation lifecycle:
        Triage → Hypothesis Generation → Evidence Collection →
        Analysis → Conclusion → Reporting

        Args:
            results: Complete ThreatScope analysis results dict.

        Returns:
            Structured investigation report dictionary.
        """
        self._results = results
        logger.info("Starting agentic investigation...")

        # Phase 1: Triage
        self.phase = InvestigationPhase.TRIAGE
        triage = self._triage(results)

        # Phase 2: Hypothesis Generation
        self.phase = InvestigationPhase.HYPOTHESIS_GENERATION
        hypotheses = self.hypothesis_engine.generate_from_results(results)
        logger.info(f"Generated {len(hypotheses)} hypotheses")

        # Phase 3: Evidence Collection
        self.phase = InvestigationPhase.EVIDENCE_COLLECTION
        self.evidence_collector = EvidenceCollector(results)
        self._collect_evidence_for_hypotheses(hypotheses)

        # Phase 4: Analysis
        self.phase = InvestigationPhase.ANALYSIS
        analysis = self._analyze_hypotheses()

        # Phase 5: Conclusion
        self.phase = InvestigationPhase.CONCLUSION
        conclusion = self._draw_conclusions()

        # Phase 6: Reporting
        self.phase = InvestigationPhase.REPORTING
        self._investigation_report = {
            "metadata": {
                "tool": "ThreatScope V3.5 Agentic Copilot",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "investigation_id": hashlib.md5(
                    datetime.now(timezone.utc).isoformat().encode()
                ).hexdigest()[:12],
            },
            "triage": triage,
            "hypotheses": self.hypothesis_engine.get_ranked_hypotheses(),
            "evidence_summary": (
                self.evidence_collector.get_evidence_summary()
                if self.evidence_collector else {}
            ),
            "analysis": analysis,
            "conclusion": conclusion,
            "executive_summary": self._generate_executive_summary(
                triage, conclusion
            ),
            "recommended_actions": self._generate_action_items(conclusion),
        }

        logger.info("Investigation complete")
        return self._investigation_report

    def _triage(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 1: Quick triage assessment."""
        score = results.get("threat_score", 0)
        level = results.get("threat_level", "Unknown")
        summary = results.get("summary", {})

        # Determine urgency
        if score >= 80 or summary.get("critical", 0) >= 3:
            urgency = "CRITICAL — Immediate response required"
        elif score >= 60 or summary.get("critical", 0) >= 1:
            urgency = "HIGH — Escalate to senior analyst"
        elif score >= 40:
            urgency = "MEDIUM — Investigate within 24 hours"
        elif score >= 20:
            urgency = "LOW — Standard investigation queue"
        else:
            urgency = "INFORMATIONAL — Monitor only"

        # Identify dominant attack stages
        attack_stages = set()
        mitre_hits = results.get("mitre_hits", {})
        for tid in mitre_hits:
            parent = tid.split(".")[0]
            tactics = TECHNIQUE_TACTIC_MAP.get(parent, []) + TECHNIQUE_TACTIC_MAP.get(tid, [])
            for tactic in tactics:
                tactic_name = MITRE_TACTICS.get(tactic, {}).get("name", "")
                if tactic_name:
                    attack_stages.add(tactic_name)

        return {
            "threat_score": score,
            "threat_level": level,
            "urgency": urgency,
            "total_findings": summary.get("total_findings", 0),
            "critical_findings": summary.get("critical", 0),
            "high_findings": summary.get("high", 0),
            "attack_stages_detected": sorted(attack_stages),
            "kill_chain_coverage": len(attack_stages),
            "total_mitre_techniques": len(mitre_hits),
        }

    def _collect_evidence_for_hypotheses(self, hypotheses: List[Hypothesis]) -> None:
        """Phase 3: Systematically collect evidence for each hypothesis."""
        if not self.evidence_collector:
            return

        # Collect general evidence first
        self.evidence_collector.collect_ioc_evidence()
        self.evidence_collector.collect_timeline_anomalies()

        for hyp in hypotheses:
            # Collect by MITRE technique
            for technique in hyp.mitre_techniques:
                technique_evidence = self.evidence_collector.collect_for_technique(technique)
                for ev in technique_evidence:
                    hyp.add_evidence(ev)

            # Collect by keywords from hypothesis title/description
            keywords = self._extract_investigation_keywords(hyp)
            if keywords:
                kw_evidence = self.evidence_collector.collect_for_keywords(keywords)
                for ev in kw_evidence[:5]:  # Limit keyword evidence per hypothesis
                    hyp.add_evidence(ev)

    def _extract_investigation_keywords(self, hypothesis: Hypothesis) -> List[str]:
        """Extract investigation-relevant keywords from hypothesis."""
        keywords = []
        text = f"{hypothesis.title} {hypothesis.description}".lower()

        # Tool/technique names
        tool_patterns = [
            "mimikatz", "psexec", "cobalt", "beacon", "meterpreter",
            "empire", "sliver", "bloodhound", "sharphound",
            "rubeus", "kerberoast", "dcsync", "hashdump",
            "lsass", "procdump", "ransomware", "encrypt",
            "vssadmin", "wevtutil", "schtasks", "wmic",
        ]
        for tool in tool_patterns:
            if tool in text:
                keywords.append(tool)

        # Limit to avoid noise
        return keywords[:5]

    def _analyze_hypotheses(self) -> Dict[str, Any]:
        """Phase 4: Analyze hypothesis status and confidence."""
        hypotheses = list(self.hypothesis_engine.hypotheses.values())

        supported = [h for h in hypotheses if h.status == HypothesisStatus.SUPPORTED]
        refuted = [h for h in hypotheses if h.status == HypothesisStatus.REFUTED]
        investigating = [h for h in hypotheses if h.status == HypothesisStatus.INVESTIGATING]
        inconclusive = [h for h in hypotheses if h.status == HypothesisStatus.INCONCLUSIVE]

        return {
            "total_hypotheses": len(hypotheses),
            "supported": len(supported),
            "refuted": len(refuted),
            "investigating": len(investigating),
            "inconclusive": len(inconclusive),
            "primary_hypothesis": (
                supported[0].to_dict() if supported
                else (hypotheses[0].to_dict() if hypotheses else None)
            ),
            "investigation_completeness": self._compute_completeness(hypotheses),
        }

    def _compute_completeness(self, hypotheses: List[Hypothesis]) -> float:
        """Compute investigation completeness score (0-100%)."""
        if not hypotheses:
            return 0.0

        resolved = sum(
            1 for h in hypotheses
            if h.status in (HypothesisStatus.SUPPORTED, HypothesisStatus.REFUTED)
        )
        return round(resolved / len(hypotheses) * 100, 1)

    def _draw_conclusions(self) -> Dict[str, Any]:
        """Phase 5: Draw conclusions from the investigation."""
        hypotheses = list(self.hypothesis_engine.hypotheses.values())
        supported = sorted(
            [h for h in hypotheses if h.status == HypothesisStatus.SUPPORTED],
            key=lambda h: h.confidence,
            reverse=True,
        )

        if supported:
            primary = supported[0]
            conclusion_text = (
                f"The investigation supports the hypothesis: '{primary.title}' "
                f"(confidence: {primary.confidence:.0%}). "
                f"{primary.description}"
            )
        elif hypotheses:
            best = max(hypotheses, key=lambda h: h.confidence)
            conclusion_text = (
                f"The investigation is ongoing. The most likely scenario is: "
                f"'{best.title}' (confidence: {best.confidence:.0%}), "
                f"but more evidence is needed."
            )
        else:
            conclusion_text = "Insufficient data to form a conclusion."

        # Collect all unique MITRE techniques from supported hypotheses
        mitre_techniques = set()
        for h in supported:
            mitre_techniques.update(h.mitre_techniques)

        return {
            "conclusion": conclusion_text,
            "confirmed_hypotheses": [h.to_dict() for h in supported],
            "mitre_techniques": sorted(mitre_techniques),
            "confidence": max((h.confidence for h in hypotheses), default=0.0),
        }

    def _generate_executive_summary(
        self,
        triage: Dict[str, Any],
        conclusion: Dict[str, Any],
    ) -> str:
        """Generate a brief executive summary."""
        parts = [
            f"THREAT LEVEL: {triage.get('threat_level', 'Unknown').upper()} "
            f"(Score: {triage.get('threat_score', 0)}%)",
            f"URGENCY: {triage.get('urgency', 'Unknown')}",
            "",
            conclusion.get("conclusion", "No conclusion available."),
            "",
            f"Attack stages detected: {', '.join(triage.get('attack_stages_detected', []))}",
            f"MITRE techniques confirmed: {len(conclusion.get('mitre_techniques', []))}",
            f"Critical findings: {triage.get('critical_findings', 0)}",
        ]
        return "\n".join(parts)

    def _generate_action_items(
        self,
        conclusion: Dict[str, Any],
    ) -> List[Dict[str, str]]:
        """Generate recommended investigation action items."""
        actions = []

        # Always recommend
        actions.append({
            "priority": "immediate",
            "action": "Preserve all log evidence and create forensic images",
            "rationale": "Evidence preservation is critical for further investigation",
        })

        confirmed = conclusion.get("confirmed_hypotheses", [])
        techniques = set(conclusion.get("mitre_techniques", []))

        # Credential-related actions
        if techniques & {"T1003", "T1003.001", "T1110", "T1558"}:
            actions.append({
                "priority": "immediate",
                "action": "Reset all compromised credentials and force MFA re-enrollment",
                "rationale": "Credential theft detected — all exposed accounts must be rotated",
            })

        # Lateral movement actions
        if techniques & {"T1021", "T1570", "T1080"}:
            actions.append({
                "priority": "immediate",
                "action": "Isolate affected endpoints from the network",
                "rationale": "Active lateral movement detected — contain the spread",
            })

        # C2 actions
        if techniques & {"T1071", "T1105", "T1573", "T1572"}:
            actions.append({
                "priority": "immediate",
                "action": "Block identified C2 IP addresses and domains at the firewall",
                "rationale": "Active C2 communication detected — sever attacker access",
            })

        # Persistence actions
        if techniques & {"T1547", "T1543", "T1053", "T1136"}:
            actions.append({
                "priority": "high",
                "action": "Audit and remove unauthorized persistence mechanisms",
                "rationale": "Persistence mechanisms detected — ensure complete removal",
            })

        # Ransomware actions
        if techniques & {"T1486", "T1490", "T1489"}:
            actions.append({
                "priority": "immediate",
                "action": "Activate incident response plan — potential ransomware deployment",
                "rationale": "Ransomware indicators detected — time-critical response needed",
            })

        # Data exfiltration actions
        if techniques & {"T1041", "T1048", "T1567"}:
            actions.append({
                "priority": "immediate",
                "action": "Review DLP logs and block identified exfiltration channels",
                "rationale": "Data exfiltration indicators detected — assess data impact",
            })

        # Always recommend follow-up
        actions.append({
            "priority": "standard",
            "action": "Conduct a thorough threat hunt across the environment",
            "rationale": "Determine the full scope of the compromise",
        })

        return actions

    # ----------------------------------------------------------
    # Interactive Q&A
    # ----------------------------------------------------------

    def ask(self, question: str) -> str:
        """
        Ask the copilot a question about the investigation.

        Uses AI if available, otherwise provides structured answers
        from the investigation data.

        Args:
            question: The analyst's question.

        Returns:
            Response string.
        """
        if not self._investigation_report:
            return (
                "No investigation has been run yet. "
                "Call investigate(results) first to start the analysis."
            )

        # Try AI-powered response; fall back to the offline engine whenever the
        # provider is unavailable, disabled, returns nothing, or fails so that
        # ask() always honours its string return contract.
        if self.ai_core and self.ai_core.available:
            response = self._ask_ai(question)
            if response:
                return response

        # Fallback: keyword-based response
        return self._ask_offline(question)

    def _ask_ai(self, question: str) -> Optional[str]:
        """
        Generate an AI-powered response to a question.

        Returns ``None`` (so the caller can fall back to the offline engine)
        when the provider yields no usable response.
        """
        # Build context from investigation report
        context = json.dumps({
            "triage": self._investigation_report.get("triage"),
            "hypotheses": self._investigation_report.get("hypotheses", [])[:5],
            "conclusion": self._investigation_report.get("conclusion"),
            "executive_summary": self._investigation_report.get("executive_summary"),
            "recommended_actions": self._investigation_report.get("recommended_actions"),
        }, indent=2, default=str)

        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "system", "content": f"Investigation Report:\n{context}"},
        ]

        # Add conversation history (last 8 messages)
        messages.extend(self._chat_history[-8:])
        messages.append({"role": "user", "content": question})

        try:
            response = self.ai_core._call_openai(
                messages, max_tokens=1500, temperature=0.4
            )
        except Exception as exc:
            # Fall back to the offline engine; never surface provider errors to
            # the caller or record a failed turn in the conversation history.
            logger.warning(
                "AI provider failed while answering a question; using offline "
                "engine: %s", exc,
            )
            return None
        if not response:
            # Provider disabled/failed; do not record an empty turn in history.
            return None

        self._chat_history.append({"role": "user", "content": question})
        self._chat_history.append({"role": "assistant", "content": response})

        return response

    def _ask_offline(self, question: str) -> str:
        """Answer questions using structured investigation data."""
        q_lower = question.lower()
        report = self._investigation_report

        # Route to appropriate section
        if any(kw in q_lower for kw in ["summary", "overview", "what happened", "executive"]):
            return report.get("executive_summary", "No summary available.")

        if any(kw in q_lower for kw in ["hypothesis", "theory", "what do you think"]):
            hypotheses = report.get("hypotheses", [])
            if not hypotheses:
                return "No hypotheses were generated."
            lines = ["Investigation Hypotheses (ranked by priority):\n"]
            for i, h in enumerate(hypotheses[:5], 1):
                lines.append(
                    f"{i}. [{h['status'].upper()}] {h['title']} "
                    f"(confidence: {h['confidence']:.0%}, priority: {h['priority']})"
                )
                lines.append(f"   {h['description'][:120]}")
                if h.get("mitre_techniques"):
                    lines.append(f"   MITRE: {', '.join(h['mitre_techniques'][:5])}")
                lines.append("")
            return "\n".join(lines)

        if any(kw in q_lower for kw in ["evidence", "proof", "support"]):
            ev_summary = report.get("evidence_summary", {})
            return (
                f"Evidence Summary:\n"
                f"  Total pieces: {ev_summary.get('total_evidence', 0)}\n"
                f"  By grade: {ev_summary.get('by_grade', {})}\n"
                f"  By source: {ev_summary.get('by_source', {})}\n"
                f"  Average confidence: {ev_summary.get('avg_confidence', 0):.1%}"
            )

        if any(kw in q_lower for kw in ["action", "recommend", "what should", "next step"]):
            actions = report.get("recommended_actions", [])
            if not actions:
                return "No recommendations available."
            lines = ["Recommended Actions:\n"]
            for a in actions:
                lines.append(f"  [{a['priority'].upper()}] {a['action']}")
                lines.append(f"    Rationale: {a['rationale']}\n")
            return "\n".join(lines)

        if any(kw in q_lower for kw in ["conclusion", "result", "verdict"]):
            conclusion = report.get("conclusion", {})
            return conclusion.get("conclusion", "No conclusion drawn yet.")

        if any(kw in q_lower for kw in ["triage", "severity", "urgent", "score"]):
            triage = report.get("triage", {})
            return (
                f"Triage Assessment:\n"
                f"  Threat Score: {triage.get('threat_score', 0)}%\n"
                f"  Threat Level: {triage.get('threat_level', 'Unknown')}\n"
                f"  Urgency: {triage.get('urgency', 'Unknown')}\n"
                f"  Critical Findings: {triage.get('critical_findings', 0)}\n"
                f"  Attack Stages: {', '.join(triage.get('attack_stages_detected', []))}"
            )

        if any(kw in q_lower for kw in ["mitre", "technique", "tactic", "att&ck"]):
            conclusion = report.get("conclusion", {})
            techs = conclusion.get("mitre_techniques", [])
            return (
                f"Confirmed MITRE ATT&CK Techniques ({len(techs)}):\n"
                + "\n".join(f"  - {t}" for t in techs) if techs
                else "No confirmed MITRE techniques."
            )

        # Default response
        return (
            "I can answer questions about:\n"
            "  • summary/overview — Executive summary\n"
            "  • hypotheses — Investigation theories\n"
            "  • evidence — Collected evidence\n"
            "  • actions/recommendations — Next steps\n"
            "  • conclusion — Investigation verdict\n"
            "  • triage/severity — Threat assessment\n"
            "  • MITRE techniques — ATT&CK mappings\n\n"
            "For AI-powered free-form Q&A, set your OpenAI API key."
        )

    def get_report(self) -> Optional[Dict[str, Any]]:
        """Get the full investigation report."""
        return self._investigation_report

    def get_chat_history(self) -> List[Dict[str, str]]:
        """Get the conversation history."""
        return self._chat_history

    def export_report(self, filepath: str) -> bool:
        """
        Export the investigation report to a JSON file.

        Args:
            filepath: Output file path.

        Returns:
            True if exported successfully.
        """
        if not self._investigation_report:
            logger.error("No investigation report to export")
            return False

        try:
            outpath = Path(filepath)
            outpath.parent.mkdir(parents=True, exist_ok=True)
            with open(outpath, "w", encoding="utf-8") as fh:
                json.dump(self._investigation_report, fh, indent=2, default=str)
            logger.info(f"Investigation report exported to {outpath}")
            return True
        except Exception as e:
            logger.error(f"Failed to export report: {e}")
            return False
