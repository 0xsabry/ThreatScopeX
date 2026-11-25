"""
ThreatScope — AI Analysis Core
Author: 0xSABRY

Attack Narrative Engine: Generates coherent attack stories from findings.
Analyst Copilot: Chat interface for Q&A grounded in session data.
Training Mode: Educational guided analysis with hints.

Uses OpenAI API (configurable) — gracefully degrades without API key.
"""

import json
import logging
from typing import List, Dict, Optional, Generator

logger = logging.getLogger("threatscope.ai")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class AICore:
    """
    Shared AI functionality for narrative generation, copilot,
    and training mode. Uses OpenAI API with graceful degradation.
    """

    def __init__(self, api_key: str = "", model: str = "gpt-4"):
        from config import OPENAI_API_KEY, OPENAI_MODEL
        self.api_key = api_key or OPENAI_API_KEY
        self.model = model or OPENAI_MODEL
        self.available = bool(self.api_key) and REQUESTS_AVAILABLE
        self._conversation_history: List[dict] = []

    def _call_openai(self, messages: List[dict], max_tokens: int = 2000,
                     temperature: float = 0.7) -> str:
        """
        Call OpenAI API.

        Args:
            messages: List of message dicts with 'role' and 'content'.
            max_tokens: Maximum response tokens.
            temperature: Creativity parameter.

        Returns:
            Response text string.
        """
        if not self.available:
            return self._generate_fallback_response(messages)

        try:
            resp = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                },
                timeout=60,
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
            else:
                logger.warning(f"OpenAI API error: {resp.status_code} {resp.text[:200]}")
                return self._generate_fallback_response(messages)
        except Exception as e:
            logger.error(f"OpenAI API call failed: {e}")
            return self._generate_fallback_response(messages)

    def _generate_fallback_response(self, messages: List[dict]) -> str:
        """Generate a helpful response without API access."""
        return (
            "⚠️ AI features require an OpenAI API key. "
            "Set your API key in Settings → API Configuration, or set the "
            "OPENAI_API_KEY environment variable. "
            "Analysis data is still available in the Dashboard and Findings tabs."
        )


class NarrativeEngine(AICore):
    """
    Generates coherent attack narratives from analysis findings.
    Instead of a raw list of alerts, produces a readable attack story.
    """

    SYSTEM_PROMPT = """You are an expert DFIR analyst writing a professional incident report narrative.
Given the analysis findings, timeline, IOCs, and correlations, write a clear, coherent attack story.

Structure your narrative as:
1. **Executive Summary** — 2-3 sentence overview of the incident
2. **Initial Access** — How the attacker gained entry
3. **Attack Progression** — Step-by-step what the attacker did, in chronological order
4. **Impact Assessment** — What was compromised, what data was at risk
5. **IOCs & Artifacts** — Key indicators found
6. **Recommendations** — Immediate containment and remediation steps

Use professional language suitable for an executive audience.
Reference specific MITRE ATT&CK techniques where relevant.
Be specific with timestamps, IPs, and usernames when available."""

    def generate_narrative(self, results: dict) -> str:
        """
        Generate an attack narrative from analysis results.

        Args:
            results: Complete analysis results dictionary.

        Returns:
            Narrative text string.
        """
        context = self._build_context(results)

        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": f"Generate an attack narrative for this analysis:\n\n{context}"},
        ]

        return self._call_openai(messages, max_tokens=3000, temperature=0.6)

    def _build_context(self, results: dict) -> str:
        """Build a concise context string from results."""
        parts = []

        parts.append(f"**File:** {results.get('metadata', {}).get('filepath', 'Unknown')}")
        parts.append(f"**Threat Score:** {results.get('threat_score', 0)}% ({results.get('threat_level', 'Unknown')})")

        summary = results.get("summary", {})
        parts.append(f"**Findings:** {summary.get('total_findings', 0)} total — "
                     f"{summary.get('critical', 0)} critical, {summary.get('high', 0)} high")
        parts.append(f"**MITRE Techniques:** {summary.get('mitre_techniques', 0)}")
        parts.append(f"**IOCs:** {summary.get('total_iocs', 0)}")

        # Top findings (limit)
        findings = results.get("findings", [])[:15]
        if findings:
            parts.append("\n**Top Findings:**")
            for f in findings:
                parts.append(f"- [{f.get('severity', '').upper()}] {f.get('title', '')} — {f.get('description', '')}")
                if f.get("mitre"):
                    parts.append(f"  MITRE: {f['mitre']}")
                if f.get("timestamp"):
                    parts.append(f"  Time: {f['timestamp']}")

        # Correlations
        corrs = results.get("correlations", {}).get("correlations", [])
        if corrs:
            parts.append("\n**Attack Correlations:**")
            for c in corrs[:5]:
                parts.append(f"- [{c['severity'].upper()}] {c['name']}: {c['description']}")

        # IOCs
        iocs = results.get("iocs", {})
        if iocs.get("top_ips"):
            parts.append(f"\n**Top IPs:** {', '.join(iocs['top_ips'][:5])}")
        if iocs.get("top_domains"):
            parts.append(f"**Top Domains:** {', '.join(iocs['top_domains'][:5])}")

        return "\n".join(parts)


class AnalystCopilot(AICore):
    """
    Chat interface for analyst Q&A grounded in current session data.
    Supports contextual follow-up questions about the analysis.
    """

    SYSTEM_PROMPT = """You are ThreatScope AI Copilot — an expert DFIR analyst assistant.
You have access to the current analysis session data. Answer questions about:
- Specific findings, their severity, and impact
- IOCs and their significance
- MITRE ATT&CK techniques detected
- Recommendations for containment and remediation
- Attack correlations and behavioral chains

Be concise, professional, and actionable.
If you reference specific data from the analysis, cite it specifically.
If asked about something not in the data, say so honestly."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._session_context = ""
        self._chat_history: List[dict] = []

    def set_context(self, results: dict):
        """
        Set the analysis context for the copilot session.

        Args:
            results: Complete analysis results dictionary.
        """
        narrative_engine = NarrativeEngine(api_key=self.api_key, model=self.model)
        self._session_context = narrative_engine._build_context(results)
        self._chat_history = []

    def ask(self, question: str) -> str:
        """
        Ask the copilot a question about the current analysis.

        Args:
            question: The analyst's question.

        Returns:
            AI response string.
        """
        if not self._session_context:
            return "No analysis context loaded. Please run an analysis first."

        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "system", "content": f"Current Analysis Data:\n{self._session_context}"},
        ]

        # Add conversation history
        messages.extend(self._chat_history[-10:])  # Last 10 messages
        messages.append({"role": "user", "content": question})

        response = self._call_openai(messages, max_tokens=1500, temperature=0.5)

        # Track history
        self._chat_history.append({"role": "user", "content": question})
        self._chat_history.append({"role": "assistant", "content": response})

        return response

    def get_history(self) -> List[dict]:
        """Get the chat history."""
        return self._chat_history


class TrainingMode(AICore):
    """
    Educational mode that guides analysts with questions and hints
    instead of showing answers directly.
    """

    SYSTEM_PROMPT = """You are a cybersecurity instructor using the Socratic method.
The student is analyzing a security incident. Instead of directly showing findings,
guide them step by step with questions and hints.

When the student asks about the analysis:
1. Ask them what they've observed so far
2. Give a hint about what to look for next
3. If they're stuck, provide a small clue
4. Confirm correct observations and explain why they matter
5. Connect findings to the MITRE ATT&CK framework

Never reveal all findings at once. Build understanding progressively.
Be encouraging and educational."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._session_context = ""
        self._revealed_findings: List[str] = []
        self._chat_history: List[dict] = []

    def set_context(self, results: dict):
        """Set analysis context for training mode."""
        narrative_engine = NarrativeEngine(api_key=self.api_key, model=self.model)
        self._session_context = narrative_engine._build_context(results)
        self._revealed_findings = []
        self._chat_history = []

    def interact(self, message: str) -> str:
        """
        Interact with the training assistant.

        Args:
            message: Student's message.

        Returns:
            Educational response with guidance.
        """
        if not self._session_context:
            return "No analysis loaded. Upload and analyze a log file first."

        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "system", "content": f"[HIDDEN - Full Analysis Data — do NOT reveal directly]:\n{self._session_context}"},
            {"role": "system", "content": f"Findings already revealed to student: {self._revealed_findings}"},
        ]

        messages.extend(self._chat_history[-10:])
        messages.append({"role": "user", "content": message})

        response = self._call_openai(messages, max_tokens=1000, temperature=0.7)

        self._chat_history.append({"role": "user", "content": message})
        self._chat_history.append({"role": "assistant", "content": response})

        return response

    def get_hint(self) -> str:
        """Get a hint about the next finding to discover."""
        return self.interact("I'm stuck. Can you give me a hint about what to look for?")
