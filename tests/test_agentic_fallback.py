"""Regression tests for AgenticCopilot AI fallback behaviour.

When the AI provider is disabled, unavailable, returns ``None`` or fails, the
copilot must fall back to the offline engine instead of propagating ``None``.
"""
import json

import config
from ai.ai_core import AICore
from ai.agentic_core import AgenticCopilot, HypothesisEngine


class _StubAI:
    """Minimal stand-in for AICore with a controllable completion."""

    def __init__(self, response):
        self.available = True
        self._response = response

    def _call_openai(self, messages, max_tokens=0, temperature=0.0):
        return self._response


class _RaisingAI:
    """Stand-in provider that raises instead of returning a response."""

    available = True

    def _call_openai(self, messages, max_tokens=0, temperature=0.0):
        raise RuntimeError("provider exploded")


def _results():
    return {
        "threat_score": 50,
        "threat_level": "HIGH",
        "summary": {"total_findings": 4, "critical": 1, "high": 2},
        "mitre_hits": {"T1003": 2},
        "findings": [],
        "iocs": {"hashes": {"md5": ["a" * 32]}, "top_ips": []},
    }


def _copilot_after_investigation():
    copilot = AgenticCopilot()
    copilot.investigate(_results())
    return copilot


# ------------------------------------------------------------ Fix 4: ask()
def test_ask_uses_successful_ai_response():
    copilot = _copilot_after_investigation()
    copilot.ai_core = _StubAI("AI SAYS HI")
    assert copilot.ask("summary") == "AI SAYS HI"


def test_ask_falls_back_when_ai_returns_none():
    copilot = _copilot_after_investigation()
    copilot.ai_core = _StubAI(None)
    expected = copilot._ask_offline("summary")
    response = copilot.ask("summary")
    assert isinstance(response, str)
    assert response
    assert response == expected


def test_ask_falls_back_when_provider_raises():
    copilot = _copilot_after_investigation()
    copilot.ai_core = _RaisingAI()
    expected = copilot._ask_offline("summary")
    assert copilot.ask("summary") == expected


def test_ask_does_not_record_history_when_provider_raises():
    copilot = _copilot_after_investigation()
    copilot.ai_core = _RaisingAI()
    copilot._chat_history = []
    copilot.ask("summary")
    assert copilot._chat_history == []


def test_ask_does_not_record_history_when_ai_fails():
    copilot = _copilot_after_investigation()
    copilot.ai_core = _StubAI(None)
    copilot._chat_history = []
    copilot.ask("summary")
    assert copilot._chat_history == []


def test_ask_records_history_on_success():
    copilot = _copilot_after_investigation()
    copilot.ai_core = _StubAI("AI SAYS HI")
    copilot._chat_history = []
    copilot.ask("summary")
    assert len(copilot._chat_history) == 2


def test_ask_never_returns_none_when_ai_disabled(monkeypatch):
    monkeypatch.setattr(config, "OPENAI_API_KEY", "")
    monkeypatch.setattr(config, "AI_SEND_DATA", False)
    copilot = _copilot_after_investigation()
    assert copilot.ai_core is None or copilot.ai_core.available is False
    response = copilot.ask("summary")
    assert isinstance(response, str)
    assert response


def test_consent_denied_disables_ai_even_with_key(monkeypatch):
    monkeypatch.setattr(config, "OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(config, "AI_SEND_DATA", False)
    assert AICore().available is False


# ------------------------------------------------ Fix 4: hypothesis engine
def test_generate_ai_hypotheses_returns_empty_on_none():
    engine = HypothesisEngine(ai_core=_StubAI(None))
    assert engine._generate_ai_hypotheses(_results()) == []


def test_generate_ai_hypotheses_returns_empty_when_provider_raises():
    engine = HypothesisEngine(ai_core=_RaisingAI())
    assert engine._generate_ai_hypotheses(_results()) == []


def test_hypotheses_fall_back_to_heuristics_when_provider_raises():
    engine = HypothesisEngine(ai_core=_RaisingAI())
    assert len(engine.generate_from_results(_results())) > 0


def test_hypotheses_fall_back_to_heuristics_when_ai_returns_none():
    ai_engine = HypothesisEngine(ai_core=_StubAI(None))
    gained = ai_engine.generate_from_results(_results())

    baseline = HypothesisEngine()
    expected = baseline._generate_heuristic_hypotheses(_results())

    assert len(gained) == len(expected)
    assert len(gained) > 0


def test_hypotheses_use_valid_ai_json():
    payload = json.dumps([
        {
            "title": "Credential Access",
            "description": "LSASS access suggests credential dumping",
            "priority": 9,
            "mitre_techniques": ["T1003"],
            "evidence_needed": ["Check LSASS handles"],
        }
    ])
    engine = HypothesisEngine(ai_core=_StubAI(payload))
    hypotheses = engine.generate_from_results(_results())
    assert len(hypotheses) == 1
    assert hypotheses[0].title == "Credential Access"
    assert hypotheses[0].priority == 9
    assert hypotheses[0].investigation_notes == ["[AI] Look for: Check LSASS handles"]


def test_hypotheses_malformed_json_falls_back_to_heuristics():
    engine = HypothesisEngine(ai_core=_StubAI("this is not json"))
    assert engine._generate_ai_hypotheses(_results()) == []
    # generate_from_results must still produce heuristic hypotheses.
    assert len(engine.generate_from_results(_results())) > 0


def test_hypotheses_non_list_json_returns_empty():
    engine = HypothesisEngine(ai_core=_StubAI('{"title": "not a list"}'))
    assert engine._generate_ai_hypotheses(_results()) == []


def test_hypotheses_skips_non_dict_entries():
    engine = HypothesisEngine(ai_core=_StubAI('[1, 2, {"title": "ok", "priority": 3}]'))
    hypotheses = engine._generate_ai_hypotheses(_results())
    assert [h.title for h in hypotheses] == ["ok"]


def test_hypotheses_coerces_malformed_field_types():
    payload = (
        '[{"title": "x", "priority": "not-a-number", '
        '"mitre_techniques": "T1003", "evidence_needed": "note"}]'
    )
    engine = HypothesisEngine(ai_core=_StubAI(payload))
    hypotheses = engine._generate_ai_hypotheses(_results())
    assert len(hypotheses) == 1
    assert hypotheses[0].priority == 5
    assert hypotheses[0].mitre_techniques == []
    assert hypotheses[0].investigation_notes == []


def test_hypotheses_accepts_numeric_string_priority():
    engine = HypothesisEngine(ai_core=_StubAI('[{"title": "x", "priority": "7"}]'))
    hypotheses = engine._generate_ai_hypotheses(_results())
    assert hypotheses[0].priority == 7
