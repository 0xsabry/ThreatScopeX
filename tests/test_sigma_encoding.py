"""Regression tests for Sigma encoding modifiers (wide/utf16* and base64offset).

The fixtures are constructed independently with the stdlib codecs/base64 so the
tests do not merely echo the implementation's own output.
"""
import base64

import pytest

from core.sigma_engine import SigmaRule


def _rule(detection: dict) -> SigmaRule:
    return SigmaRule({"title": "t", "detection": detection, "level": "high"})


def _event(fields=None, raw=""):
    return {"fields": fields or {}, "raw": raw}


def _utf16le_field(text: str) -> str:
    """UTF-16LE bytes rendered as a 1:1 (latin-1) string, as log parsers emit."""
    return text.encode("utf-16-le").decode("latin-1")


def _utf16be_field(text: str) -> str:
    return text.encode("utf-16-be").decode("latin-1")


# ---------------------------------------------------------------- Fix 1: wide
def test_wide_matches_genuine_utf16le_field():
    # A terminal encoding modifier is invalid (nothing can match its raw
    # bytes literally), so a match modifier must follow it.
    rule = _rule({"s": {"CommandLine|wide|contains": "cmd"}, "condition": "s"})
    assert rule.matches(_event({"CommandLine": _utf16le_field("cmd")})) is True


def test_wide_does_not_match_plain_ascii_field():
    # A plain ASCII field must not match just because the untransformed value is
    # present; the candidate is the UTF-16LE (NUL-interleaved) form.
    rule = _rule({"s": {"CommandLine|wide|contains": "cmd"}, "condition": "s"})
    assert rule.matches(_event({"CommandLine": "cmd"})) is False


def test_wide_is_alias_of_utf16le():
    wide = _rule({"s": {"F|wide|contains": "cmd"}, "condition": "s"})
    utf16le = _rule({"s": {"F|utf16le|contains": "cmd"}, "condition": "s"})
    field = _utf16le_field("cmd")
    wide_result = wide.matches(_event({"F": field}))
    utf16le_result = utf16le.matches(_event({"F": field}))
    assert wide_result is True
    assert utf16le_result is True
    assert wide_result == utf16le_result


def test_utf16be_matches_genuine_big_endian_field():
    rule = _rule({"s": {"F|utf16be|contains": "cmd"}, "condition": "s"})
    assert rule.matches(_event({"F": _utf16be_field("cmd")})) is True
    assert rule.matches(_event({"F": _utf16le_field("cmd")})) is False


def test_utf16_matches_bom_prefixed_field():
    # pySigma's `utf16` prepends the U+FEFF BOM character, then UTF-16LE data.
    rule = _rule({"s": {"F|utf16|contains": "cmd"}, "condition": "s"})
    assert rule.matches(_event({"F": "\ufeff" + _utf16le_field("cmd")})) is True


def test_wide_with_contains_matches_embedded_value():
    rule = _rule({"s": {"CommandLine|wide|contains": "cmd"}, "condition": "s"})
    field = "prefix " + _utf16le_field("cmd") + " suffix"
    assert rule.matches(_event({"CommandLine": field})) is True
    assert rule.matches(_event({"CommandLine": "prefix cmd suffix"})) is False


def test_wide_field_name_is_case_insensitive():
    rule = _rule({"s": {"commandline|wide|contains": "cmd"}, "condition": "s"})
    assert rule.matches(_event({"CommandLine": _utf16le_field("cmd")})) is True


def test_terminal_encoding_modifier_is_rejected():
    # `wide`/`utf16*` as the last modifier can never match literally, so the
    # rule is invalid and must not detect.
    rule = _rule({"s": {"F|wide": "cmd"}, "condition": "s"})
    assert rule.valid is False
    assert any("terminate" in e for e in rule.validation_errors)
    assert rule.matches(_event({"F": _utf16le_field("cmd")})) is False


def test_wide_empty_input_returns_bool_without_crashing():
    rule = _rule({"s": {"F|wide|contains": ""}, "condition": "s"})
    # An empty value produces no encoded candidate; it must not over-match.
    assert rule.matches(_event({"F": ""})) is False


def test_wide_then_base64_chain():
    rule = _rule({"s": {"F|wide|base64|contains": "cmd"}, "condition": "s"})
    encoded = base64.b64encode("cmd".encode("utf-16-le")).decode()
    assert rule.matches(_event({"F": "prefix " + encoded})) is True


def test_utf16_then_base64_uses_utf16_bom_bytes():
    # The U+FEFF BOM must be encoded as FF FE (UTF-16LE BOM), not EF BB BF.
    rule = _rule({"s": {"F|utf16|base64|contains": "cmd"}, "condition": "s"})
    encoded = base64.b64encode(b"\xff\xfe" + "cmd".encode("utf-16-le")).decode()
    assert rule.matches(_event({"F": encoded})) is True


# ---------------------------------------------------------- Fix 2: base64offset
def test_base64offset_reference_vectors():
    # Reference vectors produced by pySigma's SigmaBase64OffsetModifier for
    # "cmd" (all three byte alignments).
    assert SigmaRule._expand_value("cmd", ["base64offset"]) == ["Y21k", "NtZ", "jbW"]


@pytest.mark.parametrize("offset", [0, 1, 2])
def test_base64offset_matches_each_alignment_inside_longer_value(offset):
    value = b"Invoke-Mimikatz"
    # 4*offset ≡ offset (mod 3), so the value starts at the requested alignment.
    buffer = b"HEAD" * offset + value + b"TAILTAIL"
    field = base64.b64encode(buffer).decode()
    rule = _rule(
        {"s": {"CommandLine|base64offset|contains": "Invoke-Mimikatz"}, "condition": "s"}
    )
    assert rule.matches(_event({"CommandLine": field})) is True


def test_base64offset_does_not_match_unrelated_encoded_value():
    rule = _rule({"s": {"F|base64offset|contains": "cmd"}, "condition": "s"})
    unrelated = base64.b64encode(b"totally unrelated payload").decode()
    assert rule.matches(_event({"F": unrelated})) is False


def test_base64offset_does_not_match_plaintext_value():
    rule = _rule({"s": {"F|base64offset|contains": "cmd"}, "condition": "s"})
    assert rule.matches(_event({"F": "cmd"})) is False


def test_base64offset_with_wildcard_value_does_not_match_or_crash():
    rule = _rule({"s": {"F|base64offset|contains": "cm*"}, "condition": "s"})
    assert rule.matches(_event({"F": "anything"})) is False


@pytest.mark.parametrize("offset", [0, 1, 2])
def test_utf16_base64offset_chain_matches_all_alignments(offset):
    data = b"\xff\xfe" + "cmd".encode("utf-16-le")
    # Prefix length ≡ offset (mod 3) so the data lands at the requested alignment.
    buffer = b"Z" * (3 + offset) + data
    field = base64.b64encode(buffer).decode()
    rule = _rule({"s": {"F|utf16|base64offset|contains": "cmd"}, "condition": "s"})
    assert rule.matches(_event({"F": field})) is True


def test_base64_is_exact_value_not_substring():
    # Sigma semantics: `base64` transforms the value; the default matcher is
    # equality. An embedded encoding requires an explicit `|contains`.
    encoded = base64.b64encode(b"Invoke-Mimikatz").decode()
    rule = _rule({"s": {"CommandLine|base64": "Invoke-Mimikatz"}, "condition": "s"})
    assert rule.matches(_event({"CommandLine": encoded})) is True
    assert rule.matches(_event({"CommandLine": "powershell -enc " + encoded})) is False


def test_base64_keeps_rfc4648_padding():
    encoded = base64.b64encode(b"ping").decode()
    assert encoded.endswith("==")
    rule = _rule({"s": {"F|base64": "ping"}, "condition": "s"})
    assert rule.matches(_event({"F": encoded})) is True
    # The old behavior stripped padding; verify the unpadded form is not matched.
    assert rule.matches(_event({"F": encoded.rstrip("=")})) is False


def test_base64_with_contains_matches_embedded_value():
    encoded = base64.b64encode(b"Invoke-Mimikatz").decode()
    rule = _rule({"s": {"CommandLine|base64|contains": "Invoke-Mimikatz"}, "condition": "s"})
    assert rule.matches(_event({"CommandLine": "powershell -enc " + encoded})) is True
