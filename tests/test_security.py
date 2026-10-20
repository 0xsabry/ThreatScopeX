"""Regression tests for security helpers (path containment, CSRF)."""
from pathlib import Path

from core.security import InputValidator, CSRFProtection, is_within


def test_is_within_rejects_prefix_siblings(tmp_path):
    base = tmp_path / "uploads"
    base.mkdir()
    evil = tmp_path / "uploads_evil"
    evil.mkdir()
    assert is_within(base / "a.log", base) is True
    assert is_within(evil / "a.log", base) is False


def test_validate_filepath_blocks_traversal(tmp_path):
    base = tmp_path / "uploads"
    base.mkdir()
    inside = base / "ok.log"
    inside.write_text("x")
    valid, _ = InputValidator.validate_filepath(str(inside), base)
    assert valid is True

    outside = tmp_path / "secret.txt"
    outside.write_text("x")
    valid, _ = InputValidator.validate_filepath(str(outside), base)
    assert valid is False


def test_validate_path_within_roots(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    f = root / "auth.log"
    f.write_text("data")
    ok, _ = InputValidator.validate_path_within_roots(str(f), [root], require_file=True)
    assert ok is True

    bad, _ = InputValidator.validate_path_within_roots(
        str(tmp_path / "elsewhere.log"), [root]
    )
    assert bad is False


def test_csrf_token_roundtrip():
    session = {}
    token = CSRFProtection.get_token(session)
    assert token
    assert CSRFProtection.validate(session, token) is True
    assert CSRFProtection.validate(session, "wrong") is False
    assert CSRFProtection.validate({}, token) is False
