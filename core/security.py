"""
ThreatScope V3 — Security Hardening Module
Author: 0xSABRY

Centralized security controls for the ThreatScope platform:
  - Input validation & sanitization
  - Rate limiting (in-memory token bucket per IP)
  - Secure file handling with path traversal prevention
  - Security response headers middleware
  - Audit logging for security events
"""

import os
import re
import time
import hmac
import hashlib
import logging
import secrets
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Tuple
from collections import defaultdict
from functools import wraps

logger = logging.getLogger("threatscope.security")


def is_within(child: Path, base: Path) -> bool:
    """
    Return True only if ``child`` resolves to ``base`` or a path inside it.

    Uses ``os.path.commonpath`` on the fully resolved absolute paths so that
    sibling directories sharing a prefix (e.g. ``/uploads`` vs ``/uploads_evil``)
    are correctly rejected. This replaces a naive ``str.startswith`` check.
    """
    try:
        child_resolved = Path(child).resolve()
        base_resolved = Path(base).resolve()
        common = os.path.commonpath([str(child_resolved), str(base_resolved)])
        return common == str(base_resolved)
    except (ValueError, OSError):
        # Different drives on Windows raise ValueError; treat as not contained.
        return False


# ============================================================
# Input Validator
# ============================================================
class InputValidator:
    """
    Centralized input validation for all user-supplied data.
    Prevents injection attacks, path traversal, and malformed input.
    """

    # Allowed filename characters (restrictive whitelist)
    SAFE_FILENAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-. ]{0,254}$")

    # Dangerous path components
    PATH_TRAVERSAL_PATTERNS = [
        "..", "~", "%2e", "%2E", "%252e", "%00",
        "..\\", "../", "....//", "..;/",
    ]

    # Max lengths for common inputs
    MAX_LENGTHS = {
        "filename": 255,
        "filepath": 1024,
        "question": 2000,
        "format_type": 10,
        "cve_id": 20,
        "api_key": 128,
        "hostname": 253,
    }

    @staticmethod
    def validate_filename(filename: str) -> Tuple[bool, str]:
        """
        Validate a filename is safe for filesystem operations.

        Args:
            filename: The filename to validate.

        Returns:
            Tuple of (is_valid, sanitized_filename_or_error).
        """
        if not filename or not isinstance(filename, str):
            return False, "Empty or invalid filename"

        filename = filename.strip()

        if len(filename) > InputValidator.MAX_LENGTHS["filename"]:
            return False, "Filename too long"

        # Check for path traversal
        for pattern in InputValidator.PATH_TRAVERSAL_PATTERNS:
            if pattern in filename:
                logger.warning(f"Path traversal attempt blocked in filename: {filename!r}")
                return False, "Invalid filename: path traversal detected"

        # Check for null bytes
        if "\x00" in filename:
            logger.warning("Null byte injection attempt in filename")
            return False, "Invalid filename: null byte detected"

        # Ensure filename matches safe pattern
        if not InputValidator.SAFE_FILENAME_RE.match(filename):
            return False, "Filename contains invalid characters"

        return True, filename

    @staticmethod
    def validate_filepath(filepath: str, allowed_base: Path) -> Tuple[bool, str]:
        """
        Validate a filepath stays within allowed directory boundaries.

        Args:
            filepath: The file path to validate.
            allowed_base: The base directory paths must reside within.

        Returns:
            Tuple of (is_valid, error_message_if_invalid).
        """
        if not filepath or not isinstance(filepath, str):
            return False, "Empty or invalid filepath"

        # Check for path traversal patterns
        for pattern in InputValidator.PATH_TRAVERSAL_PATTERNS:
            if pattern in filepath:
                logger.warning(f"Path traversal attempt: {filepath!r}")
                return False, "Path traversal detected"

        try:
            resolved = Path(filepath).resolve()
            allowed = allowed_base.resolve()

            # Ensure the resolved path is under the allowed base
            if not is_within(resolved, allowed):
                logger.warning(f"Path escape attempt: {resolved} not under {allowed}")
                return False, "Path outside allowed directory"

            return True, ""
        except Exception as e:
            return False, f"Invalid path: {e}"

    @staticmethod
    def validate_path_within_roots(
        filepath: str, allowed_roots: list, require_file: bool = False
    ) -> Tuple[bool, str]:
        """
        Validate that a path resolves inside at least one allowed root directory.

        Unlike :meth:`validate_filepath`, this accepts a set of permitted roots
        (used for live-monitoring of well-known log locations) while still
        rejecting traversal and out-of-tree paths.

        Args:
            filepath: The path supplied by the caller.
            allowed_roots: Iterable of base directories the path must reside in.
            require_file: When True, also require the target to be a regular file.

        Returns:
            Tuple of (is_valid, error_message_if_invalid).
        """
        if not filepath or not isinstance(filepath, str):
            return False, "Empty or invalid filepath"

        for pattern in InputValidator.PATH_TRAVERSAL_PATTERNS:
            if pattern in filepath:
                logger.warning(f"Path traversal attempt: {filepath!r}")
                return False, "Path traversal detected"

        target = Path(filepath)
        if require_file and not target.is_file():
            return False, "Path is not a regular file"
        if not target.exists():
            return False, "Path not found"

        if not any(is_within(target, root) for root in allowed_roots):
            logger.warning(f"Path outside allowed monitor roots: {target}")
            return False, "Path outside allowed directories"

        return True, ""

    @staticmethod
    def validate_cve_id(cve_id: str) -> Tuple[bool, str]:
        """Validate a CVE identifier format."""
        if not cve_id or not isinstance(cve_id, str):
            return False, "Empty CVE ID"
        pattern = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
        if not pattern.match(cve_id.strip()):
            return False, "Invalid CVE ID format"
        return True, cve_id.strip().upper()

    @staticmethod
    def validate_format_type(format_type: str) -> Tuple[bool, str]:
        """Validate export format type."""
        allowed = {"json", "csv", "stix", "pdf", "docx"}
        if format_type and format_type.lower() in allowed:
            return True, format_type.lower()
        return False, f"Invalid format. Allowed: {', '.join(sorted(allowed))}"

    @staticmethod
    def sanitize_string(value: str, max_length: int = 2000) -> str:
        """
        Sanitize a string by removing dangerous characters and limiting length.

        Args:
            value: The string to sanitize.
            max_length: Maximum allowed length.

        Returns:
            Sanitized string.
        """
        if not isinstance(value, str):
            return ""
        # Remove null bytes and control characters (except newline, tab)
        cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
        return cleaned[:max_length]

    @staticmethod
    def validate_file_magic(filepath: str, allowed_extensions: set) -> Tuple[bool, str]:
        """
        Validate file content matches its extension (magic byte check).

        Args:
            filepath: Path to the file.
            allowed_extensions: Set of allowed extensions.

        Returns:
            Tuple of (is_valid, error_message).
        """
        ext = Path(filepath).suffix.lower()
        if ext not in allowed_extensions:
            return False, f"Extension {ext} not allowed"

        try:
            with open(filepath, "rb") as f:
                header = f.read(16)

            # Check for known dangerous magic bytes in log files
            if ext in {".log", ".txt", ".csv", ".syslog"}:
                # These should be text files, not binaries
                if header[:2] == b"MZ" or header[:4] == b"\x7fELF":
                    logger.warning(f"Binary file disguised as text: {filepath}")
                    return False, "Binary content in text file"

            return True, ""
        except Exception as e:
            return False, f"Cannot read file: {e}"


# ============================================================
# Rate Limiter (Token Bucket)
# ============================================================
class RateLimiter:
    """
    In-memory token bucket rate limiter per client IP.

    Prevents API abuse, brute-force attacks, and DoS attempts
    without requiring external dependencies like Redis.
    """

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        """
        Initialize the rate limiter.

        Args:
            max_requests: Maximum requests allowed per window.
            window_seconds: Time window in seconds.
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets: Dict[str, list] = defaultdict(list)
        self._blocked: Dict[str, float] = {}  # IP -> block expiry timestamp
        self._block_duration = 300  # 5 minutes block after limit exceeded

    def is_allowed(self, client_ip: str) -> Tuple[bool, Dict]:
        """
        Check if a request from the given IP is allowed.

        Args:
            client_ip: The client's IP address.

        Returns:
            Tuple of (is_allowed, rate_limit_info).
        """
        now = time.time()

        # Check if IP is currently blocked
        if client_ip in self._blocked:
            if now < self._blocked[client_ip]:
                remaining_block = int(self._blocked[client_ip] - now)
                return False, {
                    "blocked": True,
                    "retry_after": remaining_block,
                    "reason": "Rate limit exceeded — temporarily blocked",
                }
            else:
                del self._blocked[client_ip]

        # Clean old entries outside the window
        cutoff = now - self.window_seconds
        self._buckets[client_ip] = [
            t for t in self._buckets[client_ip] if t > cutoff
        ]

        current_count = len(self._buckets[client_ip])

        if current_count >= self.max_requests:
            # Block the IP
            self._blocked[client_ip] = now + self._block_duration
            logger.warning(f"Rate limit exceeded for {client_ip} — blocked for {self._block_duration}s")
            return False, {
                "blocked": True,
                "retry_after": self._block_duration,
                "reason": "Rate limit exceeded",
            }

        # Record this request
        self._buckets[client_ip].append(now)

        return True, {
            "blocked": False,
            "remaining": self.max_requests - current_count - 1,
            "reset_at": int(cutoff + self.window_seconds),
        }

    def cleanup(self):
        """Remove stale entries to prevent memory leaks."""
        now = time.time()
        cutoff = now - self.window_seconds

        stale_ips = [
            ip for ip, timestamps in self._buckets.items()
            if not timestamps or max(timestamps) < cutoff
        ]
        for ip in stale_ips:
            del self._buckets[ip]

        expired_blocks = [
            ip for ip, expiry in self._blocked.items()
            if now >= expiry
        ]
        for ip in expired_blocks:
            del self._blocked[ip]


# ============================================================
# Secure File Handler
# ============================================================
class SecureFileHandler:
    """
    Safe file operations with path traversal prevention and sandboxing.
    All file operations go through this handler to ensure security.
    """

    def __init__(self, upload_dir: Path, export_dir: Path):
        """
        Initialize with allowed directories.

        Args:
            upload_dir: Directory for file uploads.
            export_dir: Directory for report exports.
        """
        self.upload_dir = upload_dir.resolve()
        self.export_dir = export_dir.resolve()

    def safe_save_upload(self, file_storage, filename: str) -> Tuple[bool, str]:
        """
        Safely save an uploaded file with full validation.

        Args:
            file_storage: Flask FileStorage object.
            filename: The sanitized filename.

        Returns:
            Tuple of (success, filepath_or_error).
        """
        # Validate filename
        valid, result = InputValidator.validate_filename(filename)
        if not valid:
            return False, result

        # Construct safe path
        safe_path = self.upload_dir / result
        resolved = safe_path.resolve()

        # Ensure we're still in the upload directory
        if not is_within(resolved, self.upload_dir):
            logger.warning(f"Upload path escape: {resolved}")
            return False, "Invalid upload path"

        try:
            file_storage.save(str(resolved))

            # Verify the file was actually saved and size is reasonable
            if not resolved.exists():
                return False, "File save failed"

            file_size = resolved.stat().st_size
            if file_size == 0:
                resolved.unlink()
                return False, "Empty file"

            return True, str(resolved)
        except Exception as e:
            logger.error(f"Upload save error: {e}")
            return False, "File save failed"

    def safe_export_path(self, filename: str) -> Tuple[bool, str]:
        """
        Generate a safe export file path.

        Args:
            filename: The export filename.

        Returns:
            Tuple of (success, filepath_or_error).
        """
        valid, result = InputValidator.validate_filename(filename)
        if not valid:
            return False, result

        safe_path = self.export_dir / result
        resolved = safe_path.resolve()

        if not is_within(resolved, self.export_dir):
            return False, "Invalid export path"

        return True, str(resolved)


# ============================================================
# Security Headers Middleware
# ============================================================
class SecurityHeaders:
    """
    Flask middleware that adds security headers to all responses.
    Implements OWASP recommended security headers.
    """

    # Default security headers
    HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    }

    CSP_POLICY = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none';"
    )

    @classmethod
    def apply(cls, response):
        """
        Apply security headers to a Flask response.

        Args:
            response: Flask response object.

        Returns:
            Response with security headers added.
        """
        for header, value in cls.HEADERS.items():
            response.headers[header] = value

        response.headers["Content-Security-Policy"] = cls.CSP_POLICY

        return response


# ============================================================
# Audit Logger
# ============================================================
class AuditLogger:
    """
    Logs all security-relevant actions for forensic analysis.
    Actions include file uploads, analysis runs, API access,
    and security events.
    """

    def __init__(self, log_dir: Optional[Path] = None):
        """
        Initialize the audit logger.

        Args:
            log_dir: Directory for audit log files.
        """
        if log_dir is None:
            from config import LOG_DIR
            log_dir = LOG_DIR

        log_dir.mkdir(parents=True, exist_ok=True)

        self._logger = logging.getLogger("threatscope.audit")
        if not self._logger.handlers:
            handler = logging.FileHandler(
                str(log_dir / "audit.log"),
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter(
                "%(asctime)s | %(levelname)s | %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%SZ",
            ))
            self._logger.addHandler(handler)
            self._logger.setLevel(logging.INFO)

    def log_upload(self, client_ip: str, filename: str, file_size: int, success: bool):
        """Log a file upload event."""
        status = "SUCCESS" if success else "FAILED"
        self._logger.info(
            f"UPLOAD | ip={self._anonymize_ip(client_ip)} | "
            f"file={filename} | size={file_size} | status={status}"
        )

    def log_analysis(self, client_ip: str, filepath: str, threat_score: int):
        """Log an analysis run."""
        self._logger.info(
            f"ANALYSIS | ip={self._anonymize_ip(client_ip)} | "
            f"file={Path(filepath).name} | threat_score={threat_score}"
        )

    def log_export(self, client_ip: str, format_type: str, success: bool):
        """Log a report export."""
        status = "SUCCESS" if success else "FAILED"
        self._logger.info(
            f"EXPORT | ip={self._anonymize_ip(client_ip)} | "
            f"format={format_type} | status={status}"
        )

    def log_security_event(self, client_ip: str, event_type: str, details: str):
        """Log a security-relevant event."""
        self._logger.warning(
            f"SECURITY | ip={self._anonymize_ip(client_ip)} | "
            f"event={event_type} | details={details}"
        )

    def log_rate_limit(self, client_ip: str, endpoint: str):
        """Log a rate limit event."""
        self._logger.warning(
            f"RATE_LIMIT | ip={self._anonymize_ip(client_ip)} | "
            f"endpoint={endpoint}"
        )

    @staticmethod
    def _anonymize_ip(ip: str) -> str:
        """
        Partially anonymize an IP address for privacy compliance.
        Keeps enough info for security analysis while respecting privacy.
        """
        if not ip:
            return "unknown"
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
        return ip[:len(ip)//2] + "***"


# ============================================================
# CSRF Protection (session-bound synchronizer token)
# ============================================================
class CSRFProtection:
    """
    Minimal, dependency-free CSRF protection using a session-bound
    synchronizer token compared in constant time.

    The token is generated once per session and must be echoed by the
    client in the ``X-CSRF-Token`` header for state-changing requests.
    """

    SESSION_KEY = "_csrf_token"
    HEADER_NAME = "X-CSRF-Token"

    @classmethod
    def get_token(cls, flask_session) -> str:
        """Return (creating if necessary) the CSRF token for this session."""
        token = flask_session.get(cls.SESSION_KEY)
        if not token:
            token = secrets.token_urlsafe(32)
            flask_session[cls.SESSION_KEY] = token
        return token

    @classmethod
    def validate(cls, flask_session, provided_token: Optional[str]) -> bool:
        """
        Constant-time comparison of the provided token against the session token.

        Returns True when the token is present and matches; False otherwise.
        """
        expected = flask_session.get(cls.SESSION_KEY)
        if not expected or not provided_token:
            return False
        try:
            return hmac.compare_digest(str(expected), str(provided_token))
        except (TypeError, ValueError):
            return False
