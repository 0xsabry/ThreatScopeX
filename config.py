"""
ThreatScope V3 — Global Configuration
Author: 0xSABRY

Security-hardened configuration with cryptographically secure defaults.
"""

import os
import secrets
from pathlib import Path

# ============================================================
# Version & Identity
# ============================================================
VERSION = "3.0.0"
APP_NAME = "ThreatScope"
AUTHOR = "0xSABRY"
TAGLINE = "Advanced DFIR & Threat Detection Platform"

# ============================================================
# Paths
# ============================================================
BASE_DIR = Path(__file__).parent.resolve()
SIGMA_RULES_DIR = BASE_DIR / "sigma_rules"
YARA_RULES_DIR = BASE_DIR / "yara_rules"
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = BASE_DIR / "uploads"
EXPORT_DIR = BASE_DIR / "exports"
LOG_DIR = BASE_DIR / "logs"

# Create directories
for d in [SIGMA_RULES_DIR, YARA_RULES_DIR, DATA_DIR, UPLOAD_DIR, EXPORT_DIR, LOG_DIR]:
    d.mkdir(exist_ok=True)

# ============================================================
# SigmaHQ Integration
# ============================================================
SIGMAHQ_REPO_URL = "https://github.com/SigmaHQ/sigma.git"
SIGMAHQ_RULES_SUBDIR = "rules"
SIGMA_SYNC_INTERVAL_DAYS = 7

# ============================================================
# Sigma regex resource limits (per analysis scan)
# ============================================================
# A single catastrophic regex is bounded by the ``regex`` package timeout,
# but a scan can still evaluate thousands of regexes. These scan-scoped
# limits cap the aggregate work. They are intentionally conservative and
# can be tuned with environment variables.
SIGMA_REGEX_MAX_EVALUATIONS = int(
    os.environ.get("THREATSCOPE_SIGMA_REGEX_MAX_EVALUATIONS", "10000")
)
SIGMA_REGEX_MAX_SECONDS = float(
    os.environ.get("THREATSCOPE_SIGMA_REGEX_MAX_SECONDS", "30")
)
SIGMA_REGEX_TIMEOUT_SECONDS = float(
    os.environ.get("THREATSCOPE_SIGMA_REGEX_TIMEOUT_SECONDS", "2")
)
SIGMA_REGEX_MAX_SUBJECT_LENGTH = int(
    os.environ.get("THREATSCOPE_SIGMA_REGEX_MAX_SUBJECT_LENGTH", "1000000")
)

# ============================================================
# API Keys (configurable via env vars or settings page)
# ============================================================
VIRUSTOTAL_API_KEY = os.environ.get("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4")

# ============================================================
# AI data-handling consent (privacy / exfiltration guard)
# ============================================================
# When False (default), NO forensic content is transmitted to external AI
# services. The AI Copilot/Narrative fall back to the local heuristic engine.
# Set THREATSCOPE_AI_SEND_DATA=true to explicitly authorise transmission.
AI_SEND_DATA = os.environ.get("THREATSCOPE_AI_SEND_DATA", "false").lower() == "true"

# Redact sensitive details (absolute paths, encoded blobs) from AI prompts.
# Set THREATSCOPE_AI_REDACT=false to send raw context when transmission is enabled.
AI_REDACT_DATA = os.environ.get("THREATSCOPE_AI_REDACT", "true").lower() == "true"

# ============================================================
# Live-monitor allowed roots
# ============================================================
# Directories that /api/live/start may monitor. Overridable with a
# pathsep-separated THREATSCOPE_MONITOR_ROOTS env var. When unset, a set of
# well-known log locations plus the uploads/logs directories is used.
def _default_monitor_roots() -> list:
    roots = [UPLOAD_DIR, LOG_DIR]
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        roots.append(Path(system_root) / "System32" / "winevt" / "Logs")
    else:
        roots.extend([Path("/var/log"), Path("/var/log/journal")])
    return roots


_monitor_roots_env = os.environ.get("THREATSCOPE_MONITOR_ROOTS", "")
if _monitor_roots_env:
    LIVE_MONITOR_ALLOWED_ROOTS = [
        Path(p).expanduser() for p in _monitor_roots_env.split(os.pathsep) if p
    ]
else:
    LIVE_MONITOR_ALLOWED_ROOTS = _default_monitor_roots()

# ============================================================
# Analysis Settings
# ============================================================
MAX_LOG_LINES = 5_000_000
BEHAVIORAL_CHAIN_WINDOW_MINUTES = 15
FP_SUPPRESSION_THRESHOLD = 0.85
REALTIME_POLL_INTERVAL_SECONDS = 5
ENRICHMENT_CACHE_TTL_HOURS = 24
MAX_CONCURRENT_ENRICHMENTS = 10

# ============================================================
# Security Settings
# ============================================================
# Cryptographically secure SECRET_KEY with env var override
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
FLASK_DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"  # False by default
FLASK_HOST = os.environ.get("FLASK_HOST", "127.0.0.1")
FLASK_PORT = int(os.environ.get("FLASK_PORT", "5000"))

# Rate limiting
RATE_LIMIT_REQUESTS = 120  # per window
RATE_LIMIT_WINDOW = 60     # seconds
RATE_LIMIT_BLOCK_DURATION = 300  # 5 min block after exceeded

# Upload restrictions
MAX_UPLOAD_SIZE_MB = 500
ALLOWED_UPLOAD_EXTENSIONS = {
    ".log", ".txt", ".evtx", ".json", ".csv",
    ".syslog", ".xml", ".gz",
}

# Audit logging
AUDIT_LOG_FILE = LOG_DIR / "audit.log"

# ============================================================
# UI Theme (used by templates)
# ============================================================
THEME = {
    "bg_primary": "#0a0e17",
    "bg_secondary": "#111827",
    "bg_card": "#1a2332",
    "bg_elevated": "#1f2937",
    "accent": "#00d4ff",
    "accent_secondary": "#8b5cf6",
    "success": "#10b981",
    "warning": "#f59e0b",
    "danger": "#ef4444",
    "critical": "#ff1744",
    "text_primary": "#f1f5f9",
    "text_secondary": "#94a3b8",
    "text_muted": "#64748b",
    "border": "#1e293b",
}

# ============================================================
# Severity Levels
# ============================================================
SEVERITY_LEVELS = {
    "critical": {"color": "#ff1744", "weight": 40, "icon": "🔴"},
    "high": {"color": "#ef4444", "weight": 25, "icon": "🟠"},
    "medium": {"color": "#f59e0b", "weight": 15, "icon": "🟡"},
    "low": {"color": "#3b82f6", "weight": 5, "icon": "🔵"},
    "informational": {"color": "#64748b", "weight": 1, "icon": "⚪"},
}

# ============================================================
# MITRE ATT&CK Tactics
# ============================================================
MITRE_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}



