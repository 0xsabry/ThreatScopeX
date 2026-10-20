"""
ThreatScope V3 — Flask Web Application
Author: 0xSABRY

Modern web-based DFIR platform with dark-themed UI,
interactive dashboards, real-time analysis, and live monitoring.
Security-hardened with CSP headers, rate limiting, and audit logging.
"""

import os
import sys
import json
import logging
from pathlib import Path
from datetime import datetime, timezone

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from flask import (
    Flask, render_template, request, jsonify, send_file,
    redirect, url_for, session
)
from werkzeug.utils import secure_filename

from config import (
    VERSION, APP_NAME, FLASK_HOST, FLASK_PORT, FLASK_DEBUG,
    SECRET_KEY, UPLOAD_DIR, EXPORT_DIR, MITRE_TACTICS,
    OPENAI_API_KEY, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY,
    AI_SEND_DATA, LIVE_MONITOR_ALLOWED_ROOTS,
)
from core.analyzer import LogAnalyzer
from core.sigma_engine import SigmaEngine
from core.sigma_sync import SigmaSync
from core.realtime_monitor import RealtimeMonitor
from core.live_monitor import LiveLogMonitor
from core.security import (
    InputValidator, RateLimiter, SecureFileHandler,
    SecurityHeaders, AuditLogger, CSRFProtection,
)
from intel.enrichment import ThreatIntelEnrichment
from intel.apt_mapper import APTMapper, CVEFeed, get_technique_name
from ai.ai_core import NarrativeEngine, AnalystCopilot, TrainingMode
from export.exporters import export_json, export_csv, export_stix, export_pdf, export_docx

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("threatscope")

# Flask app
app = Flask(__name__,
            static_folder="static",
            template_folder="templates")
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500MB max upload
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Only require Secure cookies when the operator terminates TLS; forcing it on
# plain-HTTP localhost would silently drop the session cookie.
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("THREATSCOPE_HTTPS", "false").lower() == "true"

# Ensure directories exist
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
EXPORT_DIR.mkdir(parents=True, exist_ok=True)

# Security components
rate_limiter = RateLimiter(max_requests=120, window_seconds=60)
secure_files = SecureFileHandler(upload_dir=UPLOAD_DIR, export_dir=EXPORT_DIR)
audit_log = AuditLogger()

# Global state
current_analysis = {"results": None, "analyzer": None}
copilot = AnalystCopilot()
training = TrainingMode()
realtime = RealtimeMonitor()
live_monitor = LiveLogMonitor()


# ============================================================
# Security Middleware
# ============================================================
@app.after_request
def apply_security_headers(response):
    """Apply security headers to every response."""
    return SecurityHeaders.apply(response)


@app.before_request
def check_rate_limit():
    """Enforce rate limiting on all API endpoints."""
    if request.path.startswith("/api/"):
        client_ip = request.remote_addr or "unknown"
        allowed, info = rate_limiter.is_allowed(client_ip)
        if not allowed:
            audit_log.log_rate_limit(client_ip, request.path)
            return jsonify({
                "error": "Rate limit exceeded",
                "retry_after": info.get("retry_after", 60),
            }), 429


@app.before_request
def enforce_csrf():
    """
    Require a valid session-bound CSRF token on state-changing API requests.

    The token is delivered to the SPA via a <meta> tag (see base.html) and
    echoed back in the X-CSRF-Token header. Safe methods are exempt.
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    if not request.path.startswith("/api/"):
        return None
    provided = request.headers.get(CSRFProtection.HEADER_NAME)
    if not CSRFProtection.validate(session, provided):
        audit_log.log_security_event(
            request.remote_addr or "", "csrf_rejected", f"path={request.path}"
        )
        return jsonify({"error": "CSRF validation failed"}), 403
    return None


@app.context_processor
def inject_csrf_token():
    """Expose a CSRF token to templates for the client to echo back."""
    return {"csrf_token": CSRFProtection.get_token(session)}

ALLOWED_EXTENSIONS = {".log", ".txt", ".evtx", ".json", ".csv", ".syslog", ".xml"}


def allowed_file(filename):
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


# ============================================================
# Routes
# ============================================================

@app.route("/")
def index():
    """Main dashboard page."""
    return render_template("dashboard.html",
                           version=VERSION,
                           app_name=APP_NAME,
                           results=current_analysis["results"])


@app.route("/analysis")
def analysis_page():
    """Analysis results page."""
    return render_template("analysis.html",
                           version=VERSION,
                           results=current_analysis["results"])


@app.route("/timeline")
def timeline_page():
    """Interactive attack timeline."""
    return render_template("timeline.html",
                           version=VERSION,
                           results=current_analysis["results"])


@app.route("/mitre")
def mitre_page():
    """MITRE ATT&CK coverage heatmap."""
    return render_template("mitre.html",
                           version=VERSION,
                           results=current_analysis["results"],
                           tactics=MITRE_TACTICS)


@app.route("/intel")
def intel_page():
    """Threat intelligence page."""
    return render_template("intel.html",
                           version=VERSION,
                           results=current_analysis["results"])


@app.route("/copilot")
def copilot_page():
    """AI Analyst Copilot chat."""
    return render_template("copilot.html",
                           version=VERSION,
                           results=current_analysis["results"])


@app.route("/rules")
def rules_page():
    """Sigma rules management."""
    sigma = SigmaEngine()
    sigma.load_rules()
    return render_template("rules.html",
                           version=VERSION,
                           stats=sigma.get_stats())


@app.route("/settings")
def settings_page():
    """Configuration settings."""
    api_keys = {
        "openai": bool(OPENAI_API_KEY),
        "virustotal": bool(VIRUSTOTAL_API_KEY),
        "abuseipdb": bool(ABUSEIPDB_API_KEY),
        "otx": bool(OTX_API_KEY),
    }
    return render_template("settings.html", version=VERSION, api_keys=api_keys)


# ============================================================
# API Endpoints
# ============================================================

@app.route("/api/upload", methods=["POST"])
def upload_file():
    """Handle log file upload."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": f"Unsupported file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"}), 400

    client_ip = request.remote_addr or ""
    filename = secure_filename(file.filename)

    # Save through the hardened handler (validates filename + containment).
    ok, result = secure_files.safe_save_upload(file, filename)
    if not ok:
        audit_log.log_upload(client_ip, filename, 0, False)
        return jsonify({"error": result}), 400

    # Verify the content matches the extension (rejects disguised binaries).
    valid, err = InputValidator.validate_file_magic(result, ALLOWED_EXTENSIONS)
    if not valid:
        Path(result).unlink(missing_ok=True)
        audit_log.log_upload(client_ip, filename, 0, False)
        return jsonify({"error": err}), 400

    filepath = Path(result)
    size = filepath.stat().st_size
    audit_log.log_upload(client_ip, filename, size, True)
    return jsonify({
        "status": "success",
        "filename": filename,
        "filepath": str(filepath),
        "size": size,
    })


@app.route("/api/analyze", methods=["POST"])
def run_analysis():
    """Run analysis on uploaded file."""
    data = request.get_json() or {}
    filepath = data.get("filepath", "")

    # Confine analysis to the upload directory (prevents arbitrary file read).
    valid, err = InputValidator.validate_filepath(filepath, UPLOAD_DIR)
    if not valid or not Path(filepath).is_file():
        audit_log.log_security_event(
            request.remote_addr or "", "path_traversal_blocked", f"path={filepath!r}"
        )
        return jsonify({"error": "File not found"}), 400

    try:
        analyzer = LogAnalyzer(filepath)
        analyzer.load()
        results = analyzer.analyze()

        current_analysis["results"] = results
        current_analysis["analyzer"] = analyzer

        # Set copilot context
        copilot.set_context(results)
        training.set_context(results)

        audit_log.log_analysis(request.remote_addr or "", filepath, results["threat_score"])
        return jsonify({
            "status": "success",
            "threat_score": results["threat_score"],
            "threat_level": results["threat_level"],
            "summary": results["summary"],
        })
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/results")
def get_results():
    """Get current analysis results."""
    if current_analysis["results"]:
        return jsonify(current_analysis["results"])
    return jsonify({"error": "No analysis results available"}), 404


@app.route("/api/copilot", methods=["POST"])
def copilot_ask():
    """AI Copilot Q&A endpoint."""
    data = request.get_json() or {}
    question = data.get("question", "")
    mode = data.get("mode", "copilot")  # copilot or training

    if not question:
        return jsonify({"error": "No question provided"}), 400

    if mode == "training":
        response = training.interact(question)
    else:
        response = copilot.ask(question)

    return jsonify({"response": response})


@app.route("/api/narrative", methods=["POST"])
def generate_narrative():
    """Generate AI attack narrative."""
    if not current_analysis["results"]:
        return jsonify({"error": "No analysis results"}), 404

    engine = NarrativeEngine()
    narrative = engine.generate_narrative(current_analysis["results"])
    return jsonify({"narrative": narrative})


@app.route("/api/enrich", methods=["POST"])
def enrich_iocs():
    """Enrich IOCs with threat intelligence."""
    if not current_analysis["results"]:
        return jsonify({"error": "No analysis results"}), 404

    try:
        enricher = ThreatIntelEnrichment()
        iocs = current_analysis["results"].get("iocs", {})

        # Build IOC dict from results
        ioc_sets = {}
        for ioc_type in ["top_ips", "top_domains"]:
            values = iocs.get(ioc_type, [])
            ioc_type_key = "ipv4" if "ip" in ioc_type else "domain"
            if values:
                ioc_sets[ioc_type_key] = set(values[:10])

        for hash_type in ["md5", "sha1", "sha256"]:
            hashes = iocs.get("hashes", {}).get(hash_type, [])
            if hashes:
                ioc_sets[hash_type] = set(hashes[:5])

        results = enricher.enrich_all(ioc_sets)
        return jsonify({
            "status": "success",
            "enrichment": {k: v for k, v in results.items()},
            "summary": enricher.get_summary(),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/apt-map", methods=["POST"])
def apt_mapping():
    """APT group attribution mapping."""
    if not current_analysis["results"]:
        return jsonify({"error": "No analysis results"}), 404

    techniques = list(current_analysis["results"].get("mitre_hits", {}).keys())
    mapper = APTMapper()
    matches = mapper.map_techniques(techniques)
    return jsonify({"matches": matches, "techniques_analyzed": len(techniques)})


@app.route("/api/sigma-sync", methods=["POST"])
def sync_sigma():
    """Sync Sigma rules from SigmaHQ."""
    try:
        syncer = SigmaSync()
        result = syncer.sync()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/export/<format_type>", methods=["POST"])
def export_report(format_type):
    """Export analysis report in specified format."""
    if not current_analysis["results"]:
        return jsonify({"error": "No analysis results"}), 404

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results = current_analysis["results"]

    try:
        if format_type == "json":
            path = export_json(results, str(EXPORT_DIR / f"threatscope_report_{timestamp}.json"))
        elif format_type == "csv":
            path = export_csv(results, str(EXPORT_DIR / f"threatscope_report_{timestamp}.csv"))
        elif format_type == "stix":
            path = export_stix(results, str(EXPORT_DIR / f"threatscope_stix_{timestamp}.json"))
        elif format_type == "pdf":
            path = export_pdf(results, str(EXPORT_DIR / f"threatscope_report_{timestamp}.pdf"))
        elif format_type == "docx":
            path = export_docx(results, str(EXPORT_DIR / f"threatscope_report_{timestamp}.docx"))
        else:
            return jsonify({"error": f"Unknown format: {format_type}"}), 400

        # export_pdf/export_docx may fall back to .txt/.json when optional deps
        # are missing; honour the path they actually returned.
        if not path or not Path(path).is_file():
            audit_log.log_export(request.remote_addr or "", format_type, False)
            return jsonify({"error": "Export failed"}), 500

        audit_log.log_export(request.remote_addr or "", format_type, True)
        return send_file(path, as_attachment=True)
    except Exception as e:
        audit_log.log_export(request.remote_addr or "", format_type, False)
        return jsonify({"error": str(e)}), 500


@app.route("/api/cve/<cve_id>")
def lookup_cve(cve_id):
    """Look up a CVE."""
    feed = CVEFeed()
    result = feed.lookup_cve(cve_id)
    return jsonify(result)


# ============================================================
# Template Filters
# ============================================================

@app.template_filter("technique_name")
def technique_name_filter(technique_id):
    return get_technique_name(technique_id)


@app.template_filter("format_number")
def format_number_filter(value):
    try:
        return f"{int(value):,}"
    except (ValueError, TypeError):
        return value


# ============================================================
# Entry Point
# ============================================================


# ============================================================
# Live Monitor Routes
# ============================================================
@app.route("/live-monitor")
def live_monitor_page():
    """Live log monitoring dashboard."""
    return render_template("live_monitor.html", app_name=APP_NAME, version=VERSION)


@app.route("/api/live/start", methods=["POST"])
def api_live_start():
    """Start live log monitoring."""
    data = request.get_json(force=True, silent=True) or {}
    path = data.get("path", "").strip()

    if not path:
        return jsonify({"error": "Path is required"}), 400

    # Validate path
    path = InputValidator.sanitize_string(path, max_length=1024)

    # Confine monitoring to an allow-list of log roots (prevents arbitrary
    # file read/disclosure through the live alert feed).
    valid, err = InputValidator.validate_path_within_roots(
        path, LIVE_MONITOR_ALLOWED_ROOTS
    )
    if not valid:
        audit_log.log_security_event(
            request.remote_addr or "", "monitor_path_rejected", f"path={path!r}"
        )
        return jsonify({"error": err}), 403

    target = Path(path)
    if target.is_dir():
        live_monitor.add_directory(str(target))
    elif target.is_file():
        live_monitor.add_file(str(target))
    else:
        return jsonify({"error": "Path not found"}), 404

    if not live_monitor.is_running:
        live_monitor.start()

    audit_log.log_security_event(
        request.remote_addr or "", "live_monitor_start", f"path={path}"
    )
    return jsonify({"status": "monitoring", "path": path})


@app.route("/api/live/stop", methods=["POST"])
def api_live_stop():
    """Stop live log monitoring."""
    live_monitor.stop()
    return jsonify({"status": "stopped"})


@app.route("/api/live/status")
def api_live_status():
    """Get live monitor status and recent alerts."""
    return jsonify(live_monitor.get_stats())


# ============================================================
# Main Entry Point
# ============================================================

if __name__ == "__main__":
    banner = (
        "\n"
        "    +===============================================+\n"
        f"    |  [*] ThreatScope V{VERSION}                       |\n"
        "    |  Advanced DFIR & Threat Detection Platform    |\n"
        "    |  SECURITY HARDENED                            |\n"
        "    |  by 0xSABRY                                  |\n"
        "    +===============================================+\n"
        f"    |  Dashboard: http://{FLASK_HOST}:{FLASK_PORT}            |\n"
        "    |  Live Monitor: /live-monitor                  |\n"
        "    +===============================================+\n"
    )
    print(banner)
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
