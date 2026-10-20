"""
ThreatScope V2 — Enhanced CLI Interface
Author: 0xSABRY

Powerful command-line interface for headless analysis, automation,
and CI/CD integration.
"""

import sys
import argparse
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from config import VERSION, APP_NAME
from core.analyzer import LogAnalyzer
from core.sigma_sync import SigmaSync
from export.exporters import export_json, export_csv, export_stix


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def enable_utf8_output():
    """
    Force UTF-8 console output so banner/report glyphs don't raise
    UnicodeEncodeError on Windows terminals using a legacy code page.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _utf8_capable() -> bool:
    """Return True when stdout can encode the banner's box-drawing glyphs."""
    enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    if enc in ("utf-8", "utf8", "cp65001"):
        return True
    try:
        "╔═║🛡️".encode(enc or "ascii")
        return True
    except Exception:
        return False


def print_banner():
    if not _utf8_capable():
        print(f"""
\033[36m+==================================================+
|  {APP_NAME} V{VERSION}
|  Advanced DFIR & Threat Detection Platform
|  by 0xSABRY
+==================================================+\033[0m
""")
        return
    print(f"""
\033[36m╔══════════════════════════════════════════════════╗
║  🛡️  {APP_NAME} V{VERSION}                              ║
║  Advanced DFIR & Threat Detection Platform        ║
║  by 0xSABRY                                       ║
╚══════════════════════════════════════════════════╝\033[0m
""")


def cmd_analyze(args):
    """Run analysis on a log file."""
    filepath = Path(args.file)
    if not filepath.exists():
        print(f"\033[91m[ERROR] File not found: {filepath}\033[0m")
        sys.exit(1)

    print(f"\033[36m[*] Loading: {filepath}\033[0m")
    analyzer = LogAnalyzer(str(filepath))
    analyzer.load()

    print(f"\033[36m[*] Analyzing {analyzer.total_lines:,} events...\033[0m")
    results = analyzer.analyze()

    # Print summary
    score = results["threat_score"]
    level = results["threat_level"]
    color = "\033[91m" if score >= 60 else "\033[93m" if score >= 30 else "\033[92m"

    print(f"\n{color}{'=' * 60}")
    print(f"  THREAT SCORE: {score}% — {level}")
    print(f"{'=' * 60}\033[0m")
    print(f"  Total Events:     {results['metadata']['total_events']:,}")
    print(f"  Total Findings:   {results['summary']['total_findings']}")
    print(f"  \033[91mCritical:       {results['summary']['critical']}\033[0m")
    print(f"  \033[93mHigh:           {results['summary']['high']}\033[0m")
    print(f"  Medium:           {results['summary']['medium']}")
    print(f"  Low:              {results['summary']['low']}")
    print(f"  MITRE Techniques: {results['summary']['mitre_techniques']}")
    print(f"  IOCs Extracted:   {results['summary']['total_iocs']}")
    print(f"  Correlations:     {results['summary']['correlations']}")
    print(f"  Behavioral Chains: {results['summary']['behavioral_chains']}")

    # Top findings
    if results["findings"]:
        print(f"\n\033[36m  TOP FINDINGS:\033[0m")
        for f in results["findings"][:15]:
            sev = f.get("severity", "").upper()
            sev_col = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[33m"}.get(sev, "\033[34m")
            print(f"  {sev_col}[{sev}]\033[0m {f.get('title', '')} — {f.get('description', '')}")
            if f.get("mitre"):
                print(f"         MITRE: {f['mitre']}")

    # Export
    if args.output:
        fmt = args.format or "json"
        output_path = args.output
        if fmt == "json":
            export_json(results, output_path)
        elif fmt == "csv":
            export_csv(results, output_path)
        elif fmt == "stix":
            export_stix(results, output_path)
        else:
            export_json(results, output_path)
        print(f"\n\033[92m[✓] Report saved to: {output_path}\033[0m")

    # Full text report
    if args.report:
        print(f"\n{analyzer.generate_report()}")


def cmd_sync(args):
    """Sync Sigma rules from SigmaHQ."""
    print("\033[36m[*] Syncing Sigma rules from SigmaHQ...\033[0m")
    syncer = SigmaSync()
    result = syncer.sync()

    if result.get("errors"):
        print(f"\033[91m[!] Errors: {', '.join(result['errors'])}\033[0m")
    else:
        print(f"\033[92m[✓] Synced {result.get('rules_total', 0)} rules"
              f" ({result.get('rules_added', 0)} new, {result.get('rules_updated', 0)} updated)\033[0m")


def cmd_gui(args):
    """Launch the desktop GUI."""
    from gui import main as gui_main
    gui_main()


def cmd_web(args):
    """Launch the web interface."""
    from app import app
    from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG
    host = args.host or FLASK_HOST
    port = args.port or FLASK_PORT
    app.run(host=host, port=int(port), debug=FLASK_DEBUG)


def main():
    enable_utf8_output()
    print_banner()

    parser = argparse.ArgumentParser(
        prog="threatscope",
        description=f"{APP_NAME} V{VERSION} — Advanced DFIR & Threat Detection",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a log file")
    analyze_parser.add_argument("file", help="Path to log file (.evtx, .log, .json, etc.)")
    analyze_parser.add_argument("-o", "--output", help="Export report to file")
    analyze_parser.add_argument("-f", "--format", choices=["json", "csv", "stix"],
                                default="json", help="Export format (default: json)")
    analyze_parser.add_argument("-r", "--report", action="store_true",
                                help="Print full text report")
    analyze_parser.add_argument("-v", "--verbose", action="store_true",
                                help="Enable verbose logging")

    # Sync command
    subparsers.add_parser("sync", help="Sync Sigma rules from SigmaHQ")

    # GUI command
    subparsers.add_parser("gui", help="Launch desktop GUI (default)")

    # Web command
    web_parser = subparsers.add_parser("web", help="Launch web interface")
    web_parser.add_argument("--host", default="127.0.0.1", help="Host address")
    web_parser.add_argument("--port", default=5000, type=int, help="Port number")

    args = parser.parse_args()

    if args.command == "analyze":
        setup_logging(getattr(args, "verbose", False))
        cmd_analyze(args)
    elif args.command == "sync":
        setup_logging()
        cmd_sync(args)
    elif args.command == "gui":
        cmd_gui(args)
    elif args.command == "web":
        setup_logging()
        cmd_web(args)
    else:
        # Default: launch GUI
        cmd_gui(args)


if __name__ == "__main__":
    main()
