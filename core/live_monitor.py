"""
ThreatScope — Live Log Monitor with Real-Time Detection
Author: 0xSABRY

Tails live log files, parses new lines incrementally, and runs detection
rules in real-time. Emits alerts via callback (compatible with WebSocket
streaming to the web UI).

Features:
  - Tail multiple log files simultaneously (like tail -f)
  - Incremental line parsing and detection
  - Debounced alert emission to prevent alert storms
  - Thread-safe operations with proper cleanup
  - Statistics tracking (events/sec, alerts, critical findings)
"""

import os
import re
import time
import json
import logging
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Optional, Callable, Set
from collections import deque, Counter

logger = logging.getLogger("threatscope.live_monitor")


class LiveLogMonitor:
    """
    Real-time log file tailer with integrated threat detection.

    Monitors specified log files for new content, parses incoming lines,
    runs them through detection rules, and emits alerts via callbacks.
    Designed for WebSocket integration with the web UI.
    """

    MAX_LINE_LENGTH = 10_000  # Truncate excessively long lines
    STATS_WINDOW = 60        # Stats calculation window in seconds

    def __init__(self,
                 alert_callback: Optional[Callable] = None,
                 stats_callback: Optional[Callable] = None,
                 detection_patterns: Optional[Dict] = None):
        """
        Initialize the live log monitor.

        Args:
            alert_callback: Function to call when an alert fires.
                Signature: callback(alert: dict) -> None
            stats_callback: Function to call with periodic stats updates.
                Signature: callback(stats: dict) -> None
            detection_patterns: Custom detection patterns dict (uses BUILTIN_PATTERNS by default).
        """
        self.alert_callback = alert_callback
        self.stats_callback = stats_callback

        # Import detection patterns from analyzer
        if detection_patterns is None:
            from core.analyzer import BUILTIN_PATTERNS
            self.detection_patterns = BUILTIN_PATTERNS
        else:
            self.detection_patterns = detection_patterns

        # Monitored files
        self._monitored_files: Dict[str, dict] = {}  # filepath -> {offset, inode, ...}
        self._file_lock = threading.Lock()

        # State
        self.is_running = False
        self._stop_event = threading.Event()
        self._threads: List[threading.Thread] = []

        # Alerts and stats
        self.alerts: deque = deque(maxlen=1000)  # Rolling window of recent alerts
        self._alert_counter = Counter()
        self._event_timestamps: deque = deque(maxlen=5000)
        self._total_lines = 0
        self._total_alerts = 0
        self._critical_alerts = 0

        # Debouncing: prevent same rule firing too rapidly
        self._alert_debounce: Dict[str, float] = {}
        self._debounce_seconds = 5.0

        # Poll interval
        self.poll_interval = 1.0  # seconds between file checks

    def add_file(self, filepath: str) -> bool:
        """
        Add a file to the live monitoring list.

        Args:
            filepath: Absolute path to the log file to monitor.

        Returns:
            True if the file was added successfully.
        """
        path = Path(filepath)
        if not path.exists():
            logger.warning(f"File not found: {filepath}")
            return False

        if not path.is_file():
            logger.warning(f"Not a file: {filepath}")
            return False

        with self._file_lock:
            if filepath in self._monitored_files:
                logger.info(f"Already monitoring: {filepath}")
                return True

            try:
                stat = path.stat()
                self._monitored_files[filepath] = {
                    "offset": stat.st_size,  # Start from end (tail behavior)
                    "inode": stat.st_ino,
                    "path": path,
                    "name": path.name,
                    "lines_read": 0,
                    "alerts": 0,
                }
                logger.info(f"Added file to live monitor: {filepath} (starting from offset {stat.st_size})")
                return True
            except Exception as e:
                logger.error(f"Error adding file {filepath}: {e}")
                return False

    def remove_file(self, filepath: str):
        """Remove a file from monitoring."""
        with self._file_lock:
            if filepath in self._monitored_files:
                del self._monitored_files[filepath]
                logger.info(f"Removed file from live monitor: {filepath}")

    def add_directory(self, directory: str, extensions: Optional[Set[str]] = None):
        """
        Add all matching log files in a directory.

        Args:
            directory: Directory path to scan.
            extensions: File extensions to include. Defaults to common log extensions.
        """
        if extensions is None:
            extensions = {".log", ".txt", ".syslog", ".json"}

        dir_path = Path(directory)
        if not dir_path.is_dir():
            logger.warning(f"Not a directory: {directory}")
            return

        for path in dir_path.rglob("*"):
            if path.is_file() and path.suffix.lower() in extensions:
                self.add_file(str(path))

    def start(self):
        """Start the live monitoring daemon."""
        if self.is_running:
            logger.warning("Live monitor is already running")
            return

        self.is_running = True
        self._stop_event.clear()

        # Start the main monitoring thread
        monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="live-monitor-main",
            daemon=True,
        )
        monitor_thread.start()
        self._threads.append(monitor_thread)

        # Start the stats emitter thread
        stats_thread = threading.Thread(
            target=self._stats_loop,
            name="live-monitor-stats",
            daemon=True,
        )
        stats_thread.start()
        self._threads.append(stats_thread)

        logger.info("Live log monitor started")

    def stop(self):
        """Stop the live monitoring daemon."""
        self.is_running = False
        self._stop_event.set()

        for thread in self._threads:
            thread.join(timeout=5)
        self._threads.clear()

        logger.info("Live log monitor stopped")

    def _monitor_loop(self):
        """Main monitoring loop — tails all files for new content."""
        while not self._stop_event.is_set():
            try:
                with self._file_lock:
                    files_snapshot = dict(self._monitored_files)

                for filepath, file_info in files_snapshot.items():
                    try:
                        self._check_file(filepath, file_info)
                    except Exception as e:
                        logger.debug(f"Error checking {filepath}: {e}")

                self._stop_event.wait(timeout=self.poll_interval)
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                self._stop_event.wait(timeout=self.poll_interval)

    def _check_file(self, filepath: str, file_info: dict):
        """Check a single file for new content and process new lines."""
        path = Path(filepath)
        if not path.exists():
            return

        try:
            stat = path.stat()
            current_size = stat.st_size
            current_inode = stat.st_ino
        except OSError:
            return

        offset = file_info["offset"]

        # Handle file rotation (inode changed or file got smaller)
        if current_inode != file_info["inode"] or current_size < offset:
            file_info["inode"] = current_inode
            file_info["offset"] = 0
            offset = 0

        if current_size <= offset:
            return  # No new content

        # Read new content
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                f.seek(offset)
                new_content = f.read(current_size - offset)
                file_info["offset"] = f.tell()
        except Exception as e:
            logger.debug(f"Error reading {filepath}: {e}")
            return

        # Process new lines
        for line in new_content.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Truncate excessively long lines
            if len(line) > self.MAX_LINE_LENGTH:
                line = line[:self.MAX_LINE_LENGTH]

            self._total_lines += 1
            file_info["lines_read"] += 1
            self._event_timestamps.append(time.time())

            # Run detection on this line
            self._detect_threats(line, filepath, file_info["lines_read"])

        # Update the shared state
        with self._file_lock:
            if filepath in self._monitored_files:
                self._monitored_files[filepath] = file_info

    def _detect_threats(self, line: str, filepath: str, line_number: int):
        """
        Run the line through all detection patterns.

        Args:
            line: The log line to analyze.
            filepath: Source file path.
            line_number: Line number in the file.
        """
        now = time.time()

        for rule_id, rule in self.detection_patterns.items():
            for pattern in rule["patterns"]:
                try:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Debounce: skip if the same rule fired recently
                        debounce_key = f"{rule_id}:{filepath}"
                        last_fire = self._alert_debounce.get(debounce_key, 0)
                        if now - last_fire < self._debounce_seconds:
                            break

                        self._alert_debounce[debounce_key] = now

                        alert = {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "rule_id": rule_id,
                            "category": rule["category"],
                            "severity": rule["severity"],
                            "description": rule["desc"],
                            "mitre": rule.get("mitre", ""),
                            "source_file": Path(filepath).name,
                            "line_number": line_number,
                            "line_preview": line[:300],
                            "matched_pattern": pattern,
                        }

                        self.alerts.append(alert)
                        self._total_alerts += 1
                        self._alert_counter[rule["severity"]] += 1

                        if rule["severity"] == "critical":
                            self._critical_alerts += 1

                        # Fire callback
                        if self.alert_callback:
                            try:
                                self.alert_callback(alert)
                            except Exception as e:
                                logger.debug(f"Alert callback error: {e}")

                        break  # One match per rule per line
                except re.error:
                    continue

    def _stats_loop(self):
        """Periodically emit statistics."""
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=5)
            if self._stop_event.is_set():
                break

            if self.stats_callback:
                try:
                    stats = self.get_stats()
                    self.stats_callback(stats)
                except Exception as e:
                    logger.debug(f"Stats callback error: {e}")

    def get_stats(self) -> dict:
        """Get current monitoring statistics."""
        now = time.time()

        # Calculate events per second (over last 60s window)
        recent = [t for t in self._event_timestamps if now - t < self.STATS_WINDOW]
        events_per_second = round(len(recent) / max(self.STATS_WINDOW, 1), 2)

        with self._file_lock:
            monitored_count = len(self._monitored_files)
            file_stats = {
                info["name"]: {
                    "lines_read": info["lines_read"],
                    "alerts": info["alerts"],
                }
                for info in self._monitored_files.values()
            }

        return {
            "is_running": self.is_running,
            "monitored_files": monitored_count,
            "total_lines_processed": self._total_lines,
            "total_alerts": self._total_alerts,
            "critical_alerts": self._critical_alerts,
            "events_per_second": events_per_second,
            "alerts_by_severity": dict(self._alert_counter),
            "recent_alerts": list(self.alerts)[-20:],
            "file_stats": file_stats,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def get_recent_alerts(self, limit: int = 50) -> List[dict]:
        """Get the most recent alerts."""
        return list(self.alerts)[-limit:]
