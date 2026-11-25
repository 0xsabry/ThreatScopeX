"""
ThreatScope — Realtime Log Monitoring Daemon
Author: 0xSABRY

Watches live log directories for new/modified files and fires
instant alerts. Pushes alerts via WebSocket to the web UI.
"""

import os
import time
import json
import logging
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Optional, Callable

logger = logging.getLogger("threatscope.realtime")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logger.info("watchdog not installed — realtime monitoring uses polling mode")


class LogFileHandler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    """Handles file system events for log monitoring."""

    SUPPORTED_EXTENSIONS = {".log", ".txt", ".evtx", ".json", ".csv", ".syslog"}

    def __init__(self, callback: Callable, extensions: List[str] = None):
        self.callback = callback
        self.extensions = set(extensions) if extensions else self.SUPPORTED_EXTENSIONS
        self._debounce = {}
        self._debounce_interval = 2  # seconds

    def on_modified(self, event):
        if not event.is_directory:
            self._handle_event(event.src_path, "modified")

    def on_created(self, event):
        if not event.is_directory:
            self._handle_event(event.src_path, "created")

    def _handle_event(self, filepath: str, event_type: str):
        """Process a file event with debouncing."""
        ext = Path(filepath).suffix.lower()
        if ext not in self.extensions:
            return

        now = time.time()
        last = self._debounce.get(filepath, 0)
        if now - last < self._debounce_interval:
            return
        self._debounce[filepath] = now

        try:
            self.callback(filepath, event_type)
        except Exception as e:
            logger.error(f"Error handling {event_type} event for {filepath}: {e}")


class RealtimeMonitor:
    """
    Monitors directories for new and modified log files in real time.
    Can run as a background daemon, triggering analysis and alerts
    for incoming log data.
    """

    def __init__(self, analyze_callback: Optional[Callable] = None,
                 alert_callback: Optional[Callable] = None,
                 poll_interval: int = 5):
        """
        Initialize the realtime monitor.

        Args:
            analyze_callback: Function to call when a new/modified file is detected.
                              Signature: callback(filepath: str, event_type: str)
            alert_callback: Function to call with alert data.
                           Signature: callback(alert: dict)
            poll_interval: Seconds between poll checks (fallback mode).
        """
        self.analyze_callback = analyze_callback
        self.alert_callback = alert_callback
        self.poll_interval = poll_interval
        self.monitored_dirs: List[str] = []
        self.is_running = False
        self._observer = None
        self._thread = None
        self._file_sizes: Dict[str, int] = {}
        self.events_log: List[dict] = []
        self.alerts: List[dict] = []

    def add_directory(self, directory: str):
        """
        Add a directory to monitor.

        Args:
            directory: Path to the directory to watch.
        """
        path = Path(directory)
        if path.exists() and path.is_dir():
            self.monitored_dirs.append(str(path.resolve()))
            logger.info(f"Added monitoring directory: {path}")
        else:
            logger.warning(f"Directory does not exist: {directory}")

    def start(self):
        """Start the realtime monitoring daemon."""
        if self.is_running:
            logger.warning("Monitor is already running")
            return

        self.is_running = True

        if WATCHDOG_AVAILABLE:
            self._start_watchdog()
        else:
            self._start_polling()

        logger.info("Realtime monitor started")

    def stop(self):
        """Stop the monitoring daemon."""
        self.is_running = False
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Realtime monitor stopped")

    def _start_watchdog(self):
        """Start monitoring using watchdog file system events."""
        handler = LogFileHandler(callback=self._on_file_event)
        self._observer = Observer()

        for dir_path in self.monitored_dirs:
            self._observer.schedule(handler, dir_path, recursive=True)

        self._observer.daemon = True
        self._observer.start()

    def _start_polling(self):
        """Start monitoring using file polling (fallback)."""
        # Record initial file sizes
        for dir_path in self.monitored_dirs:
            self._scan_directory(dir_path)

        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def _poll_loop(self):
        """Polling loop for environments without watchdog."""
        while self.is_running:
            try:
                for dir_path in self.monitored_dirs:
                    self._check_for_changes(dir_path)
                time.sleep(self.poll_interval)
            except Exception as e:
                logger.error(f"Polling error: {e}")
                time.sleep(self.poll_interval)

    def _scan_directory(self, directory: str):
        """Record current file sizes in a directory."""
        for path in Path(directory).rglob("*"):
            if path.is_file() and path.suffix.lower() in LogFileHandler.SUPPORTED_EXTENSIONS:
                try:
                    self._file_sizes[str(path)] = path.stat().st_size
                except Exception:
                    pass

    def _check_for_changes(self, directory: str):
        """Check for new or modified files in a directory."""
        for path in Path(directory).rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in LogFileHandler.SUPPORTED_EXTENSIONS:
                continue

            filepath = str(path)
            try:
                current_size = path.stat().st_size
                if filepath not in self._file_sizes:
                    self._file_sizes[filepath] = current_size
                    self._on_file_event(filepath, "created")
                elif current_size != self._file_sizes[filepath]:
                    self._file_sizes[filepath] = current_size
                    self._on_file_event(filepath, "modified")
            except Exception:
                pass

    def _on_file_event(self, filepath: str, event_type: str):
        """Handle a detected file event."""
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "filepath": filepath,
            "event_type": event_type,
            "filename": Path(filepath).name,
        }
        self.events_log.append(event)
        logger.info(f"File {event_type}: {filepath}")

        if self.analyze_callback:
            try:
                self.analyze_callback(filepath, event_type)
            except Exception as e:
                logger.error(f"Analysis callback error: {e}")

    def emit_alert(self, alert: dict):
        """
        Emit an alert from realtime analysis.

        Args:
            alert: Alert dictionary with findings.
        """
        alert["timestamp"] = datetime.now(timezone.utc).isoformat()
        self.alerts.append(alert)

        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

    def get_status(self) -> dict:
        """Get current monitor status."""
        return {
            "is_running": self.is_running,
            "mode": "watchdog" if WATCHDOG_AVAILABLE else "polling",
            "monitored_dirs": self.monitored_dirs,
            "events_detected": len(self.events_log),
            "alerts_fired": len(self.alerts),
            "recent_events": self.events_log[-10:] if self.events_log else [],
        }
