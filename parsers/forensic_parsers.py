"""
ThreatScope V3.5 — Deep Forensics Artifact Parsers
Author: 0xSABRY

Windows forensic artifact parsers for deep-dive DFIR investigations:
  - Prefetch: Execution evidence with run counts and timestamps
  - $MFT / UsnJrnl: File system timeline and timestomping detection
  - Shimcache (AppCompatCache): Historical execution evidence
  - Amcache: SHA1 hashes and install metadata for binaries

All parsers produce normalized ThreatFinding-compatible output
for seamless integration with core/analyzer.py.
"""

import re
import os
import csv
import json
import struct
import logging
import hashlib
from io import BytesIO, StringIO
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import (
    Dict, List, Optional, Tuple, Any, Generator, BinaryIO,
)

logger = logging.getLogger("threatscope.parsers.forensic")


# ============================================================
# Shared: ThreatFinding Format
# ============================================================

def _make_finding(
    title: str,
    description: str,
    severity: str = "medium",
    source: str = "forensic_artifact",
    artifact_type: str = "",
    timestamp: str = "",
    mitre: str = "",
    weight: int = 15,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Create a ThreatFinding-compatible dictionary.

    Args:
        title: Finding title.
        description: Detailed description.
        severity: One of critical, high, medium, low, informational.
        source: Source module identifier.
        artifact_type: Type of forensic artifact.
        timestamp: ISO 8601 timestamp.
        mitre: MITRE ATT&CK technique ID.
        weight: Finding weight for scoring.
        metadata: Additional metadata.

    Returns:
        Finding dictionary compatible with core/analyzer.py.
    """
    return {
        "rule_id": f"forensic_{artifact_type}",
        "rule_type": "forensic",
        "title": title,
        "description": description,
        "severity": severity,
        "weight": weight,
        "mitre": mitre,
        "timestamp": timestamp,
        "category": f"Forensic: {artifact_type}",
        "matched_pattern": "",
        "raw": description[:500],
        "line_number": 0,
        "artifact_type": artifact_type,
        "metadata": metadata or {},
    }


# ============================================================
# Prefetch Parser
# ============================================================

class PrefetchParser:
    """
    Parse Windows Prefetch files (.pf) to extract execution evidence.

    Extracts:
      - Executable name and path
      - Run count (how many times executed)
      - Last execution timestamp(s)
      - Referenced DLLs and files (loaded modules)
      - Volume information

    Supports Prefetch formats:
      - Windows XP/2003 (v17)
      - Windows Vista/7 (v23)
      - Windows 8/8.1 (v26)
      - Windows 10/11 (v30, compressed MAM format)
    """

    # Prefetch file signature
    PREFETCH_SIGNATURE = b"SCCA"

    # Known suspicious executables in prefetch
    SUSPICIOUS_PREFETCH = {
        "mimikatz.exe", "psexec.exe", "psexesvc.exe", "procdump.exe",
        "rubeus.exe", "sharphound.exe", "bloodhound.exe", "lazagne.exe",
        "powershell_ise.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "certutil.exe", "bitsadmin.exe", "regsvr32.exe", "rundll32.exe",
        "rar.exe", "7z.exe", "winrar.exe", "net.exe", "net1.exe",
        "nltest.exe", "dsquery.exe", "csvde.exe", "ldifde.exe",
        "adexplorer.exe", "nmap.exe", "nc.exe", "ncat.exe",
        "rclone.exe", "megasync.exe", "tor.exe", "wce.exe",
    }

    def parse(self, filepath: str) -> Dict[str, Any]:
        """
        Parse a single Prefetch file.

        Args:
            filepath: Path to the .pf prefetch file.

        Returns:
            Dictionary with parsed prefetch data.
        """
        result: Dict[str, Any] = {
            "executable": "",
            "run_count": 0,
            "last_run_times": [],
            "referenced_files": [],
            "volume_info": [],
            "file_size": 0,
            "prefetch_hash": "",
            "version": 0,
            "source_file": filepath,
        }

        try:
            file_size = os.path.getsize(filepath)
            result["file_size"] = file_size

            with open(filepath, "rb") as f:
                data = f.read()

            # Check for compressed MAM format (Windows 10+)
            if data[:4] == b"MAM\x04":
                data = self._decompress_mam(data)
                if not data:
                    logger.warning(f"Failed to decompress MAM prefetch: {filepath}")
                    return result

            # Validate signature
            if len(data) < 84:
                return result

            # Parse header
            version = struct.unpack_from("<I", data, 0)[0]
            result["version"] = version

            # Signature check (at offset 4)
            sig = data[4:8]
            if sig != self.PREFETCH_SIGNATURE:
                logger.debug(f"Invalid prefetch signature in {filepath}")
                return result

            # File size from header
            header_size = struct.unpack_from("<I", data, 12)[0]

            # Executable name (60 characters at offset 16, UTF-16LE)
            exe_name_raw = data[16:76]
            try:
                exe_name = exe_name_raw.decode("utf-16-le").rstrip("\x00")
                result["executable"] = exe_name
            except UnicodeDecodeError:
                result["executable"] = filepath.split(os.sep)[-1].replace(".pf", "")

            # Prefetch hash (offset 76, 4 bytes)
            pf_hash = struct.unpack_from("<I", data, 76)[0]
            result["prefetch_hash"] = f"0x{pf_hash:08X}"

            # Version-specific parsing
            if version == 17:  # XP/2003
                result["run_count"] = struct.unpack_from("<I", data, 144)[0]
                last_run = self._parse_filetime(data, 120)
                if last_run:
                    result["last_run_times"].append(last_run)

            elif version == 23:  # Vista/7
                result["run_count"] = struct.unpack_from("<I", data, 152)[0]
                last_run = self._parse_filetime(data, 128)
                if last_run:
                    result["last_run_times"].append(last_run)

            elif version == 26:  # Windows 8/8.1
                result["run_count"] = struct.unpack_from("<I", data, 208)[0]
                # 8 last run times
                for i in range(8):
                    ts = self._parse_filetime(data, 128 + (i * 8))
                    if ts:
                        result["last_run_times"].append(ts)

            elif version == 30:  # Windows 10/11
                result["run_count"] = struct.unpack_from("<I", data, 208)[0]
                for i in range(8):
                    ts = self._parse_filetime(data, 128 + (i * 8))
                    if ts:
                        result["last_run_times"].append(ts)

            # Parse file references (simplified — get filenames from string table)
            result["referenced_files"] = self._extract_file_references(data, version)

        except Exception as e:
            logger.error(f"Prefetch parse error for {filepath}: {e}")

        return result

    def parse_directory(self, prefetch_dir: str) -> List[Dict[str, Any]]:
        """
        Parse all prefetch files in a directory.

        Args:
            prefetch_dir: Path to the Prefetch directory (typically C:\\Windows\\Prefetch).

        Returns:
            List of parsed prefetch results.
        """
        results: List[Dict[str, Any]] = []
        pf_path = Path(prefetch_dir)

        if not pf_path.is_dir():
            logger.error(f"Prefetch directory not found: {prefetch_dir}")
            return results

        for pf_file in sorted(pf_path.glob("*.pf")):
            result = self.parse(str(pf_file))
            if result["executable"]:
                results.append(result)

        logger.info(f"Parsed {len(results)} prefetch files from {prefetch_dir}")
        return results

    def get_findings(self, prefetch_dir: str) -> List[Dict[str, Any]]:
        """
        Parse prefetch directory and return ThreatFinding-compatible results.

        Args:
            prefetch_dir: Path to the Prefetch directory.

        Returns:
            List of finding dictionaries for suspicious prefetch entries.
        """
        findings: List[Dict[str, Any]] = []
        entries = self.parse_directory(prefetch_dir)

        for entry in entries:
            exe_lower = entry["executable"].lower()

            if exe_lower in self.SUSPICIOUS_PREFETCH:
                last_run = entry["last_run_times"][0] if entry["last_run_times"] else ""
                findings.append(_make_finding(
                    title=f"Suspicious Tool Execution: {entry['executable']}",
                    description=(
                        f"Prefetch evidence shows '{entry['executable']}' was executed "
                        f"{entry['run_count']} time(s). Last run: {last_run}. "
                        f"Hash: {entry['prefetch_hash']}."
                    ),
                    severity="high",
                    artifact_type="prefetch",
                    timestamp=last_run,
                    mitre="T1059",
                    weight=25,
                    metadata=entry,
                ))

            # Flag high run counts for known attack tools
            if entry["run_count"] > 50 and exe_lower in self.SUSPICIOUS_PREFETCH:
                findings.append(_make_finding(
                    title=f"Repeated Execution: {entry['executable']} ({entry['run_count']}x)",
                    description=(
                        f"'{entry['executable']}' has been executed {entry['run_count']} times, "
                        f"indicating persistent or automated use."
                    ),
                    severity="critical",
                    artifact_type="prefetch",
                    mitre="T1059",
                    weight=35,
                    metadata=entry,
                ))

        return findings

    @staticmethod
    def _parse_filetime(data: bytes, offset: int) -> str:
        """Parse a Windows FILETIME (100-ns intervals since 1601-01-01)."""
        try:
            if offset + 8 > len(data):
                return ""
            ft = struct.unpack_from("<Q", data, offset)[0]
            if ft == 0:
                return ""
            # Convert FILETIME to datetime
            epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
            dt = epoch + timedelta(microseconds=ft // 10)
            return dt.isoformat()
        except (struct.error, OverflowError, OSError):
            return ""

    @staticmethod
    def _decompress_mam(data: bytes) -> Optional[bytes]:
        """
        Attempt to decompress MAM-compressed prefetch data.

        Output is capped to avoid decompression bombs (a small crafted payload
        expanding to gigabytes and exhausting memory).
        """
        max_output = 64 * 1024 * 1024
        try:
            import lznt1  # type: ignore
            out = lznt1.decompress(data[8:])
            if isinstance(out, (bytes, bytearray)) and len(out) > max_output:
                logger.warning("MAM (lznt1) output exceeds cap; truncating")
                return bytes(out[:max_output])
            return out
        except ImportError:
            pass
        except Exception:
            pass
        # Fallback: zlib with a hard output cap
        try:
            import zlib
            dobj = zlib.decompressobj()
            out = dobj.decompress(data[8:], max_output)
            if out:
                return out
        except Exception:
            pass
        return None

    @staticmethod
    def _extract_file_references(data: bytes, version: int) -> List[str]:
        """Extract referenced file paths from the prefetch string table."""
        refs: List[str] = []
        try:
            # Find strings section — look for null-terminated UTF-16 strings
            # This is a simplified approach; full parsing requires version-specific offsets
            text = data.decode("utf-16-le", errors="replace")
            for match in re.finditer(r'[A-Z]:\\[^\x00]{5,200}', text):
                path = match.group(0).strip()
                if path and len(path) < 260:
                    refs.append(path)
        except Exception:
            pass
        return refs[:200]  # Limit to 200 references


# ============================================================
# MFT / UsnJrnl Parser
# ============================================================

class MFTParser:
    """
    Parse $MFT and $UsnJrnl artifacts for file system timeline
    and timestomping detection.

    Supports:
      - CSV exports from tools like MFTECmd, analyzeMFT
      - Raw binary MFT parsing (simplified for common use cases)
      - UsnJrnl CSV/JSON exports

    Detects timestomping by comparing $STANDARD_INFORMATION
    and $FILE_NAME timestamps — a delta > threshold indicates
    potential manipulation.
    """

    # Timestomping threshold (seconds)
    TIMESTOMP_THRESHOLD_SECONDS = 3600  # 1 hour delta = suspicious

    # Suspicious file extensions
    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".hta", ".scr", ".pif", ".wsf", ".lnk", ".iso", ".img",
    }

    def parse_csv(self, filepath: str) -> Generator[Dict[str, Any], None, None]:
        """
        Parse an MFT CSV export (from MFTECmd, analyzeMFT, etc.).

        Yields normalized MFT entries as dictionaries. Uses a generator
        to avoid loading entire MFT into memory.

        Args:
            filepath: Path to the MFT CSV file.

        Yields:
            Dictionary for each MFT record.
        """
        try:
            with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    entry = self._normalize_mft_row(row)
                    if entry:
                        yield entry
        except Exception as e:
            logger.error(f"MFT CSV parse error: {e}")

    def parse_usnjrnl_csv(self, filepath: str) -> Generator[Dict[str, Any], None, None]:
        """
        Parse a UsnJrnl CSV export.

        Args:
            filepath: Path to the UsnJrnl CSV file.

        Yields:
            Dictionary for each USN record.
        """
        try:
            with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    yield {
                        "filename": row.get("FileName", row.get("Name", "")),
                        "timestamp": row.get("Timestamp", row.get("UpdateTimestamp", "")),
                        "reason": row.get("UpdateReasons", row.get("Reason", "")),
                        "parent_path": row.get("ParentPath", ""),
                        "entry_number": row.get("EntryNumber", row.get("MFTEntryNumber", "")),
                        "usn": row.get("USN", ""),
                        "source": "usnjrnl",
                    }
        except Exception as e:
            logger.error(f"UsnJrnl CSV parse error: {e}")

    def detect_timestomping(
        self, filepath: str, threshold_seconds: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Detect timestomping by comparing $STANDARD_INFORMATION and
        $FILE_NAME timestamps from MFT CSV data.

        Args:
            filepath: Path to MFT CSV file.
            threshold_seconds: Override for timestomping detection threshold.

        Returns:
            List of timestomping indicators.
        """
        if threshold_seconds <= 0:
            threshold_seconds = self.TIMESTOMP_THRESHOLD_SECONDS

        indicators: List[Dict[str, Any]] = []

        for entry in self.parse_csv(filepath):
            si_created = entry.get("si_created", "")
            fn_created = entry.get("fn_created", "")

            if not si_created or not fn_created:
                continue

            try:
                si_dt = self._parse_timestamp(si_created)
                fn_dt = self._parse_timestamp(fn_created)

                if si_dt and fn_dt:
                    delta = abs((si_dt - fn_dt).total_seconds())
                    if delta > threshold_seconds:
                        indicators.append({
                            "filename": entry.get("filename", ""),
                            "full_path": entry.get("full_path", ""),
                            "si_created": si_created,
                            "fn_created": fn_created,
                            "delta_seconds": int(delta),
                            "delta_human": self._humanize_delta(delta),
                            "entry_number": entry.get("entry_number", ""),
                        })
            except Exception:
                continue

        logger.info(f"Timestomping detection: {len(indicators)} suspicious entries found")
        return indicators

    def get_findings(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Parse MFT data and return ThreatFinding-compatible results.

        Args:
            filepath: Path to MFT CSV file.

        Returns:
            List of finding dictionaries.
        """
        findings: List[Dict[str, Any]] = []

        # Detect timestomping
        stomped = self.detect_timestomping(filepath)
        for entry in stomped[:50]:  # Limit findings
            findings.append(_make_finding(
                title=f"Timestomping Detected: {entry['filename']}",
                description=(
                    f"File '{entry['full_path']}' shows {entry['delta_human']} "
                    f"delta between $SI ({entry['si_created']}) and "
                    f"$FN ({entry['fn_created']}) timestamps — probable timestomping."
                ),
                severity="high",
                artifact_type="mft_timestomp",
                timestamp=entry["si_created"],
                mitre="T1070.006",
                weight=30,
                metadata=entry,
            ))

        # Detect suspicious file creations
        for entry in self.parse_csv(filepath):
            ext = Path(entry.get("filename", "")).suffix.lower()
            if ext in self.SUSPICIOUS_EXTENSIONS:
                parent = entry.get("parent_path", "").lower()
                if any(d in parent for d in [
                    "\\temp\\", "\\tmp\\", "\\appdata\\", "\\programdata\\",
                    "\\public\\", "\\recycler\\", "\\perflogs\\",
                ]):
                    findings.append(_make_finding(
                        title=f"Suspicious File in Temp: {entry['filename']}",
                        description=(
                            f"Executable file '{entry['filename']}' found in "
                            f"suspicious location: {entry.get('full_path', parent)}"
                        ),
                        severity="medium",
                        artifact_type="mft_suspicious_file",
                        timestamp=entry.get("si_created", ""),
                        mitre="T1036",
                        weight=15,
                        metadata=entry,
                    ))

            if len(findings) > 200:
                break

        return findings

    def _normalize_mft_row(self, row: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Normalize an MFT CSV row to a standard format."""
        filename = row.get("FileName", row.get("Filename", row.get("Name", "")))
        if not filename:
            return None

        return {
            "filename": filename,
            "full_path": row.get("FullPath", row.get("FilePath", "")),
            "entry_number": row.get("EntryNumber", row.get("RecordNumber", "")),
            "parent_entry": row.get("ParentEntryNumber", row.get("ParentRecordNumber", "")),
            "parent_path": row.get("ParentPath", ""),
            "si_created": row.get("Created0x10", row.get("SI_CTime", row.get("SI_Created", ""))),
            "si_modified": row.get("LastModified0x10", row.get("SI_MTime", "")),
            "si_accessed": row.get("LastAccess0x10", row.get("SI_ATime", "")),
            "fn_created": row.get("Created0x30", row.get("FN_CTime", row.get("FN_Created", ""))),
            "fn_modified": row.get("LastModified0x30", row.get("FN_MTime", "")),
            "in_use": row.get("InUse", "True"),
            "is_directory": row.get("IsDirectory", "False"),
            "file_size": row.get("FileSize", row.get("LogicalSize", "0")),
            "source": "mft",
        }

    @staticmethod
    def _parse_timestamp(ts_str) -> Optional[datetime]:
        """
        Parse various timestamp formats to a naive ``datetime``.

        Handles ISO-8601 (including ``Z`` and timezone offsets) plus the
        formats emitted by common MFT/artifact tools. Fractional seconds with
        more than 6 digits (e.g. Windows 7-digit FILETIME precision) are
        truncated so parsing does not fail.
        """
        if not ts_str:
            return None
        if isinstance(ts_str, datetime):
            return ts_str.replace(tzinfo=None) if ts_str.tzinfo else ts_str

        s = str(ts_str).strip()
        if not s:
            return None

        norm = s.replace("Z", "+00:00").replace("z", "+00:00")
        norm = re.sub(r"(\.\d{6})\d+", r"\1", norm)
        try:
            dt = datetime.fromisoformat(norm)
            return dt.replace(tzinfo=None) if dt.tzinfo else dt
        except ValueError:
            pass

        for fmt in [
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
            "%m/%d/%Y %I:%M:%S %p",
        ]:
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
        return None

    @staticmethod
    def _humanize_delta(seconds: float) -> str:
        """Convert seconds to human-readable duration."""
        if seconds < 60:
            return f"{int(seconds)}s"
        if seconds < 3600:
            return f"{int(seconds // 60)}m {int(seconds % 60)}s"
        if seconds < 86400:
            return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60)}m"
        return f"{int(seconds // 86400)}d {int((seconds % 86400) // 3600)}h"


# ============================================================
# Shimcache (AppCompatCache) Parser
# ============================================================

class ShimcacheParser:
    """
    Parse Shimcache / AppCompatCache data for historical execution evidence.

    Shimcache records programs that have been executed or accessed, stored
    in the Windows Registry under:
    HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache

    Supports:
      - CSV exports from ShimcacheParser, AppCompatCacheParser
      - REG export text files
      - JSON exports
    """

    SUSPICIOUS_PATHS = {
        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
        "\\programdata\\", "\\public\\", "\\recycler\\",
        "\\perflogs\\", "\\users\\public\\",
    }

    def parse_csv(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Parse a Shimcache CSV export.

        Args:
            filepath: Path to the CSV file.

        Returns:
            List of shimcache entry dictionaries.
        """
        entries: List[Dict[str, Any]] = []

        try:
            with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    entry = {
                        "path": row.get("Path", row.get("FilePath", row.get("ControlSet", ""))),
                        "last_modified": row.get("LastModified", row.get("LastModifiedTime", "")),
                        "exec_flag": row.get("Executed", row.get("ExecFlag", "")),
                        "entry_position": row.get("Order", row.get("EntryPosition", "")),
                        "file_size": row.get("FileSize", ""),
                        "source": "shimcache",
                    }
                    if entry["path"]:
                        entries.append(entry)
        except Exception as e:
            logger.error(f"Shimcache CSV parse error: {e}")

        logger.info(f"Parsed {len(entries)} shimcache entries from {filepath}")
        return entries

    def get_findings(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Parse shimcache data and return ThreatFinding-compatible results.

        Args:
            filepath: Path to shimcache CSV.

        Returns:
            List of finding dictionaries for suspicious shimcache entries.
        """
        findings: List[Dict[str, Any]] = []
        entries = self.parse_csv(filepath)

        for entry in entries:
            path_lower = entry["path"].lower()
            basename = path_lower.split("\\")[-1] if "\\" in path_lower else path_lower

            # Check for suspicious tool execution
            if basename in PrefetchParser.SUSPICIOUS_PREFETCH:
                findings.append(_make_finding(
                    title=f"Shimcache: Suspicious Tool — {basename}",
                    description=(
                        f"Shimcache records execution of '{entry['path']}'. "
                        f"Last modified: {entry['last_modified']}. "
                        f"Exec flag: {entry['exec_flag']}."
                    ),
                    severity="high",
                    artifact_type="shimcache",
                    timestamp=entry["last_modified"],
                    mitre="T1059",
                    weight=25,
                    metadata=entry,
                ))

            # Check for executables in suspicious paths
            if any(sp in path_lower for sp in self.SUSPICIOUS_PATHS):
                ext = Path(path_lower).suffix
                if ext in MFTParser.SUSPICIOUS_EXTENSIONS:
                    findings.append(_make_finding(
                        title=f"Shimcache: Exe in Temp — {basename}",
                        description=(
                            f"Executable '{basename}' found in suspicious path via Shimcache: "
                            f"{entry['path']}"
                        ),
                        severity="medium",
                        artifact_type="shimcache",
                        timestamp=entry["last_modified"],
                        mitre="T1036",
                        weight=15,
                        metadata=entry,
                    ))

        return findings


# ============================================================
# Amcache Parser
# ============================================================

class AmcacheParser:
    """
    Parse Amcache.hve artifacts for execution evidence with SHA1 hashes.

    Amcache records information about programs that have been installed
    or executed, stored in C:\\Windows\\AppCompat\\Programs\\Amcache.hve.

    Supports:
      - CSV exports from AmcacheParser, RegRipper
      - JSON exports
    """

    def parse_csv(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Parse an Amcache CSV export.

        Args:
            filepath: Path to the CSV file.

        Returns:
            List of amcache entry dictionaries.
        """
        entries: List[Dict[str, Any]] = []

        try:
            with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    entry = {
                        "path": row.get("FullPath", row.get("Path", row.get("FilePath", ""))),
                        "sha1": row.get("SHA1", row.get("FileId", "")),
                        "name": row.get("FileName", row.get("Name", "")),
                        "publisher": row.get("Publisher", row.get("CompanyName", "")),
                        "version": row.get("FileVersion", row.get("ProductVersion", "")),
                        "file_size": row.get("Size", row.get("FileSize", "")),
                        "link_date": row.get("LinkDate", row.get("CompileTime", "")),
                        "last_modified": row.get("LastModified", row.get("FileKeyLastWriteTimestamp", "")),
                        "product_name": row.get("ProductName", ""),
                        "language": row.get("Language", ""),
                        "pe_header_hash": row.get("PeHeaderHash", ""),
                        "source": "amcache",
                    }

                    # Clean SHA1 (sometimes prefixed with "0000")
                    if entry["sha1"] and entry["sha1"].startswith("0000"):
                        entry["sha1"] = entry["sha1"][4:]

                    if entry["path"] or entry["name"]:
                        entries.append(entry)
        except Exception as e:
            logger.error(f"Amcache CSV parse error: {e}")

        logger.info(f"Parsed {len(entries)} amcache entries from {filepath}")
        return entries

    def get_findings(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Parse amcache and return ThreatFinding-compatible results.

        Args:
            filepath: Path to amcache CSV.

        Returns:
            List of finding dictionaries.
        """
        findings: List[Dict[str, Any]] = []
        entries = self.parse_csv(filepath)

        for entry in entries:
            name = (entry.get("name") or entry.get("path", "").split("\\")[-1]).lower()

            if name in PrefetchParser.SUSPICIOUS_PREFETCH:
                findings.append(_make_finding(
                    title=f"Amcache: Suspicious Binary — {name}",
                    description=(
                        f"Amcache records installation/execution of '{entry.get('path', name)}'. "
                        f"SHA1: {entry.get('sha1', 'N/A')}. "
                        f"Publisher: {entry.get('publisher', 'Unknown')}. "
                        f"Version: {entry.get('version', 'Unknown')}."
                    ),
                    severity="high",
                    artifact_type="amcache",
                    timestamp=entry.get("last_modified", ""),
                    mitre="T1059",
                    weight=25,
                    metadata=entry,
                ))

            # Unsigned executables (no publisher)
            if not entry.get("publisher") and entry.get("path"):
                path_lower = entry["path"].lower()
                if any(sp in path_lower for sp in ShimcacheParser.SUSPICIOUS_PATHS):
                    findings.append(_make_finding(
                        title=f"Amcache: Unsigned Exe in Temp — {name}",
                        description=(
                            f"Unsigned executable found in temp path via Amcache: "
                            f"{entry['path']}. SHA1: {entry.get('sha1', 'N/A')}."
                        ),
                        severity="medium",
                        artifact_type="amcache",
                        timestamp=entry.get("last_modified", ""),
                        mitre="T1036",
                        weight=20,
                        metadata=entry,
                    ))

        return findings

    def get_hashes(self, filepath: str) -> Dict[str, str]:
        """
        Extract all SHA1 hashes from Amcache entries for bulk lookup.

        Args:
            filepath: Path to amcache CSV.

        Returns:
            Dictionary mapping SHA1 hash -> executable name/path.
        """
        hashes: Dict[str, str] = {}
        for entry in self.parse_csv(filepath):
            sha1 = entry.get("sha1", "")
            name = entry.get("name") or entry.get("path", "")
            if sha1 and len(sha1) == 40:
                hashes[sha1] = name
        return hashes


# ============================================================
# Unified Forensic Artifact Scanner
# ============================================================

class ForensicScanner:
    """
    Unified interface for scanning forensic artifacts and producing
    ThreatFinding-compatible results for the main analyzer.

    Example:
        >>> scanner = ForensicScanner()
        >>> findings = scanner.scan_prefetch("C:/Windows/Prefetch")
        >>> findings += scanner.scan_mft("mft_export.csv")
        >>> findings += scanner.scan_shimcache("shimcache.csv")
        >>> findings += scanner.scan_amcache("amcache.csv")
    """

    def __init__(self) -> None:
        self.prefetch_parser = PrefetchParser()
        self.mft_parser = MFTParser()
        self.shimcache_parser = ShimcacheParser()
        self.amcache_parser = AmcacheParser()
        self._all_findings: List[Dict[str, Any]] = []

    def scan_prefetch(self, prefetch_dir: str) -> List[Dict[str, Any]]:
        """Scan prefetch directory for execution evidence."""
        findings = self.prefetch_parser.get_findings(prefetch_dir)
        self._all_findings.extend(findings)
        return findings

    def scan_mft(self, mft_csv: str) -> List[Dict[str, Any]]:
        """Scan MFT CSV export for timestomping and suspicious files."""
        findings = self.mft_parser.get_findings(mft_csv)
        self._all_findings.extend(findings)
        return findings

    def scan_shimcache(self, shimcache_csv: str) -> List[Dict[str, Any]]:
        """Scan shimcache CSV for execution evidence."""
        findings = self.shimcache_parser.get_findings(shimcache_csv)
        self._all_findings.extend(findings)
        return findings

    def scan_amcache(self, amcache_csv: str) -> List[Dict[str, Any]]:
        """Scan amcache CSV for execution evidence and hashes."""
        findings = self.amcache_parser.get_findings(amcache_csv)
        self._all_findings.extend(findings)
        return findings

    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Get all accumulated findings from all parsers."""
        return self._all_findings

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of forensic scanning results."""
        by_type = {}
        for f in self._all_findings:
            atype = f.get("artifact_type", "unknown")
            by_type[atype] = by_type.get(atype, 0) + 1

        return {
            "total_findings": len(self._all_findings),
            "by_artifact_type": by_type,
            "critical": len([f for f in self._all_findings if f.get("severity") == "critical"]),
            "high": len([f for f in self._all_findings if f.get("severity") == "high"]),
            "medium": len([f for f in self._all_findings if f.get("severity") == "medium"]),
        }
