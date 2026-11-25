"""
ThreatScope — Causal Graph & Process Lineage Engine
Author: 0xSABRY

Constructs directional process graphs from Sysmon, Windows Security,
and Linux auditd logs. Maps PPID→PID→Child relationships with network
connections and file modifications. Provides automated Root Cause
Analysis (RCA) backtracking and D3.js/Cytoscape.js-compatible export.

Uses networkx when available, falls back to pure-Python dict graphs.
"""

import json
import logging
import hashlib
import re
from datetime import datetime
from collections import defaultdict
from typing import (
    Dict, List, Optional, Set, Tuple, Any, Generator, NamedTuple,
)

logger = logging.getLogger("threatscope.graph_engine")

# Optional: networkx for advanced graph operations
try:
    import networkx as nx
    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False
    logger.debug("networkx not installed — using pure-Python graph backend")


# ============================================================
# Data Models
# ============================================================

class ProcessNode:
    """
    Represents a single process in the lineage graph.

    Attributes:
        pid: Process ID.
        ppid: Parent Process ID.
        name: Process name / executable.
        cmdline: Full command line.
        user: User who executed the process.
        timestamp: Execution timestamp (ISO 8601).
        hostname: Source hostname.
        event_id: Source event ID (e.g., Sysmon 1, Security 4688).
        integrity_level: Windows integrity level.
        sha256: Binary hash if available.
    """

    __slots__ = (
        "pid", "ppid", "name", "cmdline", "user", "timestamp",
        "hostname", "event_id", "integrity_level", "sha256",
        "network_connections", "file_operations", "children",
        "is_suspicious", "tags", "raw_event",
    )

    def __init__(
        self,
        pid: str,
        ppid: str = "",
        name: str = "",
        cmdline: str = "",
        user: str = "",
        timestamp: str = "",
        hostname: str = "",
        event_id: str = "",
        integrity_level: str = "",
        sha256: str = "",
        raw_event: Optional[dict] = None,
    ) -> None:
        self.pid = str(pid)
        self.ppid = str(ppid)
        self.name = name
        self.cmdline = cmdline
        self.user = user
        self.timestamp = timestamp
        self.hostname = hostname
        self.event_id = event_id
        self.integrity_level = integrity_level
        self.sha256 = sha256
        self.network_connections: List[Dict[str, str]] = []
        self.file_operations: List[Dict[str, str]] = []
        self.children: List[str] = []
        self.is_suspicious = False
        self.tags: List[str] = []
        self.raw_event = raw_event

    @property
    def node_id(self) -> str:
        """Unique node identifier: hostname:pid:timestamp."""
        ts_hash = hashlib.md5(self.timestamp.encode()).hexdigest()[:8] if self.timestamp else "0"
        return f"{self.hostname}:{self.pid}:{ts_hash}"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON export."""
        return {
            "id": self.node_id,
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "cmdline": self.cmdline,
            "user": self.user,
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "event_id": self.event_id,
            "integrity_level": self.integrity_level,
            "sha256": self.sha256,
            "network_connections": self.network_connections,
            "file_operations": self.file_operations,
            "children": self.children,
            "is_suspicious": self.is_suspicious,
            "tags": self.tags,
        }


class NetworkConnection:
    """Represents a network connection made by a process."""

    __slots__ = (
        "pid", "src_ip", "src_port", "dst_ip", "dst_port",
        "protocol", "timestamp", "initiated",
    )

    def __init__(
        self,
        pid: str,
        src_ip: str = "",
        src_port: str = "",
        dst_ip: str = "",
        dst_port: str = "",
        protocol: str = "tcp",
        timestamp: str = "",
        initiated: bool = True,
    ) -> None:
        self.pid = str(pid)
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.timestamp = timestamp
        self.initiated = initiated

    def to_dict(self) -> Dict[str, str]:
        """Serialize to dictionary."""
        return {
            "pid": self.pid,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "timestamp": self.timestamp,
            "initiated": str(self.initiated),
        }


class FileOperation:
    """Represents a file operation performed by a process."""

    __slots__ = (
        "pid", "filepath", "operation", "timestamp", "target_filename",
    )

    def __init__(
        self,
        pid: str,
        filepath: str = "",
        operation: str = "create",
        timestamp: str = "",
        target_filename: str = "",
    ) -> None:
        self.pid = str(pid)
        self.filepath = filepath
        self.operation = operation  # create, modify, delete, rename
        self.timestamp = timestamp
        self.target_filename = target_filename

    def to_dict(self) -> Dict[str, str]:
        """Serialize to dictionary."""
        return {
            "pid": self.pid,
            "filepath": self.filepath,
            "operation": self.operation,
            "timestamp": self.timestamp,
            "target_filename": self.target_filename,
        }


# ============================================================
# Suspicious Process Indicators
# ============================================================

SUSPICIOUS_PROCESSES = {
    # LOLBins and common attack tools
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "certutil.exe", "bitsadmin.exe", "msiexec.exe", "wmic.exe",
    "psexec.exe", "psexesvc.exe", "wmiprvse.exe",
    # Attack frameworks
    "mimikatz.exe", "rubeus.exe", "sharphound.exe", "cobalt",
    "beacon.exe", "meterpreter",
    # Linux suspicious
    "nc", "ncat", "nmap", "socat", "curl", "wget",
}

SUSPICIOUS_PARENT_CHILD = {
    # Suspicious parent → child relationships
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    ("w3wp.exe", "cmd.exe"),
    ("w3wp.exe", "powershell.exe"),
    ("svchost.exe", "cmd.exe"),
    ("services.exe", "cmd.exe"),
    ("explorer.exe", "mshta.exe"),
    ("explorer.exe", "regsvr32.exe"),
}


# ============================================================
# Process Graph Engine
# ============================================================

class ProcessGraph:
    """
    Directed graph mapping process lineage relationships.

    Ingests events from Sysmon (EID 1, 3, 11), Windows Security (4688),
    and Linux auditd execve logs. Uses networkx when available, otherwise
    pure-Python adjacency dict.

    Example:
        >>> graph = ProcessGraph()
        >>> graph.ingest_events(events)
        >>> rca = graph.root_cause_analysis("target_node_id")
        >>> export = graph.export_d3_json()
    """

    def __init__(self) -> None:
        """Initialize the process graph."""
        self._nodes: Dict[str, ProcessNode] = {}
        self._edges: Dict[str, List[str]] = defaultdict(list)  # parent → children
        self._reverse_edges: Dict[str, str] = {}  # child → parent
        self._pid_index: Dict[str, List[str]] = defaultdict(list)  # pid → node_ids
        self._network_conns: List[NetworkConnection] = []
        self._file_ops: List[FileOperation] = []
        self._nx_graph: Optional[Any] = None  # networkx DiGraph if available

        if NX_AVAILABLE:
            self._nx_graph = nx.DiGraph()

    @property
    def node_count(self) -> int:
        """Return total number of process nodes."""
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        """Return total number of parent→child edges."""
        return sum(len(children) for children in self._edges.values())

    def ingest_events(self, events: List[dict]) -> int:
        """
        Ingest normalized events and build the process graph.

        Handles Sysmon Event IDs 1 (Process Create), 3 (Network),
        11 (File Create), Windows Security 4688, and Linux auditd
        execve events.

        Args:
            events: List of normalized event dictionaries from ThreatScope parsers.

        Returns:
            Number of nodes added to the graph.
        """
        nodes_before = self.node_count

        for event in events:
            eid = str(event.get("event_id", ""))
            raw = event.get("raw", "")
            fields = event.get("fields", {})
            platform = event.get("platform", "")

            # Sysmon Event ID 1: Process Create
            if eid == "1" or "Process Create" in raw:
                self._ingest_sysmon_proc_create(event)

            # Sysmon Event ID 3: Network Connection
            elif eid == "3" or "Network connection" in raw:
                self._ingest_sysmon_network(event)

            # Sysmon Event ID 11: File Create
            elif eid == "11" or "File created" in raw:
                self._ingest_sysmon_file_create(event)

            # Windows Security 4688: New Process Created
            elif eid == "4688" or "A new process has been created" in raw:
                self._ingest_security_4688(event)

            # Linux auditd execve
            elif platform == "linux" and ("execve" in raw or "EXECVE" in raw):
                self._ingest_linux_execve(event)

            # Linux auditd syscall (process exec)
            elif platform == "linux" and fields.get("action") in ("execve", "exec"):
                self._ingest_linux_execve(event)

        added = self.node_count - nodes_before
        logger.info(
            f"Graph ingestion complete: {added} nodes added "
            f"({self.node_count} total, {self.edge_count} edges)"
        )
        return added

    def _ingest_sysmon_proc_create(self, event: dict) -> None:
        """Ingest a Sysmon Event ID 1 (Process Create) event."""
        fields = event.get("fields", {})
        raw = event.get("raw", "")

        # Extract from fields or parse from raw
        pid = fields.get("ProcessId", fields.get("pid", ""))
        ppid = fields.get("ParentProcessId", fields.get("ppid", ""))
        image = fields.get("Image", fields.get("process", ""))
        cmdline = fields.get("CommandLine", fields.get("cmdline", ""))
        user = fields.get("User", fields.get("user", ""))
        parent_image = fields.get("ParentImage", "")
        sha256 = fields.get("SHA256", fields.get("Hashes", ""))
        integrity = fields.get("IntegrityLevel", "")

        # Parse from raw XML if fields are sparse
        if not pid and raw:
            pid = self._extract_xml_field(raw, "ProcessId") or ""
            ppid = self._extract_xml_field(raw, "ParentProcessId") or ""
            image = self._extract_xml_field(raw, "Image") or ""
            cmdline = self._extract_xml_field(raw, "CommandLine") or ""
            user = self._extract_xml_field(raw, "User") or ""

        if not pid:
            return

        node = ProcessNode(
            pid=pid,
            ppid=ppid,
            name=self._extract_basename(image),
            cmdline=cmdline,
            user=user,
            timestamp=event.get("timestamp", ""),
            hostname=fields.get("hostname", fields.get("Computer", "")),
            event_id="sysmon_1",
            integrity_level=integrity,
            sha256=sha256,
            raw_event=event,
        )

        self._add_node(node)

        # Check for suspicious parent→child relationship
        parent_name = self._extract_basename(parent_image).lower()
        child_name = node.name.lower()
        if (parent_name, child_name) in SUSPICIOUS_PARENT_CHILD:
            node.is_suspicious = True
            node.tags.append(f"suspicious_parent:{parent_name}")

        if child_name in SUSPICIOUS_PROCESSES:
            node.tags.append("lolbin")

    def _ingest_sysmon_network(self, event: dict) -> None:
        """Ingest a Sysmon Event ID 3 (Network Connection) event."""
        fields = event.get("fields", {})
        raw = event.get("raw", "")

        pid = fields.get("ProcessId", self._extract_xml_field(raw, "ProcessId") or "")
        if not pid:
            return

        conn = NetworkConnection(
            pid=pid,
            src_ip=fields.get("SourceIp", self._extract_xml_field(raw, "SourceIp") or ""),
            src_port=fields.get("SourcePort", self._extract_xml_field(raw, "SourcePort") or ""),
            dst_ip=fields.get("DestinationIp", self._extract_xml_field(raw, "DestinationIp") or ""),
            dst_port=fields.get("DestinationPort", self._extract_xml_field(raw, "DestinationPort") or ""),
            protocol=fields.get("Protocol", "tcp"),
            timestamp=event.get("timestamp", ""),
            initiated=fields.get("Initiated", "true").lower() == "true",
        )

        self._network_conns.append(conn)

        # Attach to matching process node
        for node_id in self._pid_index.get(pid, []):
            self._nodes[node_id].network_connections.append(conn.to_dict())

    def _ingest_sysmon_file_create(self, event: dict) -> None:
        """Ingest a Sysmon Event ID 11 (File Create) event."""
        fields = event.get("fields", {})
        raw = event.get("raw", "")

        pid = fields.get("ProcessId", self._extract_xml_field(raw, "ProcessId") or "")
        target = fields.get("TargetFilename", self._extract_xml_field(raw, "TargetFilename") or "")

        if not pid:
            return

        file_op = FileOperation(
            pid=pid,
            filepath=target,
            operation="create",
            timestamp=event.get("timestamp", ""),
            target_filename=self._extract_basename(target),
        )

        self._file_ops.append(file_op)

        for node_id in self._pid_index.get(pid, []):
            self._nodes[node_id].file_operations.append(file_op.to_dict())

    def _ingest_security_4688(self, event: dict) -> None:
        """Ingest a Windows Security Event 4688 (New Process Created)."""
        fields = event.get("fields", {})
        raw = event.get("raw", "")

        pid = fields.get("NewProcessId", fields.get("ProcessId", ""))
        ppid = fields.get("CreatorProcessId", fields.get("ParentProcessId", ""))
        image = fields.get("NewProcessName", fields.get("process", ""))
        cmdline = fields.get("CommandLine", fields.get("cmdline", ""))
        user = fields.get("SubjectUserName", fields.get("TargetUserName", fields.get("user", "")))

        # Parse hex PIDs (Windows Security uses 0x format)
        if pid and pid.startswith("0x"):
            try:
                pid = str(int(pid, 16))
            except ValueError:
                pass
        if ppid and ppid.startswith("0x"):
            try:
                ppid = str(int(ppid, 16))
            except ValueError:
                pass

        if not pid:
            return

        node = ProcessNode(
            pid=pid,
            ppid=ppid,
            name=self._extract_basename(image),
            cmdline=cmdline,
            user=user,
            timestamp=event.get("timestamp", ""),
            hostname=fields.get("hostname", fields.get("Computer", "")),
            event_id="security_4688",
            raw_event=event,
        )

        self._add_node(node)

    def _ingest_linux_execve(self, event: dict) -> None:
        """Ingest a Linux auditd execve event."""
        fields = event.get("fields", {})
        raw = event.get("raw", "")

        pid = fields.get("pid", "")
        ppid = fields.get("ppid", "")
        exe = fields.get("exe", fields.get("process", ""))
        cmdline = fields.get("cmdline", fields.get("command", ""))
        user = fields.get("uid", fields.get("auid", fields.get("user", "")))

        # Parse from raw auditd format
        if not pid and raw:
            pid_match = re.search(r"pid=(\d+)", raw)
            pid = pid_match.group(1) if pid_match else ""
            ppid_match = re.search(r"ppid=(\d+)", raw)
            ppid = ppid_match.group(1) if ppid_match else ""
            exe_match = re.search(r'exe="([^"]+)"', raw)
            exe = exe_match.group(1) if exe_match else ""

        if not pid:
            return

        node = ProcessNode(
            pid=pid,
            ppid=ppid,
            name=self._extract_basename(exe),
            cmdline=cmdline,
            user=user,
            timestamp=event.get("timestamp", ""),
            hostname=fields.get("hostname", ""),
            event_id="auditd_execve",
            raw_event=event,
        )

        self._add_node(node)

    def _add_node(self, node: ProcessNode) -> None:
        """Add a process node and establish parent→child edges."""
        node_id = node.node_id
        self._nodes[node_id] = node
        self._pid_index[node.pid].append(node_id)

        # Build edges
        if node.ppid:
            parent_nodes = self._pid_index.get(node.ppid, [])
            if parent_nodes:
                parent_id = parent_nodes[-1]  # Use most recent parent
                self._edges[parent_id].append(node_id)
                self._reverse_edges[node_id] = parent_id
                if parent_id in self._nodes:
                    self._nodes[parent_id].children.append(node_id)

        # Sync to networkx graph
        if self._nx_graph is not None:
            self._nx_graph.add_node(node_id, **node.to_dict())
            if node_id in self._reverse_edges:
                self._nx_graph.add_edge(self._reverse_edges[node_id], node_id)

    # ============================================================
    # Root Cause Analysis (RCA) Backtracking
    # ============================================================

    def root_cause_analysis(
        self, alert_node_id: str, max_depth: int = 50
    ) -> Dict[str, Any]:
        """
        Automated Root Cause Analysis: given an alert node, traverse
        backwards through the process lineage to find the initial
        execution parent (e.g., w3wp.exe or winword.exe).

        Args:
            alert_node_id: The node ID of the alerting process.
            max_depth: Maximum backtrack depth to prevent infinite loops.

        Returns:
            Dictionary containing:
                - root_process: The identified root cause process node.
                - chain: Ordered list of nodes from root to alert.
                - chain_length: Number of hops.
                - risk_indicators: Suspicious patterns found in chain.
                - visualization: D3.js-compatible chain data.
        """
        if alert_node_id not in self._nodes:
            return {"error": f"Node {alert_node_id} not found in graph"}

        chain: List[ProcessNode] = []
        visited: Set[str] = set()
        current_id = alert_node_id

        # Walk backwards through parent chain
        while current_id and len(chain) < max_depth:
            if current_id in visited:
                break  # Prevent cycles
            visited.add(current_id)

            node = self._nodes.get(current_id)
            if not node:
                break

            chain.append(node)
            current_id = self._reverse_edges.get(current_id, "")

        # Reverse to get root → alert order
        chain.reverse()

        # Analyze the chain for risk indicators
        risk_indicators = self._analyze_chain_risk(chain)

        root = chain[0] if chain else None

        return {
            "root_process": root.to_dict() if root else None,
            "alert_process": self._nodes[alert_node_id].to_dict(),
            "chain": [n.to_dict() for n in chain],
            "chain_length": len(chain),
            "risk_indicators": risk_indicators,
            "visualization": self._chain_to_d3(chain),
        }

    def _analyze_chain_risk(self, chain: List[ProcessNode]) -> List[Dict[str, str]]:
        """Analyze a process chain for risk indicators."""
        indicators: List[Dict[str, str]] = []

        for i, node in enumerate(chain):
            name_lower = node.name.lower()

            # Check for suspicious process names
            if name_lower in SUSPICIOUS_PROCESSES:
                indicators.append({
                    "type": "suspicious_process",
                    "node": node.node_id,
                    "process": node.name,
                    "detail": f"Known attack tool or LOLBin: {node.name}",
                })

            # Check for suspicious parent→child
            if i > 0:
                parent_name = chain[i - 1].name.lower()
                if (parent_name, name_lower) in SUSPICIOUS_PARENT_CHILD:
                    indicators.append({
                        "type": "suspicious_spawn",
                        "node": node.node_id,
                        "detail": f"{chain[i-1].name} spawned {node.name}",
                    })

            # Check for encoded/obfuscated command lines
            cmdline = node.cmdline
            if cmdline and self._is_obfuscated_cmdline(cmdline):
                indicators.append({
                    "type": "obfuscated_cmdline",
                    "node": node.node_id,
                    "detail": f"Potentially obfuscated command line in {node.name}",
                })

            # Check for network connections from unexpected processes
            if node.network_connections and name_lower in {
                "winword.exe", "excel.exe", "notepad.exe", "calc.exe"
            }:
                indicators.append({
                    "type": "unexpected_network",
                    "node": node.node_id,
                    "detail": f"{node.name} made network connections",
                })

        return indicators

    def _is_obfuscated_cmdline(self, cmdline: str) -> bool:
        """Check if a command line appears obfuscated."""
        # Base64 encoded commands
        if re.search(r"-[eE](?:nc(?:odedcommand)?)\s+[A-Za-z0-9+/=]{20,}", cmdline):
            return True
        # Caret/backtick obfuscation
        if cmdline.count("^") > 5 or cmdline.count("`") > 5:
            return True
        # Long hex strings
        if re.search(r"(?:0x[0-9a-fA-F]{2},?){10,}", cmdline):
            return True
        return False

    def _chain_to_d3(self, chain: List[ProcessNode]) -> Dict[str, Any]:
        """Convert a process chain to D3.js-compatible format."""
        nodes = []
        links = []

        for i, node in enumerate(chain):
            d3_node = {
                "id": node.node_id,
                "label": node.name or f"PID:{node.pid}",
                "pid": node.pid,
                "user": node.user,
                "timestamp": node.timestamp,
                "suspicious": node.is_suspicious,
                "group": 2 if node.is_suspicious else 1,
            }
            nodes.append(d3_node)

            if i > 0:
                links.append({
                    "source": chain[i - 1].node_id,
                    "target": node.node_id,
                    "type": "spawned",
                })

        return {"nodes": nodes, "links": links}

    # ============================================================
    # Graph Queries
    # ============================================================

    def get_children(self, node_id: str, recursive: bool = False) -> List[ProcessNode]:
        """
        Get child processes of a given node.

        Args:
            node_id: The parent node ID.
            recursive: If True, get all descendants recursively.

        Returns:
            List of child ProcessNode objects.
        """
        result: List[ProcessNode] = []
        visited: Set[str] = set()

        def _collect(nid: str) -> None:
            for child_id in self._edges.get(nid, []):
                if child_id in visited:
                    continue
                visited.add(child_id)
                child = self._nodes.get(child_id)
                if child:
                    result.append(child)
                    if recursive:
                        _collect(child_id)

        _collect(node_id)
        return result

    def find_processes_by_name(self, name: str) -> List[ProcessNode]:
        """
        Find all process nodes matching a name (case-insensitive).

        Args:
            name: Process name to search for.

        Returns:
            List of matching ProcessNode objects.
        """
        name_lower = name.lower()
        return [
            node for node in self._nodes.values()
            if name_lower in node.name.lower()
        ]

    def get_suspicious_nodes(self) -> List[ProcessNode]:
        """Get all nodes flagged as suspicious."""
        return [n for n in self._nodes.values() if n.is_suspicious or n.tags]

    def get_process_tree(self, root_pid: str) -> Dict[str, Any]:
        """
        Build a hierarchical process tree starting from a given PID.

        Args:
            root_pid: The root process PID.

        Returns:
            Nested dictionary representing the process tree.
        """
        root_nodes = self._pid_index.get(root_pid, [])
        if not root_nodes:
            return {}

        def _build_tree(node_id: str, depth: int = 0) -> Dict[str, Any]:
            node = self._nodes.get(node_id)
            if not node or depth > 30:
                return {}

            tree: Dict[str, Any] = node.to_dict()
            tree["children_tree"] = [
                _build_tree(child_id, depth + 1)
                for child_id in self._edges.get(node_id, [])
            ]
            return tree

        return _build_tree(root_nodes[0])

    # ============================================================
    # Export Functions
    # ============================================================

    def export_d3_json(self) -> Dict[str, Any]:
        """
        Export the full graph in D3.js force-directed graph format.

        Returns:
            Dictionary with 'nodes' and 'links' arrays compatible
            with D3.js and Cytoscape.js visualization libraries.
        """
        nodes = []
        links = []

        for node_id, node in self._nodes.items():
            d3_node = {
                "id": node_id,
                "label": node.name or f"PID:{node.pid}",
                "pid": node.pid,
                "ppid": node.ppid,
                "user": node.user,
                "cmdline": node.cmdline[:200] if node.cmdline else "",
                "timestamp": node.timestamp,
                "event_id": node.event_id,
                "suspicious": node.is_suspicious,
                "tags": node.tags,
                "group": self._node_group(node),
                "network_count": len(node.network_connections),
                "file_count": len(node.file_operations),
            }
            nodes.append(d3_node)

        for parent_id, children in self._edges.items():
            for child_id in children:
                links.append({
                    "source": parent_id,
                    "target": child_id,
                    "type": "spawned",
                    "value": 1,
                })

        # Add network connection edges
        for conn in self._network_conns:
            net_node_id = f"net:{conn.dst_ip}:{conn.dst_port}"
            if net_node_id not in {n["id"] for n in nodes}:
                nodes.append({
                    "id": net_node_id,
                    "label": f"{conn.dst_ip}:{conn.dst_port}",
                    "group": 3,  # Network node group
                    "type": "network",
                })
            for node_id in self._pid_index.get(conn.pid, []):
                links.append({
                    "source": node_id,
                    "target": net_node_id,
                    "type": "network",
                    "value": 0.5,
                })

        return {
            "nodes": nodes,
            "links": links,
            "metadata": {
                "total_processes": self.node_count,
                "total_edges": self.edge_count,
                "network_connections": len(self._network_conns),
                "file_operations": len(self._file_ops),
                "suspicious_nodes": len(self.get_suspicious_nodes()),
            },
        }

    def export_cytoscape_json(self) -> Dict[str, Any]:
        """
        Export graph in Cytoscape.js JSON format.

        Returns:
            Cytoscape.js-compatible elements dictionary.
        """
        elements: List[Dict[str, Any]] = []

        for node_id, node in self._nodes.items():
            elements.append({
                "group": "nodes",
                "data": {
                    "id": node_id,
                    "label": node.name or f"PID:{node.pid}",
                    **node.to_dict(),
                },
            })

        for parent_id, children in self._edges.items():
            for child_id in children:
                elements.append({
                    "group": "edges",
                    "data": {
                        "id": f"{parent_id}->{child_id}",
                        "source": parent_id,
                        "target": child_id,
                        "type": "spawned",
                    },
                })

        return {"elements": elements}

    def export_json(self, filepath: str) -> str:
        """
        Export graph data to a JSON file.

        Args:
            filepath: Output file path.

        Returns:
            Path to the exported file.
        """
        data = {
            "format": "threatscope_process_graph",
            # Export format version (first versioned export of this
            # format). Not a product release version.
            "version": "1.0",
            "d3": self.export_d3_json(),
            "cytoscape": self.export_cytoscape_json(),
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

        logger.info(f"Process graph exported to {filepath}")
        return filepath

    # ============================================================
    # NetworkX Integration (Advanced Analytics)
    # ============================================================

    def get_centrality_scores(self) -> Dict[str, float]:
        """
        Calculate betweenness centrality for all nodes.
        High centrality nodes are potential pivot points in attacks.

        Returns:
            Dictionary mapping node IDs to centrality scores.

        Raises:
            RuntimeError: If networkx is not available.
        """
        if self._nx_graph is None:
            raise RuntimeError("networkx required for centrality analysis")
        if len(self._nx_graph) == 0:
            return {}
        return nx.betweenness_centrality(self._nx_graph)

    def detect_anomalous_paths(self) -> List[Dict[str, Any]]:
        """
        Detect anomalous process chains using graph analysis.

        Looks for:
        - Unusually deep process trees (>5 levels)
        - Processes with many children (potential process bombing)
        - Isolated suspicious processes

        Returns:
            List of anomaly dictionaries.
        """
        anomalies: List[Dict[str, Any]] = []

        # Deep chains
        for node_id in self._nodes:
            depth = 0
            current = node_id
            while current in self._reverse_edges:
                depth += 1
                current = self._reverse_edges[current]
                if depth > 50:
                    break
            if depth > 5:
                anomalies.append({
                    "type": "deep_chain",
                    "node_id": node_id,
                    "depth": depth,
                    "process": self._nodes[node_id].name,
                    "severity": "medium" if depth < 10 else "high",
                })

        # Fan-out (many children)
        for node_id, children in self._edges.items():
            if len(children) > 20:
                anomalies.append({
                    "type": "high_fanout",
                    "node_id": node_id,
                    "children_count": len(children),
                    "process": self._nodes.get(node_id, ProcessNode("")).name,
                    "severity": "medium",
                })

        return anomalies

    # ============================================================
    # Utility Methods
    # ============================================================

    @staticmethod
    def _extract_basename(path: str) -> str:
        """Extract the filename from a full path."""
        if not path:
            return ""
        # Handle both Windows and Unix paths
        return path.replace("\\", "/").split("/")[-1]

    @staticmethod
    def _extract_xml_field(raw: str, field_name: str) -> Optional[str]:
        """Extract a field value from raw XML event data."""
        pattern = rf"<Data Name='{field_name}'>([^<]*)</Data>"
        match = re.search(pattern, raw, re.IGNORECASE)
        if match:
            return match.group(1)
        # Try attribute format
        pattern2 = rf"{field_name}[=:]'?\"?([^'\">\s]+)"
        match2 = re.search(pattern2, raw, re.IGNORECASE)
        return match2.group(1) if match2 else None

    @staticmethod
    def _node_group(node: ProcessNode) -> int:
        """Assign a visualization group number based on node properties."""
        if node.is_suspicious:
            return 4  # Red — suspicious
        name = node.name.lower()
        if name in {"system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe"}:
            return 0  # System processes
        if name in SUSPICIOUS_PROCESSES:
            return 3  # Known tools
        if node.network_connections:
            return 2  # Network-active
        return 1  # Normal

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the process graph for integration
        with the main analyzer results.

        Returns:
            Summary dictionary compatible with ThreatScope results format.
        """
        suspicious = self.get_suspicious_nodes()
        return {
            "total_processes": self.node_count,
            "total_edges": self.edge_count,
            "network_connections": len(self._network_conns),
            "file_operations": len(self._file_ops),
            "suspicious_processes": len(suspicious),
            "suspicious_details": [
                {
                    "name": n.name,
                    "pid": n.pid,
                    "tags": n.tags,
                    "cmdline": n.cmdline[:200] if n.cmdline else "",
                }
                for n in suspicious[:20]
            ],
            "anomalies": self.detect_anomalous_paths()[:10],
        }
