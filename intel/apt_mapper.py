"""
ThreatScope — APT Group Mapper & CVE Feed
Author: 0xSABRY

APT Group Attribution: Cross-references detected MITRE techniques
with known APT group profiles and suggests likely threat actors.

CVE Feed: Looks up CVEs from NVD and checks ExploitDB for available exploits.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
from collections import defaultdict

logger = logging.getLogger("threatscope.intel")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ============================================================
# APT Group TTP Database (subset of MITRE Groups)
# ============================================================
APT_GROUPS = {
    "APT28": {
        "aliases": ["Fancy Bear", "Sofacy", "STRONTIUM", "Sednit"],
        "country": "Russia",
        "description": "Russian GRU-affiliated threat group known for cyber espionage",
        "techniques": ["T1566", "T1059.001", "T1071", "T1003", "T1027", "T1070",
                       "T1105", "T1083", "T1057", "T1112", "T1547.001", "T1053"],
    },
    "APT29": {
        "aliases": ["Cozy Bear", "NOBELIUM", "The Dukes"],
        "country": "Russia",
        "description": "Russian SVR-affiliated group known for SolarWinds supply chain attack",
        "techniques": ["T1195", "T1078", "T1059.001", "T1071.001", "T1586",
                       "T1583", "T1102", "T1027", "T1573", "T1021.002"],
    },
    "APT41": {
        "aliases": ["Winnti", "BARIUM", "Double Dragon"],
        "country": "China",
        "description": "Chinese dual espionage and financial gain group",
        "techniques": ["T1190", "T1133", "T1059.001", "T1059.003", "T1547.001",
                       "T1543.003", "T1068", "T1003", "T1005", "T1041"],
    },
    "Lazarus": {
        "aliases": ["HIDDEN COBRA", "Zinc", "Labyrinth Chollima"],
        "country": "North Korea",
        "description": "North Korean state-sponsored group targeting financial institutions",
        "techniques": ["T1566.001", "T1204", "T1059.005", "T1059.001",
                       "T1027", "T1055", "T1486", "T1565", "T1071.001", "T1105"],
    },
    "APT1": {
        "aliases": ["Comment Crew", "PLA Unit 61398"],
        "country": "China",
        "description": "Chinese PLA cyber espionage unit",
        "techniques": ["T1566.002", "T1059.003", "T1071.001", "T1003",
                       "T1005", "T1074", "T1041", "T1090"],
    },
    "FIN7": {
        "aliases": ["Carbanak", "Navigator", "Carbon Spider"],
        "country": "Russia",
        "description": "Financially motivated group targeting hospitality and retail",
        "techniques": ["T1566.001", "T1204.002", "T1059.001", "T1059.005",
                       "T1547.001", "T1003", "T1021.001", "T1041"],
    },
    "Sandworm": {
        "aliases": ["Voodoo Bear", "IRIDIUM", "Electrum"],
        "country": "Russia",
        "description": "GRU Unit 74455 — responsible for NotPetya and power grid attacks",
        "techniques": ["T1190", "T1059.001", "T1059.003", "T1027",
                       "T1070", "T1486", "T1529", "T1498", "T1071.001"],
    },
    "Turla": {
        "aliases": ["Snake", "Venomous Bear", "Uroburos"],
        "country": "Russia",
        "description": "Russian FSB-affiliated espionage group operational since the 1990s",
        "techniques": ["T1566.001", "T1059.001", "T1059.003", "T1071.001",
                       "T1573", "T1027", "T1083", "T1082", "T1005"],
    },
    "APT32": {
        "aliases": ["OceanLotus", "Canvas Cyclone"],
        "country": "Vietnam",
        "description": "Vietnamese state-sponsored espionage group",
        "techniques": ["T1566.001", "T1204.002", "T1059.005", "T1059.001",
                       "T1547.001", "T1027", "T1071.001", "T1573"],
    },
    "MuddyWater": {
        "aliases": ["MERCURY", "Static Kitten", "Seedworm"],
        "country": "Iran",
        "description": "Iranian state-affiliated group conducting espionage",
        "techniques": ["T1566.001", "T1059.001", "T1059.005", "T1105",
                       "T1547.001", "T1027", "T1071.001", "T1003"],
    },
    # V3 — Extended APT Groups
    "Kimsuky": {
        "aliases": ["Velvet Chollima", "Thallium", "Black Banshee"],
        "country": "North Korea",
        "description": "North Korean espionage group targeting think tanks and government",
        "techniques": ["T1566.001", "T1059.005", "T1059.001", "T1204.002",
                       "T1547.001", "T1027", "T1071.001", "T1056.001",
                       "T1113", "T1005"],
    },
    "Gamaredon": {
        "aliases": ["Primitive Bear", "Armageddon", "Shuckworm"],
        "country": "Russia",
        "description": "Russian FSB group targeting Ukrainian government entities",
        "techniques": ["T1566.001", "T1204.002", "T1059.005", "T1547.001",
                       "T1105", "T1071.001", "T1027", "T1059.003",
                       "T1083", "T1005"],
    },
    "Charming_Kitten": {
        "aliases": ["APT35", "Phosphorus", "Mint Sandstorm"],
        "country": "Iran",
        "description": "Iranian state-sponsored group conducting espionage against academics and dissidents",
        "techniques": ["T1566.001", "T1566.002", "T1078", "T1059.001",
                       "T1110", "T1003", "T1071.001", "T1105",
                       "T1005", "T1114"],
    },
    "Hafnium": {
        "aliases": ["Silk Typhoon"],
        "country": "China",
        "description": "Chinese state-sponsored group targeting Exchange servers and defense contractors",
        "techniques": ["T1190", "T1505.003", "T1059.001", "T1003",
                       "T1560", "T1041", "T1071.001", "T1027",
                       "T1083", "T1082"],
    },
    "Darkside": {
        "aliases": ["BlackMatter"],
        "country": "Russia",
        "description": "Ransomware-as-a-Service operation behind Colonial Pipeline attack",
        "techniques": ["T1190", "T1133", "T1078", "T1486",
                       "T1021.002", "T1003", "T1041", "T1070",
                       "T1562.001", "T1529"],
    },
    "REvil": {
        "aliases": ["Sodinokibi", "GoldSouthfield"],
        "country": "Russia",
        "description": "Prolific RaaS operation known for high-profile supply chain attacks",
        "techniques": ["T1190", "T1195", "T1486", "T1059.001",
                       "T1027", "T1562.001", "T1070", "T1041",
                       "T1078", "T1021.001"],
    },
    "Volt_Typhoon": {
        "aliases": ["Bronze Silhouette", "Vanguard Panda"],
        "country": "China",
        "description": "Chinese state actor targeting US critical infrastructure using LOLBins",
        "techniques": ["T1190", "T1059.001", "T1059.003", "T1078",
                       "T1047", "T1053.005", "T1021.001", "T1003",
                       "T1082", "T1071.001"],
    },
    "Scattered_Spider": {
        "aliases": ["UNC3944", "Roasted 0ktapus", "Star Fraud"],
        "country": "International",
        "description": "Social engineering group targeting identity providers and telecom",
        "techniques": ["T1566", "T1621", "T1078", "T1110",
                       "T1059.001", "T1021.001", "T1098",
                       "T1530", "T1003", "T1486"],
    },
    "LockBit_Group": {
        "aliases": ["LockBit 3.0", "LockBitSupp"],
        "country": "Russia",
        "description": "Most prolific ransomware group operating LockBit RaaS",
        "techniques": ["T1190", "T1133", "T1078", "T1486",
                       "T1059.001", "T1562.001", "T1070",
                       "T1021.002", "T1003", "T1041"],
    },
    "ALPHV_BlackCat": {
        "aliases": ["BlackCat", "Noberus"],
        "country": "Russia",
        "description": "Rust-based ransomware group with cross-platform capabilities",
        "techniques": ["T1190", "T1078", "T1486", "T1059.001",
                       "T1562.001", "T1070", "T1003",
                       "T1021.002", "T1041", "T1048"],
    },
}


class APTMapper:
    """
    Maps detected MITRE ATT&CK techniques to known APT groups
    and provides attribution suggestions with confidence scores.
    """

    def __init__(self, custom_groups: Optional[Dict] = None):
        self.groups = APT_GROUPS.copy()
        if custom_groups:
            self.groups.update(custom_groups)

    def map_techniques(self, detected_techniques: List[str]) -> List[dict]:
        """
        Cross-reference detected techniques with APT group profiles.

        Args:
            detected_techniques: List of MITRE technique IDs found in analysis.

        Returns:
            List of APT group matches sorted by confidence.
        """
        if not detected_techniques:
            return []

        detected_set = set(t.upper() for t in detected_techniques)
        # Also match sub-techniques to parent
        detected_parents = set()
        for t in detected_set:
            detected_parents.add(t)
            if "." in t:
                detected_parents.add(t.split(".")[0])

        matches = []
        for group_name, group_data in self.groups.items():
            group_techniques = set(t.upper() for t in group_data["techniques"])
            group_parents = set()
            for t in group_techniques:
                group_parents.add(t)
                if "." in t:
                    group_parents.add(t.split(".")[0])

            overlap = detected_parents & group_parents
            if not overlap:
                continue

            coverage = len(overlap) / max(len(group_parents), 1)
            match_ratio = len(overlap) / max(len(detected_parents), 1)
            confidence = round((coverage * 0.6 + match_ratio * 0.4) * 100, 1)

            if confidence >= 15:
                matches.append({
                    "group": group_name,
                    "aliases": group_data["aliases"],
                    "country": group_data["country"],
                    "description": group_data["description"],
                    "confidence": confidence,
                    "matched_techniques": sorted(overlap),
                    "matched_count": len(overlap),
                    "group_total_techniques": len(group_techniques),
                })

        matches.sort(key=lambda x: x["confidence"], reverse=True)
        return matches[:10]

    def get_all_groups(self) -> List[dict]:
        """Get all APT groups in the database."""
        return [
            {
                "name": name,
                "aliases": data["aliases"],
                "country": data["country"],
                "description": data["description"],
                "technique_count": len(data["techniques"]),
            }
            for name, data in self.groups.items()
        ]


class CVEFeed:
    """
    Looks up CVEs from NVD and checks ExploitDB for available exploits.
    """

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        self.results: Dict[str, dict] = {}

    def lookup_cve(self, cve_id: str) -> dict:
        """
        Look up a CVE from the NVD API.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228).

        Returns:
            CVE details dictionary.
        """
        if cve_id in self.results:
            return self.results[cve_id]

        result = {
            "cve_id": cve_id,
            "description": "",
            "severity": "",
            "cvss_score": 0,
            "references": [],
            "exploits_available": False,
            "exploit_references": [],
        }

        if not REQUESTS_AVAILABLE:
            result["error"] = "requests library not installed"
            return result

        # Query NVD
        try:
            params = {"cveId": cve_id}
            resp = requests.get(self.NVD_API_URL, params=params, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    cve_data = vulnerabilities[0].get("cve", {})

                    # Description
                    descriptions = cve_data.get("descriptions", [])
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            result["description"] = desc.get("value", "")
                            break

                    # CVSS Score
                    metrics = cve_data.get("metrics", {})
                    for metric_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        metric_data = metrics.get(metric_version, [])
                        if metric_data:
                            cvss = metric_data[0].get("cvssData", {})
                            result["cvss_score"] = cvss.get("baseScore", 0)
                            result["severity"] = cvss.get("baseSeverity", "").upper()
                            break

                    # References
                    for ref in cve_data.get("references", [])[:10]:
                        ref_url = ref.get("url", "")
                        result["references"].append(ref_url)
                        if "exploit" in ref_url.lower() or "poc" in ref_url.lower():
                            result["exploits_available"] = True
                            result["exploit_references"].append(ref_url)

        except Exception as e:
            logger.debug(f"NVD lookup error for {cve_id}: {e}")
            result["error"] = str(e)

        self.results[cve_id] = result
        return result

    def lookup_multiple(self, cve_ids: List[str]) -> List[dict]:
        """Look up multiple CVEs."""
        results = []
        for cve_id in cve_ids[:20]:  # Limit to 20
            result = self.lookup_cve(cve_id)
            results.append(result)
        return results

    def get_summary(self) -> dict:
        """Get CVE lookup summary."""
        critical = len([r for r in self.results.values() if r.get("cvss_score", 0) >= 9.0])
        high = len([r for r in self.results.values() if 7.0 <= r.get("cvss_score", 0) < 9.0])
        exploitable = len([r for r in self.results.values() if r.get("exploits_available")])
        return {
            "total_cves": len(self.results),
            "critical": critical,
            "high": high,
            "exploitable": exploitable,
            "results": list(self.results.values()),
        }


# ============================================================
# MITRE ATT&CK Data Helper — Extended (100+ techniques)
# ============================================================
MITRE_TECHNIQUE_DESCRIPTIONS = {
    # Reconnaissance (TA0043)
    "T1595": "Active Scanning",
    "T1592": "Gather Victim Host Information",
    "T1589": "Gather Victim Identity Information",
    "T1590": "Gather Victim Network Information",
    "T1591": "Gather Victim Org Information",
    # Resource Development (TA0042)
    "T1583": "Acquire Infrastructure",
    "T1586": "Compromise Accounts",
    "T1584": "Compromise Infrastructure",
    "T1587": "Develop Capabilities",
    "T1585": "Establish Accounts",
    # Initial Access (TA0001)
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1200": "Hardware Additions",
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1195": "Supply Chain Compromise",
    "T1199": "Trusted Relationship",
    "T1078": "Valid Accounts",
    "T1204": "User Execution",
    "T1204.002": "Malicious File",
    # Execution (TA0002)
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.004": "Unix Shell",
    "T1059.005": "Visual Basic",
    "T1059.006": "Python",
    "T1203": "Exploitation for Client Execution",
    "T1047": "Windows Management Instrumentation",
    "T1053": "Scheduled Task/Job",
    "T1053.003": "Cron",
    "T1053.005": "Scheduled Task",
    "T1569": "System Services",
    "T1106": "Native API",
    # Persistence (TA0003)
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1543": "Create or Modify System Process",
    "T1543.003": "Windows Service",
    "T1136": "Create Account",
    "T1505": "Server Software Component",
    "T1505.003": "Web Shell",
    "T1542": "Pre-OS Boot",
    "T1542.001": "System Firmware",
    "T1098": "Account Manipulation",
    "T1037": "Boot or Logon Initialization Scripts",
    # Privilege Escalation (TA0004)
    "T1068": "Exploitation for Privilege Escalation",
    "T1055": "Process Injection",
    "T1055.001": "DLL Injection",
    "T1055.012": "Process Hollowing",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1548.001": "Setuid and Setgid",
    "T1548.002": "Bypass User Account Control",
    "T1611": "Escape to Host",
    "T1134": "Access Token Manipulation",
    # Defense Evasion (TA0005)
    "T1027": "Obfuscated Files or Information",
    "T1027.002": "Software Packing",
    "T1070": "Indicator Removal",
    "T1070.001": "Clear Windows Event Logs",
    "T1070.003": "Clear Command History",
    "T1070.004": "File Deletion",
    "T1562": "Impair Defenses",
    "T1562.001": "Disable or Modify Tools",
    "T1562.008": "Disable Cloud Logs",
    "T1553": "Subvert Trust Controls",
    "T1553.005": "Mark-of-the-Web Bypass",
    "T1036": "Masquerading",
    "T1218": "System Binary Proxy Execution",
    "T1112": "Modify Registry",
    "T1014": "Rootkit",
    "T1497": "Virtualization/Sandbox Evasion",
    "T1140": "Deobfuscate/Decode Files",
    # Credential Access (TA0006)
    "T1003": "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1003.006": "DCSync",
    "T1110": "Brute Force",
    "T1110.001": "Password Guessing",
    "T1110.003": "Password Spraying",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1558.001": "Golden Ticket",
    "T1558.003": "Kerberoasting",
    "T1528": "Steal Application Access Token",
    "T1539": "Steal Web Session Cookie",
    "T1621": "Multi-Factor Authentication Request Generation",
    "T1056": "Input Capture",
    "T1056.001": "Keylogging",
    "T1552": "Unsecured Credentials",
    "T1649": "Steal or Forge Authentication Certificates",
    # Discovery (TA0007)
    "T1046": "Network Service Discovery",
    "T1057": "Process Discovery",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1087": "Account Discovery",
    "T1087.002": "Domain Account",
    "T1016": "System Network Configuration Discovery",
    "T1049": "System Network Connections Discovery",
    "T1069": "Permission Groups Discovery",
    "T1018": "Remote System Discovery",
    "T1518": "Software Discovery",
    # Lateral Movement (TA0008)
    "T1021": "Remote Services",
    "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1021.006": "Windows Remote Management",
    "T1080": "Taint Shared Content",
    "T1563": "Remote Service Session Hijacking",
    "T1550": "Use Alternate Authentication Material",
    # Collection (TA0009)
    "T1005": "Data from Local System",
    "T1074": "Data Staged",
    "T1560": "Archive Collected Data",
    "T1113": "Screen Capture",
    "T1115": "Clipboard Data",
    "T1114": "Email Collection",
    "T1530": "Data from Cloud Storage",
    "T1039": "Data from Network Shared Drive",
    "T1119": "Automated Collection",
    # Command and Control (TA0011)
    "T1071": "Application Layer Protocol",
    "T1071.001": "Web Protocols",
    "T1071.004": "DNS",
    "T1573": "Encrypted Channel",
    "T1105": "Ingress Tool Transfer",
    "T1090": "Proxy",
    "T1102": "Web Service",
    "T1219": "Remote Access Software",
    "T1568": "Dynamic Resolution",
    "T1568.002": "Domain Generation Algorithms",
    "T1571": "Non-Standard Port",
    "T1572": "Protocol Tunneling",
    "T1205": "Traffic Signaling",
    # Exfiltration (TA0010)
    "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1567": "Exfiltration Over Web Service",
    "T1029": "Scheduled Transfer",
    "T1537": "Transfer Data to Cloud Account",
    # Impact (TA0040)
    "T1486": "Data Encrypted for Impact",
    "T1565": "Data Manipulation",
    "T1529": "System Shutdown/Reboot",
    "T1498": "Network Denial of Service",
    "T1496": "Resource Hijacking",
    "T1491": "Defacement",
    "T1561": "Disk Wipe",
    "T1557": "Adversary-in-the-Middle",
    "T1557.002": "ARP Cache Poisoning",
}


def get_technique_name(technique_id: str) -> str:
    """Get the human name for a MITRE technique ID."""
    return MITRE_TECHNIQUE_DESCRIPTIONS.get(technique_id.upper(), technique_id)
