"""
ThreatScope V2 — Main Analyzer Orchestrator
Author: 0xSABRY

Central analysis engine that coordinates all detection modules:
Sigma rules, regex patterns, YARA scanning, behavioral chains,
correlation, IOC extraction, and threat scoring.
"""

import re
import hashlib
import logging
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict, Counter
from typing import List, Dict, Optional, Any

from core.sigma_engine import SigmaEngine
from core.yara_engine import YaraEngine
from core.ioc_extractor import IOCExtractor
from core.correlation import CorrelationEngine
from core.behavioral_chain import BehavioralChainEngine
from core.false_positive import FalsePositiveSuppressor
from parsers.log_parsers import get_parser, compute_file_hashes, TextLogParser

logger = logging.getLogger("threatscope.analyzer")


# ============================================================
# Built-in Detection Patterns (115+ regex rules from v3)
# ============================================================
BUILTIN_PATTERNS = {
    # Brute Force & Authentication
    "brute_force": {
        "patterns": [r"(?:failed|invalid)\s+(?:login|password|auth)", r"authentication\s+fail",
                     r"login\s+attempt.*fail", r"access\s+denied.*(?:user|login)", r"4625.*Audit\s+Failure"],
        "severity": "high", "weight": 20, "category": "Brute Force",
        "desc": "Multiple failed authentication attempts detected", "mitre": "T1110",
    },
    "credential_dumping": {
        "patterns": [r"mimikatz", r"sekurlsa", r"lsass\.exe.*access", r"hashdump",
                     r"gsecdump", r"wce\.exe", r"procdump.*lsass", r"comsvcs\.dll.*MiniDump"],
        "severity": "critical", "weight": 40, "category": "Credential Dumping",
        "desc": "Credential dumping tool or technique detected", "mitre": "T1003",
    },
    "privilege_escalation": {
        "patterns": [r"privilege\s+escalat", r"UAC\s+bypass", r"admin.*token",
                     r"sudo\s+.*NOPASSWD", r"4672.*Special\s+privileges", r"getsystem",
                     r"SeDebugPrivilege", r"JuicyPotato", r"PrintSpoofer"],
        "severity": "critical", "weight": 35, "category": "Privilege Escalation",
        "desc": "Privilege escalation attempt detected", "mitre": "T1068",
    },
    "lateral_movement": {
        "patterns": [r"psexec", r"wmiexec", r"smbexec", r"atexec", r"dcomexec",
                     r"evil-winrm", r"Enter-PSSession", r"Invoke-Command.*-Computer",
                     r"net\s+use.*\\\\", r"5140.*Network\s+Share"],
        "severity": "critical", "weight": 35, "category": "Lateral Movement",
        "desc": "Lateral movement technique detected", "mitre": "T1021",
    },
    "data_exfiltration": {
        "patterns": [r"exfiltrat", r"rclone\s+copy", r"mega(?:cmd|sync)",
                     r"curl.*-(?:T|d\s+@)", r"scp\s+.*@.*:", r"dns.*tunnel",
                     r"base64.*>.*\.txt", r"7z\s+a.*-p"],
        "severity": "critical", "weight": 35, "category": "Data Exfiltration",
        "desc": "Data exfiltration technique detected", "mitre": "T1041",
    },
    "persistence": {
        "patterns": [r"schtasks\s*/create", r"sc\s+create", r"reg\s+add.*Run",
                     r"crontab\s+-e", r"systemctl\s+enable", r"at\s+\d+:\d+",
                     r"HKLM\\.*\\Run", r"New-Service", r"Register-ScheduledTask"],
        "severity": "high", "weight": 25, "category": "Persistence",
        "desc": "Persistence mechanism creation detected", "mitre": "T1053",
    },
    "command_and_control": {
        "patterns": [r"beacon", r"cobalt\s*strike", r"meterpreter", r"empire",
                     r"reverse.*shell", r"bind.*shell", r"nc\s+-.*-e",
                     r"C2\s+channel", r"sliver", r"covenant"],
        "severity": "critical", "weight": 40, "category": "Command & Control",
        "desc": "Command & control activity detected", "mitre": "T1071",
    },
    "ransomware": {
        "patterns": [r"ransom", r"encrypt.*(?:files|documents)", r"\.locked$",
                     r"bitcoin.*wallet", r"your\s+files.*encrypted",
                     r"vssadmin.*delete.*shadows", r"wbadmin\s+delete",
                     r"bcdedit.*recoveryenabled.*no"],
        "severity": "critical", "weight": 40, "category": "Ransomware",
        "desc": "Ransomware indicators detected", "mitre": "T1486",
    },
    "log_tampering": {
        "patterns": [r"wevtutil\s+cl", r"Clear-EventLog", r"1102.*Log\s+Clear",
                     r"auditpol.*disable", r"rm\s+-rf\s+/var/log",
                     r"history\s*-c", r"shred\s+.*\.log"],
        "severity": "critical", "weight": 35, "category": "Log Tampering",
        "desc": "Log tampering or anti-forensics detected", "mitre": "T1070",
    },
    "reverse_shell": {
        "patterns": [r"bash\s+-i\s+>&\s+/dev/tcp", r"nc\s+.*-e\s+/bin/(?:ba)?sh",
                     r"python.*socket.*connect.*exec", r"php\s+-r.*fsockopen",
                     r"ruby.*TCPSocket.*exec", r"powershell.*Net\.Sockets"],
        "severity": "critical", "weight": 40, "category": "Reverse Shell",
        "desc": "Reverse shell technique detected", "mitre": "T1059",
    },
    "sql_injection": {
        "patterns": [r"(?:UNION|SELECT).*(?:FROM|WHERE).*(?:--|;)", r"OR\s+1\s*=\s*1",
                     r"(?:DROP|ALTER)\s+TABLE", r"WAITFOR\s+DELAY",
                     r"xp_cmdshell", r"load_file\s*\(", r"INTO\s+OUTFILE"],
        "severity": "high", "weight": 25, "category": "SQL Injection",
        "desc": "SQL injection attempt detected", "mitre": "T1190",
    },
    "powershell_abuse": {
        "patterns": [r"(?:-enc|-EncodedCommand)\s+[A-Za-z0-9+/=]{20,}",
                     r"Invoke-Expression", r"IEX\s*\(", r"Invoke-Mimikatz",
                     r"Download(?:String|File)", r"Net\.WebClient",
                     r"Set-MpPreference.*-DisableRealtimeMonitoring"],
        "severity": "high", "weight": 25, "category": "PowerShell Abuse",
        "desc": "Suspicious PowerShell activity detected", "mitre": "T1059.001",
    },
    "av_tamper": {
        "patterns": [r"Set-MpPreference.*Disable", r"net\s+stop.*(?:defender|antivirus|mcafee|norton)",
                     r"sc\s+(?:stop|delete).*(?:Security|Windefend)",
                     r"kill.*(?:avp|avgnt|mbam|norton|defender)"],
        "severity": "critical", "weight": 35, "category": "AV Tampering",
        "desc": "Security tool tampering detected", "mitre": "T1562.001",
    },
    "kerberoasting": {
        "patterns": [r"kerberoast", r"Invoke-Kerberoast", r"GetUserSPNs",
                     r"4769.*(?:0x17|Encryption\s+Type:.*0x17)", r"Rubeus.*kerberoast"],
        "severity": "critical", "weight": 35, "category": "Kerberoasting",
        "desc": "Kerberoasting attack detected", "mitre": "T1558.003",
    },
    "golden_silver_ticket": {
        "patterns": [r"golden.*ticket", r"silver.*ticket", r"Invoke-(?:Golden|Silver)Ticket",
                     r"mimikatz.*kerberos::golden", r"ticketer\.py"],
        "severity": "critical", "weight": 40, "category": "Golden/Silver Ticket",
        "desc": "Kerberos ticket forging detected", "mitre": "T1558.001",
    },
    "ad_recon": {
        "patterns": [r"BloodHound", r"SharpHound", r"Get-(?:Domain|Forest|Net)",
                     r"ldapsearch", r"enum4linux", r"windapsearch",
                     r"PowerView", r"ADRecon"],
        "severity": "high", "weight": 25, "category": "AD Reconnaissance",
        "desc": "Active Directory reconnaissance detected", "mitre": "T1087.002",
    },
    "phishing_url": {
        "patterns": [r"(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co)/\S+",
                     r"login.*\.(?:xyz|tk|ml|ga|cf|pw)/",
                     r"(?:verify|confirm|secure).*account.*(?:click|link)"],
        "severity": "medium", "weight": 15, "category": "Phishing",
        "desc": "Phishing URL or social engineering indicators", "mitre": "T1566",
    },
    "network_discovery": {
        "patterns": [r"nmap\s+", r"masscan\s+", r"net\s+view", r"arp\s+-a",
                     r"netstat\s+-", r"ipconfig\s+/all", r"ifconfig"],
        "severity": "medium", "weight": 15, "category": "Network Discovery",
        "desc": "Network discovery commands detected", "mitre": "T1046",
    },
    "wmi_abuse": {
        "patterns": [r"wmic\s+", r"Get-WmiObject", r"Invoke-WmiMethod",
                     r"ManagementObject.*Win32_", r"wmic\s+process\s+call"],
        "severity": "medium", "weight": 15, "category": "WMI Abuse",
        "desc": "WMI abuse for execution or recon", "mitre": "T1047",
    },
    "scheduled_task": {
        "patterns": [r"schtasks\s*/create", r"Register-ScheduledTask",
                     r"crontab", r"at\s+\d+:\d+\s+"],
        "severity": "medium", "weight": 15, "category": "Scheduled Task",
        "desc": "Scheduled task creation detected", "mitre": "T1053.005",
    },
    "off_hours_access": {
        "patterns": [r"(?:0[0-4]|2[2-3]):\d{2}:\d{2}.*(?:logon|login|auth.*success)"],
        "severity": "medium", "weight": 10, "category": "Off-Hours Access",
        "desc": "Logon activity during unusual hours", "mitre": "T1078",
    },
    "bulk_download": {
        "patterns": [r"(?:wget|curl|certutil).*-(?:O|o|urlcache)",
                     r"bitsadmin.*transfer", r"large.*download", r"bulk.*export"],
        "severity": "medium", "weight": 15, "category": "Bulk Download",
        "desc": "Bulk file download or staging activity", "mitre": "T1105",
    },
    "container_escape": {
        "patterns": [r"docker\.sock", r"mount.*nsenter", r"docker.*--privileged",
                     r"kubernetes.*exec", r"kubectl.*exec"],
        "severity": "critical", "weight": 35, "category": "Container Escape",
        "desc": "Container escape attempt detected", "mitre": "T1611",
    },
    "arp_poisoning": {
        "patterns": [r"arp.*(?:spoof|poison)", r"ettercap", r"bettercap.*arp",
                     r"arpwatch.*changed", r"duplicate.*IP.*address"],
        "severity": "high", "weight": 25, "category": "ARP Poisoning",
        "desc": "ARP spoofing/poisoning detected", "mitre": "T1557.002",
    },
    "mfa_fatigue": {
        "patterns": [r"multiple.*push.*notification", r"MFA.*(?:denied|timeout).*repeated",
                     r"2FA.*bomb", r"authentication.*push.*spam"],
        "severity": "high", "weight": 25, "category": "MFA Fatigue",
        "desc": "MFA fatigue/push bombing attack detected", "mitre": "T1621",
    },
    "jwt_abuse": {
        "patterns": [r"JWT.*(?:none|alg.*none)", r"(?:eyJ|jwt).*(?:tamper|forge|modify)",
                     r"token.*(?:replay|reuse)"],
        "severity": "high", "weight": 25, "category": "JWT Abuse",
        "desc": "JWT token abuse detected", "mitre": "T1528",
    },
    "prompt_injection": {
        "patterns": [r"ignore\s+(?:previous|all)\s+instructions",
                     r"(?:system|admin)\s+prompt.*override",
                     r"jailbreak.*(?:DAN|bypass)"],
        "severity": "medium", "weight": 15, "category": "Prompt Injection",
        "desc": "AI prompt injection attempt detected", "mitre": "T1059",
    },
    # ============================================================
    # V3 Extended Detection Patterns (30 new categories)
    # ============================================================
    "ssh_brute_force": {
        "patterns": [r"sshd\[\d+\]:\s+Failed\s+password", r"sshd.*authentication\s+failure",
                     r"sshd\[\d+\]:\s+Invalid\s+user", r"maximum\s+authentication\s+attempts\s+exceeded",
                     r"ssh.*Connection\s+closed.*preauth", r"pam_unix.*sshd.*authentication\s+failure"],
        "severity": "high", "weight": 25, "category": "SSH Brute Force",
        "desc": "SSH brute-force attack detected", "mitre": "T1110.001",
    },
    "linux_rootkit": {
        "patterns": [r"LD_PRELOAD\s*=", r"/etc/ld\.so\.preload",
                     r"diamorphine", r"reptile", r"jynx",
                     r"insmod\s+.*\.ko", r"modprobe.*--force",
                     r"hidden.*(?:process|pid|port)", r"sys_call_table"],
        "severity": "critical", "weight": 40, "category": "Linux Rootkit",
        "desc": "Linux rootkit indicators detected", "mitre": "T1014",
    },
    "linux_cron_persistence": {
        "patterns": [r"crontab\s+-[el]", r"/etc/cron\.\w+/",
                     r"echo\s+.*>>?\s*/(?:var/spool/cron|etc/crontab)",
                     r"at\s+\d+:\d+\s+", r"/etc/anacrontab",
                     r"systemctl\s+(?:enable|start)\s+(?:cron|atd)"],
        "severity": "high", "weight": 25, "category": "Linux Cron Persistence",
        "desc": "Cron-based persistence mechanism detected", "mitre": "T1053.003",
    },
    "linux_privesc": {
        "patterns": [r"chmod\s+[ugo]*\+s\s+", r"find\s+.*-perm\s+.*4000",
                     r"sudo\s+.*NOPASSWD", r"pkexec",
                     r"setcap\s+.*cap_setuid", r"capabilities\s+.*cap_sys_admin",
                     r"linpeas|linenum|linux-exploit-suggester",
                     r"/etc/sudoers.*NOPASSWD"],
        "severity": "critical", "weight": 35, "category": "Linux Privilege Escalation",
        "desc": "Linux privilege escalation technique detected", "mitre": "T1548.001",
    },
    "cryptojacking": {
        "patterns": [r"stratum\+(?:tcp|ssl)://", r"xmrig", r"minerd",
                     r"cpuminer", r"cryptonight", r"monero.*pool",
                     r"hashrate", r"nanopool\.org", r"supportxmr\.com",
                     r"coinhive", r"coin-?hive"],
        "severity": "high", "weight": 25, "category": "Cryptojacking",
        "desc": "Cryptocurrency mining activity detected", "mitre": "T1496",
    },
    "supply_chain_attack": {
        "patterns": [r"dependency\s+confusion", r"typosquat",
                     r"npm\s+install.*--ignore-scripts\s*$",
                     r"pip\s+install\s+(?!-r).*(?:eval|exec|os\.)",
                     r"package.*(?:backdoor|malicious)", r"SolarWinds.*SUNBURST",
                     r"codecov.*bash\s+uploader"],
        "severity": "critical", "weight": 35, "category": "Supply Chain Attack",
        "desc": "Supply chain compromise indicators detected", "mitre": "T1195",
    },
    "cloud_iam_abuse": {
        "patterns": [r"CreateUser.*(?:admin|root)", r"AttachUserPolicy",
                     r"PutRolePolicy", r"CreateAccessKey",
                     r"AssumeRole.*(?:cross|external)", r"iam:PassRole",
                     r"CreateLoginProfile", r"UpdateLoginProfile"],
        "severity": "critical", "weight": 35, "category": "Cloud IAM Abuse",
        "desc": "Cloud IAM privilege escalation detected", "mitre": "T1098",
    },
    "cloud_storage_exfil": {
        "patterns": [r"PutBucketPolicy.*(?:public|AllUsers)", r"s3:GetObject.*wildcard",
                     r"PutBucketAcl.*public", r"storage\.objects\.(?:list|get).*bulk",
                     r"BlobContainerPublicAccessType", r"PutObjectAcl.*public-read"],
        "severity": "critical", "weight": 35, "category": "Cloud Storage Exfiltration",
        "desc": "Cloud storage public exposure or bulk exfiltration detected", "mitre": "T1530",
    },
    "api_bola": {
        "patterns": [r"(?:GET|POST|PUT|DELETE)\s+/api/.*(?:user|account)/\d+",
                     r"IDOR", r"broken.*object.*level.*auth",
                     r"(?:401|403).*(?:unauthorized|forbidden).*(?:repeated|multiple)"],
        "severity": "high", "weight": 25, "category": "API BOLA/IDOR",
        "desc": "Broken Object Level Authorization attempt detected", "mitre": "T1190",
    },
    "dns_tunneling": {
        "patterns": [r"dns.*tunnel", r"iodine", r"dnscat", r"dns2tcp",
                     r"TXT\s+query.*(?:base64|hex|[a-f0-9]{50,})",
                     r"dns.*(?:exfil|covert|channel)",
                     r"(?:query|request).*\.(?:dnscat|dns2tcp)\."],
        "severity": "high", "weight": 25, "category": "DNS Tunneling",
        "desc": "DNS tunneling or covert channel detected", "mitre": "T1071.004",
    },
    "dga_detection": {
        "patterns": [r"(?:[a-z]{2,4}\d{2,4}){3,}\.(?:com|net|org|xyz|top|info)",
                     r"(?:[bcdfghjklmnpqrstvwxz]{5,}|[aeiou]{5,})\.(?:com|net|org)",
                     r"domain.*generation.*algorithm",
                     r"DGA\s+detected"],
        "severity": "high", "weight": 25, "category": "DGA Detection",
        "desc": "Domain Generation Algorithm patterns detected", "mitre": "T1568.002",
    },
    "waf_bypass": {
        "patterns": [r"(?:url|double).*encod(?:e|ing).*(?:bypass|evasion)",
                     r"(?:null|unicode).*byte.*(?:injection|bypass)",
                     r"%(?:00|0a|0d|25|2e|2f|5c)",
                     r"HTTP\s+(?:parameter|header)\s+(?:pollution|smuggling)"],
        "severity": "high", "weight": 25, "category": "WAF Bypass",
        "desc": "Web Application Firewall bypass attempt detected", "mitre": "T1190",
    },
    "ssrf_attack": {
        "patterns": [r"(?:169\.254\.169\.254|metadata\.google)", r"(?:localhost|127\.0\.0\.1):\d+",
                     r"gopher://", r"file:///etc/",
                     r"SSRF", r"server.*side.*request.*forg"],
        "severity": "critical", "weight": 35, "category": "SSRF Attack",
        "desc": "Server-Side Request Forgery attempt detected", "mitre": "T1190",
    },
    "xxe_injection": {
        "patterns": [r"<!ENTITY\s+", r"<!DOCTYPE\s+.*ENTITY",
                     r"SYSTEM\s+\"(?:file|http|ftp)://",
                     r"XXE", r"xml.*external.*entity"],
        "severity": "critical", "weight": 35, "category": "XXE Injection",
        "desc": "XML External Entity injection attempt detected", "mitre": "T1190",
    },
    "deserialization_attack": {
        "patterns": [r"java\.lang\.Runtime.*exec", r"ObjectInputStream",
                     r"ysoserial", r"pickle\.loads", r"yaml\.(?:unsafe_)?load",
                     r"__reduce__", r"unserialize\(",
                     r"readObject\(\)", r"phpggc"],
        "severity": "critical", "weight": 35, "category": "Deserialization Attack",
        "desc": "Insecure deserialization attack detected", "mitre": "T1059",
    },
    "memory_injection": {
        "patterns": [r"VirtualAllocEx", r"WriteProcessMemory", r"NtMapViewOfSection",
                     r"process\s+hollowing", r"reflective.*(?:dll|injection)",
                     r"CreateRemoteThread", r"NtUnmapViewOfSection",
                     r"RtlCreateUserThread", r"QueueUserAPC"],
        "severity": "critical", "weight": 40, "category": "Memory Injection",
        "desc": "Process memory injection technique detected", "mitre": "T1055",
    },
    "boot_persistence": {
        "patterns": [r"bcdedit\s+/set", r"bootkit", r"MBR.*modif",
                     r"VBR.*tamper", r"bootsect\.exe",
                     r"EFI.*System.*Partition.*write",
                     r"bootmgr.*modif"],
        "severity": "critical", "weight": 40, "category": "Boot Persistence",
        "desc": "Boot-level persistence mechanism detected", "mitre": "T1542",
    },
    "firmware_attack": {
        "patterns": [r"UEFI.*(?:modif|tamper|implant)", r"firmware.*(?:backdoor|update.*forced)",
                     r"SPI.*flash.*write", r"BIOS.*(?:modif|flash|rootkit)",
                     r"ThinkPwn", r"LoJax"],
        "severity": "critical", "weight": 40, "category": "Firmware Attack",
        "desc": "Firmware-level attack indicators detected", "mitre": "T1542.001",
    },
    "keylogger": {
        "patterns": [r"SetWindowsHookEx.*WH_KEYBOARD", r"GetAsyncKeyState",
                     r"keylog", r"keystroke.*(?:log|capture|record)",
                     r"keyboard.*hook", r"GetKeyState\s*\("],
        "severity": "high", "weight": 25, "category": "Keylogger Activity",
        "desc": "Keylogger or keyboard capture detected", "mitre": "T1056.001",
    },
    "clipboard_hijack": {
        "patterns": [r"clipboard.*(?:hijack|monitor|replace)", r"SetClipboardData",
                     r"GetClipboardData", r"crypto.*(?:clipper|replace)",
                     r"(?:bitcoin|ethereum|monero).*(?:address|wallet).*(?:replace|swap)"],
        "severity": "high", "weight": 25, "category": "Clipboard Hijacking",
        "desc": "Clipboard monitoring or hijacking detected", "mitre": "T1115",
    },
    "screen_capture": {
        "patterns": [r"screenshot", r"screen\s*capture", r"PrintWindow",
                     r"BitBlt.*GetDC", r"CaptureScreen",
                     r"import\s+mss|from\s+mss", r"ImageGrab\.grab"],
        "severity": "medium", "weight": 15, "category": "Screen Capture",
        "desc": "Unauthorized screen capture activity detected", "mitre": "T1113",
    },
    "crypto_wallet_theft": {
        "patterns": [r"wallet\.dat", r"(?:bitcoin|ethereum|litecoin).*(?:wallet|keystore)",
                     r"electrum.*(?:wallet|seed)", r"metamask.*(?:vault|seed)",
                     r"(?:BIP39|mnemonic|seed\s+phrase).*(?:extract|steal|dump)"],
        "severity": "critical", "weight": 35, "category": "Crypto Wallet Theft",
        "desc": "Cryptocurrency wallet theft attempt detected", "mitre": "T1005",
    },
    "wifi_attack": {
        "patterns": [r"aircrack|aireplay|airodump", r"deauth.*attack",
                     r"evil\s*twin", r"karma\s+attack", r"hostapd.*fake",
                     r"wifiphisher", r"(?:WPA|WPA2|WEP).*crack"],
        "severity": "high", "weight": 25, "category": "WiFi Attack",
        "desc": "Wireless network attack detected", "mitre": "T1557",
    },
    "usb_abuse": {
        "patterns": [r"BadUSB", r"rubber\s*ducky", r"USB\s+Armory",
                     r"HID\s+(?:attack|injection|device)", r"teensy.*(?:attack|payload)",
                     r"bash\s+bunny", r"LAN\s+turtle"],
        "severity": "high", "weight": 25, "category": "USB Device Abuse",
        "desc": "Malicious USB device activity detected", "mitre": "T1200",
    },
    "email_compromise": {
        "patterns": [r"(?:business|email)\s+compromise", r"BEC",
                     r"New-InboxRule.*(?:delete|forward|redirect)",
                     r"Set-Mailbox.*(?:forward|redirect)",
                     r"mail.*rule.*(?:forward|delete).*(?:external|outside)"],
        "severity": "high", "weight": 25, "category": "Email Compromise",
        "desc": "Business email compromise indicators detected", "mitre": "T1114",
    },
    "zero_day_indicator": {
        "patterns": [r"heap\s*spray", r"(?:use.after.free|UAF)",
                     r"(?:buffer|stack)\s+overflow.*(?:exploit|crash)",
                     r"0[xX][0-9a-fA-F]{8}.*(?:crash|exception|violation)",
                     r"(?:SIGSEGV|SIGABRT|access\s+violation).*(?:repeated|exploit)"],
        "severity": "critical", "weight": 35, "category": "Zero-Day Indicators",
        "desc": "Potential zero-day exploitation indicators detected", "mitre": "T1203",
    },
    "fileless_malware": {
        "patterns": [r"AMSI.*(?:bypass|disable|patch)", r"amsi\.dll.*(?:patch|hook)",
                     r"Invoke-ReflectivePEInjection", r"(?:mshta|wscript|cscript).*(?:http|ftp)",
                     r"regsvr32\s+/s\s+/n\s+/u\s+/i:", r"rundll32.*javascript",
                     r"certutil\s+-urlcache\s+-split\s+-f",
                     r"bitsadmin\s+/transfer\s+"],
        "severity": "critical", "weight": 40, "category": "Fileless Malware",
        "desc": "Fileless malware or LOLBin abuse detected", "mitre": "T1059",
    },
    "dcsync_attack": {
        "patterns": [r"DCSync", r"DRS.*GetNCChanges", r"lsadump::dcsync",
                     r"(?:DS-Replication|Replicating\s+Directory\s+Changes)",
                     r"1131.*Directory.*Service.*Replication",
                     r"GetNCChanges.*request"],
        "severity": "critical", "weight": 40, "category": "DCSync Attack",
        "desc": "DCSync Active Directory replication attack detected", "mitre": "T1003.006",
    },
    "cloud_logging_tamper": {
        "patterns": [r"StopLogging", r"DeleteTrail", r"UpdateTrail.*IsLogging.*false",
                     r"DeleteFlowLogs", r"PutEventSelectors.*(?:ReadOnly|empty)",
                     r"SetDiagnosticSetting.*(?:delete|disable)",
                     r"google\.logging.*delete"],
        "severity": "critical", "weight": 35, "category": "Cloud Logging Tampering",
        "desc": "Cloud audit log tampering detected", "mitre": "T1562.008",
    },
    "linux_shell_escape": {
        "patterns": [r"python\s+-c\s+.*import\s+(?:os|pty|subprocess)",
                     r"perl\s+-e\s+.*(?:exec|system)",
                     r"ruby\s+-e\s+.*(?:exec|system|spawn)",
                     r"awk\s+.*system\s*\(", r"find\s+.*-exec\s+/bin/sh",
                     r"vi\s+.*:!sh", r"nmap\s+--interactive"],
        "severity": "high", "weight": 25, "category": "Linux Shell Escape",
        "desc": "Restricted shell escape technique detected", "mitre": "T1059.004",
    },
}


class LogAnalyzer:
    """
    Central analysis orchestrator that coordinates all detection modules.
    
    Supports multiple log formats, runs Sigma rules, regex patterns,
    YARA scans, and behavioral chains, then produces a unified
    threat assessment with scoring and MITRE ATT&CK mapping.
    """

    def __init__(self, filepath: str = None):
        """
        Initialize the analyzer.

        Args:
            filepath: Path to the log file to analyze.
        """
        self.filepath = Path(filepath) if filepath else None
        self.events: List[dict] = []
        self.findings: Dict[str, List[dict]] = defaultdict(list)
        self.timeline: List[dict] = []
        self.mitre_hits: Dict[str, int] = defaultdict(int)

        # Sub-engines
        self.sigma_engine = SigmaEngine()
        self.yara_engine = YaraEngine()
        self.ioc_extractor = IOCExtractor()
        self.correlation_engine = CorrelationEngine()
        self.behavioral_engine = BehavioralChainEngine()
        self.fp_suppressor = FalsePositiveSuppressor()

        # Counters
        self.ip_counter = Counter()
        self.user_counter = Counter()
        self.event_id_counter = Counter()

        # Metadata
        self.file_hashes = {}
        self.start_time = None
        self.end_time = None
        self.total_lines = 0
        self.sigma_rules_loaded = 0
        self.analysis_complete = False
        self.analysis_timestamp = None
        # Per-analysis Sigma scan context (regex budget + diagnostics). Created
        # fresh in ``analyze`` so concurrent analyses never share budget state.
        self.sigma_scan_context = None

    def load(self, filepath: str = None):
        """
        Load and parse log file using the appropriate parser.

        Args:
            filepath: Optional override for file path.
        """
        if filepath:
            self.filepath = Path(filepath)

        if not self.filepath or not self.filepath.exists():
            raise FileNotFoundError(f"Log file not found: {self.filepath}")

        logger.info(f"Loading log file: {self.filepath}")

        # Compute file hashes
        self.file_hashes = compute_file_hashes(str(self.filepath))

        # Auto-detect parser and parse
        parser = get_parser(str(self.filepath))
        self.events = parser.parse(str(self.filepath))
        self.total_lines = len(self.events)

        # Load Sigma rules
        self.sigma_rules_loaded = self.sigma_engine.load_rules()

        # Load YARA rules
        self.yara_engine.load_rules()

        logger.info(
            f"Loaded {self.total_lines} events | "
            f"MD5: {self.file_hashes.get('md5', 'N/A')} | "
            f"Sigma rules: {self.sigma_rules_loaded} | "
            f"YARA rules: {self.yara_engine.rule_count}"
        )

    def analyze(self) -> Dict:
        """
        Run full analysis pipeline on loaded events.

        Returns:
            Complete analysis results dictionary.
        """
        if not self.events:
            logger.warning("No events loaded — nothing to analyze.")
            return self.get_results()

        logger.info(f"Analyzing {len(self.events)} events...")

        # One isolated scan context per analysis enforces the regex budget and
        # collects diagnostics across every event.
        self.sigma_scan_context = (
            self.sigma_engine.new_scan_context()
            if self.sigma_engine.available
            else None
        )

        for event in self.events:
            self._analyze_event(event)

        # YARA scan on the input file (all formats, not just binaries, so
        # log files containing malware strings are also matched)
        if self.filepath and self.yara_engine.available and self.yara_engine.compiled_rules:
            try:
                self._register_yara_findings(self.yara_engine.scan_file(str(self.filepath)))
            except Exception as e:
                logger.debug(f"YARA scan failed for {self.filepath}: {e}")

        # Run correlation analysis
        self.correlation_engine.correlate(self.findings)

        # Run behavioral chain analysis
        self.behavioral_engine.add_events_from_findings(self.findings, self.timeline)
        self.behavioral_engine.analyze()

        # Apply FP suppression
        for category in list(self.findings.keys()):
            filtered, suppressed = self.fp_suppressor.filter_findings(self.findings[category])
            self.findings[category] = filtered

        self.analysis_complete = True
        self.analysis_timestamp = datetime.now(timezone.utc).isoformat()

        logger.info(
            f"Analysis complete: {sum(len(v) for v in self.findings.values())} findings | "
            f"{len(self.mitre_hits)} MITRE techniques | "
            f"{self.ioc_extractor.get_summary()['total_iocs']} IOCs"
        )

        return self.get_results()

    def _analyze_event(self, event: dict):
        """
        Analyze a single event against all detection rules.

        Args:
            event: Normalized event dictionary.
        """
        raw = event.get("raw", "")
        if not raw:
            return

        # Track IPs
        for ip in re.findall(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", raw):
            self.ip_counter[ip] += 1

        # Track usernames
        for user in re.findall(
            r"(?:user|username|account)[=: ]+([a-zA-Z0-9_\-\.]+)", raw, re.IGNORECASE
        ):
            self.user_counter[user] += 1

        # Track Event IDs
        eid = event.get("event_id", "")
        if eid:
            self.event_id_counter[eid] += 1

        # Track timestamps
        ts = event.get("timestamp", "")
        if ts:
            if not self.start_time:
                self.start_time = ts
            self.end_time = ts

        # IOC extraction
        self.ioc_extractor.extract_from_event(event)

        # Run builtin regex patterns
        raw_lower = raw.lower()
        for rule_id, rule in BUILTIN_PATTERNS.items():
            for pattern in rule["patterns"]:
                try:
                    if re.search(pattern, raw, re.IGNORECASE):
                        finding = {
                            "rule_id": rule_id,
                            "rule_type": "builtin",
                            "title": rule["category"],
                            "description": rule["desc"],
                            "severity": rule["severity"],
                            "weight": rule["weight"],
                            "mitre": rule.get("mitre", ""),
                            "line_number": event.get("line_number", 0),
                            "raw": raw[:500],
                            "timestamp": ts,
                            "matched_pattern": pattern,
                        }
                        self.findings[rule_id].append(finding)

                        if rule.get("mitre"):
                            self.mitre_hits[rule["mitre"]] += 1

                        self.timeline.append({
                            "timestamp": ts,
                            "category": rule_id,
                            "title": rule["category"],
                            "severity": rule["severity"],
                            "line_number": event.get("line_number", 0),
                            "raw": raw[:300],
                        })
                        break  # One match per rule per event
                except re.error:
                    continue

        # Run Sigma rules
        if self.sigma_engine.available and self.sigma_engine.rules:
            sigma_matches = self.sigma_engine.match_event(
                event, self.sigma_scan_context
            )
            for match in sigma_matches:
                finding = {
                    "rule_id": match.get("rule_id", ""),
                    "rule_type": "sigma",
                    "title": match["title"],
                    "description": match["description"],
                    "severity": match["level"],
                    "weight": match["weight"],
                    "mitre": ", ".join(match.get("mitre_techniques", [])),
                    "line_number": event.get("line_number", 0),
                    "raw": raw[:500],
                    "timestamp": ts,
                }
                cat_key = f"sigma_{match.get('rule_id', 'unknown')}"
                self.findings[cat_key].append(finding)

                for tech in match.get("mitre_techniques", []):
                    self.mitre_hits[tech] += 1

                self.timeline.append({
                    "timestamp": ts,
                    "category": cat_key,
                    "title": f"Sigma: {match['title']}",
                    "severity": match["level"],
                    "line_number": event.get("line_number", 0),
                    "raw": raw[:300],
                })

    def _register_yara_findings(self, matches: List[dict]):
        """
        Convert YARA scan matches into analyzer findings/timeline entries.

        Args:
            matches: Match dictionaries returned by the YARA engine.
        """
        weight_map = {"critical": 40, "high": 25, "medium": 15, "low": 5}
        for match in matches or []:
            rule_name = match.get("rule_name", "yara_rule")
            meta = match.get("meta", {}) or {}
            severity = match.get("severity", "medium")
            mitre = meta.get("mitre", meta.get("technique", ""))
            description = meta.get("description", meta.get("desc", "YARA rule matched"))

            finding = {
                "rule_id": rule_name,
                "rule_type": "yara",
                "title": f"YARA: {rule_name}",
                "description": description,
                "severity": severity,
                "weight": weight_map.get(severity, 15),
                "mitre": mitre,
                "line_number": 0,
                "raw": str(match.get("strings_matched", ""))[:500],
                "timestamp": "",
                "yara_rule_file": match.get("rule_file", ""),
            }
            cat_key = f"yara_{rule_name}"
            self.findings[cat_key].append(finding)

            if mitre:
                self.mitre_hits[mitre] += 1

            self.timeline.append({
                "timestamp": "",
                "category": cat_key,
                "title": finding["title"],
                "severity": severity,
                "line_number": 0,
                "raw": finding["raw"][:300],
            })

    def calculate_threat_score(self) -> int:
        """
        Calculate overall threat score (0-100).

        Returns:
            Threat score as integer percentage.
        """
        if not self.findings:
            return 0

        base_score = 0
        for category, finding_list in self.findings.items():
            if finding_list:
                max_weight = max(f.get("weight", 10) for f in finding_list)
                count_boost = min(len(finding_list) * 2, 20)
                base_score += max_weight + count_boost

        # Correlation boost
        base_score += self.correlation_engine.get_score_boost()

        # Behavioral chain boost
        for chain in self.behavioral_engine.triggered_chains:
            base_score += int(chain.get("confidence", 0.5) * 15)

        # Normalize to 0-100
        return min(100, max(0, int(base_score * 100 / max(base_score + 50, 1))))

    def get_threat_level(self, score: int = None) -> tuple:
        """
        Determine threat level from score.

        Args:
            score: Optional pre-calculated score.

        Returns:
            Tuple of (level_name, color).
        """
        if score is None:
            score = self.calculate_threat_score()

        if score >= 80:
            return "CRITICAL", "#ff1744"
        elif score >= 60:
            return "HIGH", "#ef4444"
        elif score >= 40:
            return "MEDIUM", "#f59e0b"
        elif score >= 20:
            return "LOW", "#3b82f6"
        else:
            return "INFORMATIONAL", "#64748b"

    def get_results(self) -> dict:
        """
        Get complete analysis results.

        Returns:
            Comprehensive results dictionary.
        """
        score = self.calculate_threat_score()
        level, level_color = self.get_threat_level(score)
        total_findings = sum(len(v) for v in self.findings.values())
        ioc_summary = self.ioc_extractor.get_summary()

        # Flatten all findings for display
        all_findings = []
        for category, finding_list in self.findings.items():
            for finding in finding_list:
                finding["category_key"] = category
                all_findings.append(finding)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "").lower(), 5))

        # Sort timeline
        self.timeline.sort(key=lambda t: t.get("timestamp", ""))

        sigma_diagnostics = (
            self.sigma_scan_context.summary()
            if self.sigma_scan_context is not None
            else {}
        )
        detection_complete = sigma_diagnostics.get("complete", True)

        return {
            "metadata": {
                "filepath": str(self.filepath) if self.filepath else "",
                "file_hashes": self.file_hashes,
                "total_events": self.total_lines,
                "analysis_timestamp": self.analysis_timestamp,
                "time_range": {"start": self.start_time, "end": self.end_time},
                "sigma_rules_loaded": self.sigma_rules_loaded,
                "yara_rules_loaded": self.yara_engine.rule_count,
                "detection_complete": detection_complete,
            },
            "threat_score": score,
            "threat_level": level,
            "threat_color": level_color,
            "summary": {
                "total_findings": total_findings,
                "critical": len([f for f in all_findings if f.get("severity", "").lower() == "critical"]),
                "high": len([f for f in all_findings if f.get("severity", "").lower() == "high"]),
                "medium": len([f for f in all_findings if f.get("severity", "").lower() == "medium"]),
                "low": len([f for f in all_findings if f.get("severity", "").lower() == "low"]),
                "unique_ips": len(self.ip_counter),
                "unique_users": len(self.user_counter),
                "mitre_techniques": len(self.mitre_hits),
                "total_iocs": ioc_summary["total_iocs"],
                "correlations": len(self.correlation_engine.triggered_correlations),
                "behavioral_chains": len(self.behavioral_engine.triggered_chains),
            },
            "findings": all_findings,
            "findings_by_category": {k: v for k, v in self.findings.items()},
            "timeline": self.timeline[:1000],  # Limit timeline entries
            "mitre_hits": dict(self.mitre_hits),
            "iocs": ioc_summary,
            "correlations": self.correlation_engine.get_summary(),
            "behavioral_chains": self.behavioral_engine.get_summary(),
            "top_ips": self.ip_counter.most_common(20),
            "top_users": self.user_counter.most_common(20),
            "top_event_ids": self.event_id_counter.most_common(20),
            "fp_stats": self.fp_suppressor.get_stats(),
            "yara": self.yara_engine.get_summary(),
            "sigma_stats": (
                self.sigma_engine.get_stats(self.sigma_scan_context)
                if self.sigma_engine.available
                else {}
            ),
            "sigma_diagnostics": sigma_diagnostics,
            "detection_complete": detection_complete,
        }

    def generate_report(self) -> str:
        """Generate a text-based analysis report."""
        results = self.get_results()
        score = results["threat_score"]
        level = results["threat_level"]

        lines = [
            "=" * 70,
            f"  0xSABRY ThreatScope V2 — Analysis Report",
            "=" * 70,
            f"  File: {results['metadata']['filepath']}",
            f"  MD5:  {results['metadata']['file_hashes'].get('md5', 'N/A')}",
            f"  Events Analyzed: {results['metadata']['total_events']:,}",
            f"  Time Range: {results['metadata']['time_range']['start']} → {results['metadata']['time_range']['end']}",
            "-" * 70,
            f"  THREAT SCORE: {score}% ({level})",
            f"  Findings: {results['summary']['total_findings']}",
            f"  Critical: {results['summary']['critical']} | High: {results['summary']['high']} | "
            f"Medium: {results['summary']['medium']} | Low: {results['summary']['low']}",
            f"  MITRE Techniques: {results['summary']['mitre_techniques']}",
            f"  IOCs Extracted: {results['summary']['total_iocs']}",
            f"  Correlations: {results['summary']['correlations']}",
            f"  Behavioral Chains: {results['summary']['behavioral_chains']}",
            "=" * 70,
        ]

        if not results.get("detection_complete", True):
            reasons = ", ".join(
                results.get("sigma_diagnostics", {}).get("reasons", [])
            ) or "unknown"
            lines.extend([
                "  *** INCOMPLETE DETECTION ***",
                "  Some Sigma evaluations could not be completed (regex budget,",
                "  timeout, oversized subject, or rule errors). The absence of a",
                "  finding does NOT mean the source is clean.",
                f"  Reasons: {reasons}",
                "=" * 70,
            ])

        # Top findings
        if results["findings"]:
            lines.append("\n  TOP FINDINGS:")
            lines.append("-" * 70)
            for f in results["findings"][:20]:
                sev = f.get("severity", "").upper()
                lines.append(f"  [{sev}] {f.get('title', 'Unknown')} — {f.get('description', '')}")
                if f.get("mitre"):
                    lines.append(f"         MITRE: {f['mitre']}")
                lines.append(f"         Line: {f.get('line_number', 'N/A')}")

        # Correlations
        if results["correlations"]["correlations"]:
            lines.append(f"\n  ATTACK CORRELATIONS:")
            lines.append("-" * 70)
            for c in results["correlations"]["correlations"]:
                lines.append(f"  ⚡ [{c['severity'].upper()}] {c['name']}")
                lines.append(f"     {c['description']}")

        return "\n".join(lines)
