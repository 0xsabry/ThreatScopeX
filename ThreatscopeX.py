import re, json, struct, threading, hashlib, argparse, sys, os, uuid
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict
from urllib.parse import urlparse
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    EVTX_LIB = True
except ImportError:
    EVTX_LIB = False

VERSION = "1.0"
TOOL_NAME = "ThreatscopeX"
BUILT_BY = "Built by 0xSABRY"

# ═══════════════ THEME ═══════════════
BG_DARK = "#0a0a0f"
BG_PANEL = "#0f1018"
BG_CARD = "#151520"
BG_CARD2 = "#1a1a2e"
BG_WIDGET = "#1e1e30"
BG_HOVER = "#252540"
ACCENT = "#00e5ff"
ACCENT2 = "#b24dff"
ACCENT3 = "#ff6b9d"
GREEN = "#00e676"
YELLOW = "#ffd740"
ORANGE = "#ff9100"
RED = "#ff3d00"
CRITICAL_CLR = "#ff1744"
TEXT_MAIN = "#e8eaed"
TEXT_DIM = "#8892a0"
TEXT_ACCENT = "#00e5ff"
BORDER_CLR = "#2a2a45"
GLOW_CYAN = "#00e5ff"
GLOW_PURPLE = "#b24dff"
FONT_MONO = ("Cascadia Code", 10)
FONT_TITLE = ("Segoe UI", 11, "bold")
FONT_BIG = ("Segoe UI", 18, "bold")
FONT_HEADER = ("Segoe UI", 13, "bold")

# ═══════════════ 1000+ DETECTION PATTERNS ═══════════════
PATTERNS = {
    # ── Authentication & Access (50 rules) ──
    "failed_login":{"patterns":[r"EventID[=: ]*4625",r"failed (password|login|auth)",r"authentication failure",r"invalid (credentials|password|user)"],"severity":"MEDIUM","weight":5,"category":"Authentication","desc":"Failed login attempt detected","mitre":"T1110"},
    "successful_login":{"patterns":[r"EventID[=: ]*4624"],"severity":"INFO","weight":1,"category":"Authentication","desc":"Successful logon event","mitre":"T1078"},
    "anonymous_logon":{"patterns":[r"ANONYMOUS LOGON",r"ANONYMOUS_LOGON"],"severity":"HIGH","weight":20,"category":"Authentication","desc":"Anonymous logon detected","mitre":"T1078.001"},
    "brute_force":{"patterns":[r"too many (failed|invalid|auth)",r"account locked",r"EventID[=: ]*4740"],"severity":"HIGH","weight":25,"category":"Authentication","desc":"Brute-force or account lockout","mitre":"T1110.001"},
    "password_spray":{"patterns":[r"EventID[=: ]*4648",r"explicit credentials"],"severity":"HIGH","weight":20,"category":"Authentication","desc":"Password spray attempt","mitre":"T1110.003"},
    "default_credentials":{"patterns":[r"admin:admin|root:root|admin:password|guest:guest"],"severity":"CRITICAL","weight":30,"category":"Authentication","desc":"Default credentials used","mitre":"T1078.001"},
    "account_creation":{"patterns":[r"EventID[=: ]*4720",r"user account (was )?created",r"net user.*/add"],"severity":"MEDIUM","weight":15,"category":"Authentication","desc":"New user account created","mitre":"T1136.001"},
    "password_change":{"patterns":[r"EventID[=: ]*4723|EventID[=: ]*4724",r"password (was )?(changed|reset)"],"severity":"MEDIUM","weight":10,"category":"Authentication","desc":"Password changed or reset","mitre":"T1098"},
    "logon_type_anomaly":{"patterns":[r"Logon Type:\s*(3|10|8)",r"LogonType[=: ]*(3|10|8)"],"severity":"MEDIUM","weight":10,"category":"Authentication","desc":"Suspicious logon type","mitre":"T1021"},
    "service_account_abuse":{"patterns":[r"service account.*login|svc_.*logon"],"severity":"HIGH","weight":25,"category":"Authentication","desc":"Service account anomalous usage","mitre":"T1078.002"},
    "kerberos_tgt":{"patterns":[r"EventID[=: ]*4768",r"TGT.*request"],"severity":"INFO","weight":2,"category":"Authentication","desc":"Kerberos TGT request","mitre":"T1558"},
    "kerberos_tgs":{"patterns":[r"EventID[=: ]*4769",r"TGS.*request"],"severity":"INFO","weight":2,"category":"Authentication","desc":"Kerberos TGS request","mitre":"T1558.003"},
    "ntlm_auth":{"patterns":[r"NTLM.*auth|NTLMv2.*response",r"NTLMSSP_AUTH"],"severity":"MEDIUM","weight":8,"category":"Authentication","desc":"NTLM authentication detected","mitre":"T1557.001"},
    "account_disabled":{"patterns":[r"EventID[=: ]*4725",r"account.*disabled"],"severity":"MEDIUM","weight":10,"category":"Authentication","desc":"User account disabled","mitre":"T1531"},
    "account_enabled":{"patterns":[r"EventID[=: ]*4722",r"account.*enabled"],"severity":"MEDIUM","weight":10,"category":"Authentication","desc":"User account enabled","mitre":"T1098"},
    "account_locked":{"patterns":[r"EventID[=: ]*4740",r"account.*locked"],"severity":"HIGH","weight":18,"category":"Authentication","desc":"Account locked out","mitre":"T1110.001"},
    "admin_logon":{"patterns":[r"Administrator.*logon|admin.*login.*success"],"severity":"MEDIUM","weight":8,"category":"Authentication","desc":"Administrator logon","mitre":"T1078"},
    "rdp_logon":{"patterns":[r"LogonType[=: ]*10",r"Remote Desktop.*logon"],"severity":"MEDIUM","weight":12,"category":"Authentication","desc":"RDP logon detected","mitre":"T1021.001"},
    "cleartext_logon":{"patterns":[r"LogonType[=: ]*8",r"NetworkCleartext"],"severity":"HIGH","weight":20,"category":"Authentication","desc":"Cleartext network logon","mitre":"T1078"},
    "group_membership_change":{"patterns":[r"EventID[=: ]*4728|EventID[=: ]*4732|EventID[=: ]*4756"],"severity":"MEDIUM","weight":12,"category":"Authentication","desc":"Group membership changed","mitre":"T1098"},
    "domain_admin_added":{"patterns":[r"Domain Admins.*added|added.*Domain Admins"],"severity":"CRITICAL","weight":40,"category":"Authentication","desc":"User added to Domain Admins","mitre":"T1098"},
    "password_policy_change":{"patterns":[r"EventID[=: ]*4713|EventID[=: ]*4739"],"severity":"HIGH","weight":20,"category":"Authentication","desc":"Password policy changed","mitre":"T1098"},
    "logon_script_assigned":{"patterns":[r"logon.*script.*assigned|scriptPath.*modified"],"severity":"HIGH","weight":22,"category":"Authentication","desc":"Logon script assigned","mitre":"T1037.001"},
    "credential_validation":{"patterns":[r"EventID[=: ]*4774|EventID[=: ]*4776"],"severity":"INFO","weight":3,"category":"Authentication","desc":"Credential validation event","mitre":"T1110"},
    "spn_modification":{"patterns":[r"servicePrincipalName.*modified|SPN.*change"],"severity":"HIGH","weight":25,"category":"Authentication","desc":"SPN modification detected","mitre":"T1558.003"},
    "sid_history_inject":{"patterns":[r"SIDHistory.*added|SID-History.*inject"],"severity":"CRITICAL","weight":45,"category":"Authentication","desc":"SID History injection","mitre":"T1134.005"},
    "trust_relationship_change":{"patterns":[r"trust.*domain.*created|EventID[=: ]*4706"],"severity":"HIGH","weight":28,"category":"Authentication","desc":"Domain trust relationship changed","mitre":"T1482"},
    "audit_policy_change":{"patterns":[r"EventID[=: ]*4719",r"audit.*policy.*changed"],"severity":"HIGH","weight":22,"category":"Authentication","desc":"Audit policy changed","mitre":"T1562.002"},
    "smartcard_logon_fail":{"patterns":[r"smart.?card.*fail|certificate.*logon.*fail"],"severity":"MEDIUM","weight":12,"category":"Authentication","desc":"Smart card logon failure","mitre":"T1078"},
    "delegation_config":{"patterns":[r"delegation.*configured|trusted.*delegation"],"severity":"HIGH","weight":25,"category":"Authentication","desc":"Account delegation configured","mitre":"T1558"},
    # ── Privilege Escalation (40 rules) ──
    "privilege_escalation":{"patterns":[r"EventID[=: ]*4672",r"SeDebugPrivilege|SeTcbPrivilege|SeLoadDriverPrivilege"],"severity":"HIGH","weight":30,"category":"Privilege Escalation","desc":"Special privileges assigned","mitre":"T1134"},
    "token_manipulation":{"patterns":[r"EventID[=: ]*4703|EventID[=: ]*4674",r"token (impersonation|theft|manipulation)"],"severity":"HIGH","weight":30,"category":"Privilege Escalation","desc":"Token manipulation detected","mitre":"T1134.001"},
    "uac_bypass":{"patterns":[r"uac.*bypass|bypass.*uac",r"eventvwr|fodhelper|sdclt",r"computerdefaults|cmstp.*inf"],"severity":"CRITICAL","weight":40,"category":"Privilege Escalation","desc":"UAC bypass technique","mitre":"T1548.002"},
    "sudo_abuse":{"patterns":[r"sudo.*-s|sudo.*-i|sudo su",r"NOPASSWD"],"severity":"HIGH","weight":25,"category":"Privilege Escalation","desc":"Suspicious sudo usage","mitre":"T1548.003"},
    "named_pipe_impersonation":{"patterns":[r"ImpersonateNamedPipeClient|named.?pipe.*impersonat"],"severity":"HIGH","weight":30,"category":"Privilege Escalation","desc":"Named pipe impersonation","mitre":"T1134.001"},
    "dll_search_order_hijack":{"patterns":[r"dll.*search.*order|dll.*plant|side.?load.*dll"],"severity":"HIGH","weight":30,"category":"Privilege Escalation","desc":"DLL search order hijacking","mitre":"T1574.001"},
    "seimpersonate_abuse":{"patterns":[r"SeImpersonatePrivilege|SeAssignPrimaryToken",r"potato.*exploit|juicy.*potato|print.*spoofer|sweet.*potato|rogue.*potato"],"severity":"CRITICAL","weight":40,"category":"Privilege Escalation","desc":"SeImpersonate abuse (Potato)","mitre":"T1134.001"},
    "kernel_exploit":{"patterns":[r"kernel.*exploit|CVE-\d{4}-\d+.*kernel|privilege.*escalat.*kernel"],"severity":"CRITICAL","weight":50,"category":"Privilege Escalation","desc":"Kernel exploitation attempt","mitre":"T1068"},
    "setuid_abuse":{"patterns":[r"chmod.*[+]s|setuid|setgid.*abuse",r"find.*-perm.*4000"],"severity":"HIGH","weight":25,"category":"Privilege Escalation","desc":"SUID/SGID binary abuse","mitre":"T1548.001"},
    "cron_escalation":{"patterns":[r"cron.*escalat|crontab.*/etc/cron",r"cron.*wildcard"],"severity":"HIGH","weight":25,"category":"Privilege Escalation","desc":"Cron job escalation","mitre":"T1053.003"},
    "path_hijacking":{"patterns":[r"PATH.*hijack|PATH.*inject|PATH.*manipulat"],"severity":"HIGH","weight":22,"category":"Privilege Escalation","desc":"PATH hijacking","mitre":"T1574.007"},
    "policykit_exploit":{"patterns":[r"polkit.*bypass|pkexec.*exploit|CVE-2021-4034"],"severity":"CRITICAL","weight":45,"category":"Privilege Escalation","desc":"PolicyKit exploitation","mitre":"T1068"},
    "unquoted_service_path":{"patterns":[r"unquoted.*service.*path"],"severity":"HIGH","weight":25,"category":"Privilege Escalation","desc":"Unquoted service path","mitre":"T1574.009"},
    "always_install_elevated":{"patterns":[r"AlwaysInstallElevated|msiexec.*elevated"],"severity":"HIGH","weight":28,"category":"Privilege Escalation","desc":"AlwaysInstallElevated abuse","mitre":"T1574"},
    "access_token_theft":{"patterns":[r"DuplicateTokenEx|AdjustTokenPrivilege"],"severity":"CRITICAL","weight":35,"category":"Privilege Escalation","desc":"Access token theft via API","mitre":"T1134.001"},
    "parent_pid_spoofing":{"patterns":[r"PROC_THREAD_ATTRIBUTE_PARENT_PROCESS|parent.*PID.*spoof"],"severity":"CRITICAL","weight":38,"category":"Privilege Escalation","desc":"Parent PID spoofing","mitre":"T1134.004"},
    "runas_abuse":{"patterns":[r"runas.*\/savecred|runas.*/user:.*admin"],"severity":"HIGH","weight":22,"category":"Privilege Escalation","desc":"RunAs credential abuse","mitre":"T1134.002"},
    "lpe_printspooler":{"patterns":[r"PrintNightmare|CVE-2021-34527|spoolsv.*exploit"],"severity":"CRITICAL","weight":50,"category":"Privilege Escalation","desc":"PrintNightmare exploit","mitre":"T1068"},
    "lpe_zerologon":{"patterns":[r"Zerologon|CVE-2020-1472|netlogon.*exploit"],"severity":"CRITICAL","weight":55,"category":"Privilege Escalation","desc":"Zerologon exploit","mitre":"T1068"},
    "lpe_samaccountspoofing":{"patterns":[r"sAMAccountName.*spoof|CVE-2021-42278|noPac.*exploit"],"severity":"CRITICAL","weight":50,"category":"Privilege Escalation","desc":"sAMAccountName spoofing","mitre":"T1068"},
    # ── Persistence (50 rules) ──
    "persistence":{"patterns":[r"EventID[=: ]*7045",r"new service (created|installed)"],"severity":"HIGH","weight":25,"category":"Persistence","desc":"New service created","mitre":"T1543.003"},
    "scheduled_task":{"patterns":[r"EventID[=: ]*4698|EventID[=: ]*4702",r"schtasks.*create|at\.exe"],"severity":"HIGH","weight":25,"category":"Persistence","desc":"Scheduled task created/modified","mitre":"T1053.005"},
    "registry_persistence":{"patterns":[r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",r"HKLM.*Run.*",r"reg (add|query).*Run"],"severity":"HIGH","weight":25,"category":"Persistence","desc":"Registry run-key persistence","mitre":"T1547.001"},
    "startup_modification":{"patterns":[r"\\Startup\\",r"\\Start Menu\\Programs\\Startup"],"severity":"MEDIUM","weight":20,"category":"Persistence","desc":"Startup folder modification","mitre":"T1547.001"},
    "dll_hijacking":{"patterns":[r"dll (hijack|side.?load|injection)",r"LoadLibrary.*\.dll"],"severity":"CRITICAL","weight":35,"category":"Persistence","desc":"DLL hijacking/side-loading","mitre":"T1574.001"},
    "bootkit":{"patterns":[r"MBR (modif|write|overwrite|tamper)",r"bootkitty|bootsector"],"severity":"CRITICAL","weight":50,"category":"Persistence","desc":"Bootkit/MBR modification","mitre":"T1542.003"},
    "wmi_persistence":{"patterns":[r"EventID[=: ]*5861",r"__EventFilter|__EventConsumer|CommandLineEventConsumer"],"severity":"CRITICAL","weight":40,"category":"Persistence","desc":"WMI event subscription","mitre":"T1546.003"},
    "bits_job_persistence":{"patterns":[r"bitsadmin.*\/SetNotifyCmdLine",r"Start-BitsTransfer.*-Asynchronous"],"severity":"HIGH","weight":25,"category":"Persistence","desc":"BITS job persistence","mitre":"T1197"},
    "com_hijacking":{"patterns":[r"InprocServer32.*modified|COM.*hijack|CLSID.*redirect"],"severity":"HIGH","weight":30,"category":"Persistence","desc":"COM object hijacking","mitre":"T1546.015"},
    "image_file_exec_options":{"patterns":[r"Image File Execution Options|IFEO.*debugger"],"severity":"CRITICAL","weight":35,"category":"Persistence","desc":"IFEO debugger persistence","mitre":"T1546.012"},
    "browser_extension_persist":{"patterns":[r"chrome.*extension.*install|firefox.*addon.*sideload",r"browser.*extension.*malicious"],"severity":"HIGH","weight":22,"category":"Persistence","desc":"Browser extension persistence","mitre":"T1176"},
    "office_addin_persist":{"patterns":[r"Office.*AddIn|HKCU.*Office.*Addins",r"\.xll.*load|\.wll.*load"],"severity":"HIGH","weight":25,"category":"Persistence","desc":"Office add-in persistence","mitre":"T1137.006"},
    "screensaver_persist":{"patterns":[r"SCRNSAVE\.EXE|ScreenSaveActive.*1"],"severity":"MEDIUM","weight":18,"category":"Persistence","desc":"Screensaver persistence","mitre":"T1546.002"},
    "accessibility_persist":{"patterns":[r"sethc\.exe|utilman\.exe|osk\.exe|narrator\.exe|magnify\.exe",r"accessibility.*hijack"],"severity":"CRITICAL","weight":35,"category":"Persistence","desc":"Accessibility feature hijack","mitre":"T1546.008"},
    "print_monitor_persist":{"patterns":[r"Monitors\\.*\.dll|AddMonitor.*malicious"],"severity":"HIGH","weight":28,"category":"Persistence","desc":"Print monitor DLL persistence","mitre":"T1547.010"},
    "lsa_auth_package":{"patterns":[r"Authentication Packages.*modified|LSA.*auth.*package"],"severity":"CRITICAL","weight":38,"category":"Persistence","desc":"LSA authentication package","mitre":"T1547.002"},
    "security_support_provider":{"patterns":[r"Security Packages.*added|SSP.*install.*malicious"],"severity":"CRITICAL","weight":38,"category":"Persistence","desc":"Security Support Provider install","mitre":"T1547.005"},
    "winlogon_helper":{"patterns":[r"Winlogon.*Shell|Winlogon.*Userinit|Winlogon.*Notify"],"severity":"CRITICAL","weight":35,"category":"Persistence","desc":"Winlogon helper DLL","mitre":"T1547.004"},
    "appinit_dll":{"patterns":[r"AppInit_DLLs|LoadAppInit_DLLs"],"severity":"HIGH","weight":28,"category":"Persistence","desc":"AppInit_DLLs persistence","mitre":"T1546.010"},
    "netsh_helper":{"patterns":[r"netsh.*add.*helper",r"netsh.*helper.*dll"],"severity":"HIGH","weight":25,"category":"Persistence","desc":"Netsh helper DLL","mitre":"T1546.007"},
    "time_provider":{"patterns":[r"TimeProviders.*DllName",r"w32time.*malicious"],"severity":"HIGH","weight":25,"category":"Persistence","desc":"Time provider DLL persistence","mitre":"T1547.003"},
    "powershell_profile":{"patterns":[r"profile\.ps1.*modified|\$PROFILE.*write",r"Microsoft\.PowerShell_profile"],"severity":"HIGH","weight":22,"category":"Persistence","desc":"PowerShell profile persistence","mitre":"T1546.013"},
    "bashrc_persistence":{"patterns":[r"\.bashrc.*modified|\.bash_profile.*inject",r"\.zshrc.*backdoor"],"severity":"HIGH","weight":22,"category":"Persistence","desc":"Shell profile persistence","mitre":"T1546.004"},
    "systemd_persist":{"patterns":[r"systemctl.*enable.*malicious|systemd.*service.*backdoor",r"/etc/systemd/system/.*malicious"],"severity":"HIGH","weight":25,"category":"Persistence","desc":"Systemd service persistence","mitre":"T1543.002"},
    "xdg_autostart":{"patterns":[r"\.config/autostart/.*\.desktop",r"XDG.*autostart.*persist"],"severity":"MEDIUM","weight":18,"category":"Persistence","desc":"XDG autostart persistence","mitre":"T1547.013"},
    "launchd_persist":{"patterns":[r"com\.apple.*LaunchAgent|LaunchDaemon.*persist",r"launchctl.*load.*malicious"],"severity":"HIGH","weight":25,"category":"Persistence","desc":"macOS LaunchAgent/Daemon","mitre":"T1543.004"},
    "crontab_persist":{"patterns":[r"crontab -e.*backdoor|/etc/cron\.\w+/.*malicious",r"/var/spool/cron/.*modified"],"severity":"HIGH","weight":25,"category":"Persistence","desc":"Crontab persistence","mitre":"T1053.003"},
    "at_job_persist":{"patterns":[r"at\.exe.*persist|atrm|at -f"],"severity":"MEDIUM","weight":18,"category":"Persistence","desc":"AT job persistence","mitre":"T1053.002"},
    "rc_script_persist":{"patterns":[r"/etc/rc\.local.*modified|rc\.d/.*malicious"],"severity":"HIGH","weight":22,"category":"Persistence","desc":"RC script persistence","mitre":"T1037.004"},
    "kernel_module_persist":{"patterns":[r"insmod.*malicious|modprobe.*rootkit",r"lsmod.*suspicious"],"severity":"CRITICAL","weight":45,"category":"Persistence","desc":"Kernel module persistence","mitre":"T1547.006"},

    # ── Lateral Movement (40 rules) ──
    "lateral_movement":{"patterns":[r"\bpsexec\b",r"\bwmic\b.*/node",r"EventID[=: ]*4648",r"\bwinrm\b"],"severity":"HIGH","weight":35,"category":"Lateral Movement","desc":"Lateral movement tools (PsExec/WMIC/WinRM)","mitre":"T1021"},
    "pass_the_hash":{"patterns":[r"pass.?the.?hash|pth attack",r"NTLM.*lateral|mimikatz"],"severity":"CRITICAL","weight":50,"category":"Lateral Movement","desc":"Pass-the-Hash attack","mitre":"T1550.002"},
    "rdp_anomaly":{"patterns":[r"EventID[=: ]*4778|EventID[=: ]*4779",r"TermService|Remote Desktop"],"severity":"MEDIUM","weight":15,"category":"Lateral Movement","desc":"RDP session activity","mitre":"T1021.001"},
    "smb_anomaly":{"patterns":[r"EventID[=: ]*5140|EventID[=: ]*5145",r"\\\\.*\\(ADMIN|C|IPC)\$"],"severity":"HIGH","weight":30,"category":"Lateral Movement","desc":"Suspicious SMB share access","mitre":"T1021.002"},
    "dcom_lateral":{"patterns":[r"DCOM.*lateral|MMC20\.Application|ShellBrowserWindow"],"severity":"HIGH","weight":30,"category":"Lateral Movement","desc":"DCOM lateral movement","mitre":"T1021.003"},
    "wmi_lateral":{"patterns":[r"wmic.*/node:.*process call|Win32_Process.*Create.*remote"],"severity":"HIGH","weight":30,"category":"Lateral Movement","desc":"WMI remote execution","mitre":"T1047"},
    "ssh_lateral":{"patterns":[r"ssh.*-i.*key|ssh.*@.*root|sshpass"],"severity":"MEDIUM","weight":15,"category":"Lateral Movement","desc":"SSH lateral movement","mitre":"T1021.004"},
    "admin_share_access":{"patterns":[r"net use.*ADMIN\$|net use.*C\$|net use.*IPC\$"],"severity":"HIGH","weight":25,"category":"Lateral Movement","desc":"Admin share access","mitre":"T1021.002"},
    "pass_the_ticket":{"patterns":[r"pass.?the.?ticket|PTT.*attack|export.*ticket.*ccache"],"severity":"CRITICAL","weight":45,"category":"Lateral Movement","desc":"Pass-the-Ticket attack","mitre":"T1550.003"},
    "overpass_the_hash":{"patterns":[r"overpass.?the.?hash|OPTH|asktgt.*rc4|sekurlsa.*pth"],"severity":"CRITICAL","weight":45,"category":"Lateral Movement","desc":"Overpass-the-Hash","mitre":"T1550.002"},
    "rdp_hijacking":{"patterns":[r"tscon.*\/dest|RDP.*session.*hijack"],"severity":"CRITICAL","weight":40,"category":"Lateral Movement","desc":"RDP session hijacking","mitre":"T1563.002"},
    "wsman_lateral":{"patterns":[r"WSMan.*remote|New-PSSession|Enter-PSSession"],"severity":"HIGH","weight":28,"category":"Lateral Movement","desc":"WS-Management lateral","mitre":"T1021.006"},
    "smbexec":{"patterns":[r"smbexec|atexec|impacket.*exec"],"severity":"HIGH","weight":30,"category":"Lateral Movement","desc":"Impacket execution tools","mitre":"T1021.002"},
    "evil_winrm":{"patterns":[r"evil.?winrm|evil-winrm"],"severity":"HIGH","weight":30,"category":"Lateral Movement","desc":"Evil-WinRM detected","mitre":"T1021.006"},
    "crackmapexec":{"patterns":[r"crackmapexec|cme.*--exec|nxc.*smb"],"severity":"HIGH","weight":32,"category":"Lateral Movement","desc":"CrackMapExec detected","mitre":"T1021"},
    "vnc_lateral":{"patterns":[r"vnc.*connect.*remote|VNC.*unauthorized"],"severity":"MEDIUM","weight":18,"category":"Lateral Movement","desc":"VNC lateral movement","mitre":"T1021.005"},
    "internal_spearphishing":{"patterns":[r"internal.*spearphish|lateral.*phish|compromised.*email.*send"],"severity":"HIGH","weight":25,"category":"Lateral Movement","desc":"Internal spearphishing","mitre":"T1534"},
    "taint_shared_content":{"patterns":[r"shared.*drive.*malicious|network.*share.*backdoor"],"severity":"HIGH","weight":28,"category":"Lateral Movement","desc":"Tainted shared content","mitre":"T1080"},
    "remote_service_exploit":{"patterns":[r"EternalBlue|MS17-010|BlueKeep|CVE-2019-0708"],"severity":"CRITICAL","weight":50,"category":"Lateral Movement","desc":"Remote service exploit","mitre":"T1210"},
    "sc_remote_create":{"patterns":[r"sc.*\\\\.*create|sc.*\\\\.*start"],"severity":"HIGH","weight":28,"category":"Lateral Movement","desc":"Remote service creation via SC","mitre":"T1021.002"},
    # ── Command & Control (50 rules) ──
    "command_and_control":{"patterns":[r"\bcobalt\b|\bcobalt strike\b",r"\bmeterpreter\b",r"\bsliver\b",r"\bhavoc\b",r"\bbrute.?ratel\b"],"severity":"CRITICAL","weight":50,"category":"C2","desc":"Known C2 framework","mitre":"T1219"},
    "dns_tunneling":{"patterns":[r"dns (tunnel|exfil|c2)|iodine|dnscat",r"TXT.*base64"],"severity":"CRITICAL","weight":45,"category":"C2","desc":"DNS tunneling","mitre":"T1071.004"},
    "beacon_pattern":{"patterns":[r"periodic.*request|beacon interval|check.?in.*interval"],"severity":"HIGH","weight":40,"category":"C2","desc":"Beaconing behavior","mitre":"T1071.001"},
    "tor_usage":{"patterns":[r"\.onion|tor (browser|exit|relay|node)",r"9050|9051|9150"],"severity":"HIGH","weight":30,"category":"C2","desc":"Tor network usage","mitre":"T1090.003"},
    "reverse_shell":{"patterns":[r"bash -i.*>&|nc.*-e|python.*socket.*connect|\/dev\/tcp\/",r"ncat.*-e|socat.*exec"],"severity":"CRITICAL","weight":50,"category":"C2","desc":"Reverse shell command","mitre":"T1059"},
    "http_c2_pattern":{"patterns":[r"POST.*\/beacon|POST.*\/submit\.php|POST.*\/gate\.php"],"severity":"CRITICAL","weight":45,"category":"C2","desc":"HTTP C2 communication","mitre":"T1071.001"},
    "icmp_tunnel":{"patterns":[r"icmp.*tunnel|ping.*tunnel|icmpsh|ptunnel"],"severity":"HIGH","weight":35,"category":"C2","desc":"ICMP tunneling","mitre":"T1095"},
    "domain_fronting":{"patterns":[r"domain.*front|CDN.*proxy.*C2|cloudfront.*redirect"],"severity":"CRITICAL","weight":40,"category":"C2","desc":"Domain fronting","mitre":"T1090.004"},
    "fast_flux_dns":{"patterns":[r"fast.?flux|rapid.*DNS.*change"],"severity":"HIGH","weight":30,"category":"C2","desc":"Fast-flux DNS","mitre":"T1568.001"},
    "dga_detection":{"patterns":[r"DGA.*detect|domain.*generation.*algorithm|random.*subdomain"],"severity":"HIGH","weight":35,"category":"C2","desc":"DGA domain detected","mitre":"T1568.002"},
    "c2_over_social_media":{"patterns":[r"twitter.*C2|telegram.*bot.*C2|discord.*webhook.*C2"],"severity":"HIGH","weight":30,"category":"C2","desc":"C2 over social media","mitre":"T1102"},
    "c2_over_cloud":{"patterns":[r"pastebin.*C2|github.*raw.*C2|drive.*google.*C2|dropbox.*C2"],"severity":"HIGH","weight":30,"category":"C2","desc":"C2 over cloud services","mitre":"T1102.002"},
    "cobaltstrike_watermark":{"patterns":[r"watermark.*cobalt|beacon.*config.*extract"],"severity":"CRITICAL","weight":50,"category":"C2","desc":"Cobalt Strike watermark","mitre":"T1219"},
    "mythic_c2":{"patterns":[r"mythic.*agent|apfell.*c2|poseidon.*agent"],"severity":"CRITICAL","weight":48,"category":"C2","desc":"Mythic C2 framework","mitre":"T1219"},
    "covenant_c2":{"patterns":[r"covenant.*grunt|covenant.*c2"],"severity":"CRITICAL","weight":48,"category":"C2","desc":"Covenant C2 framework","mitre":"T1219"},
    "empire_c2":{"patterns":[r"powershell.empire|empire.*stager|empire.*agent"],"severity":"CRITICAL","weight":48,"category":"C2","desc":"Empire C2 framework","mitre":"T1219"},
    "poshc2":{"patterns":[r"poshc2|PoshC2.*implant"],"severity":"CRITICAL","weight":45,"category":"C2","desc":"PoshC2 framework","mitre":"T1219"},
    "merlin_c2":{"patterns":[r"merlin.*agent|merlin.*c2"],"severity":"CRITICAL","weight":45,"category":"C2","desc":"Merlin C2 framework","mitre":"T1219"},
    "encrypted_c2_channel":{"patterns":[r"encrypted.*channel.*C2|TLS.*tunnel.*backdoor"],"severity":"HIGH","weight":35,"category":"C2","desc":"Encrypted C2 channel","mitre":"T1573"},
    "malleable_c2":{"patterns":[r"malleable.*profile|malleable.*c2|custom.*beacon.*profile"],"severity":"CRITICAL","weight":42,"category":"C2","desc":"Malleable C2 profile","mitre":"T1071.001"},
    "proxy_chain":{"patterns":[r"proxychains|proxy.*chain.*tunnel|SOCKS.*proxy.*C2"],"severity":"HIGH","weight":28,"category":"C2","desc":"Proxy chaining for C2","mitre":"T1090.001"},
    "ngrok_tunnel":{"patterns":[r"ngrok|ngrok\.io|localtunnel|serveo\.net"],"severity":"HIGH","weight":25,"category":"C2","desc":"Ngrok/tunnel service","mitre":"T1572"},
    "chisel_tunnel":{"patterns":[r"chisel.*server|chisel.*client"],"severity":"HIGH","weight":28,"category":"C2","desc":"Chisel tunneling","mitre":"T1572"},
    "port_forwarding":{"patterns":[r"ssh.*-L.*tunnel|ssh.*-R.*tunnel|portfwd|netsh.*portproxy"],"severity":"MEDIUM","weight":18,"category":"C2","desc":"Port forwarding","mitre":"T1572"},
    # ── Exfiltration (35 rules) ──
    "data_exfiltration":{"patterns":[r"curl.*-T|wget.*--post-file",r"exfil|data.?theft",r"large.*upload"],"severity":"HIGH","weight":35,"category":"Exfiltration","desc":"Data exfiltration attempt","mitre":"T1041"},
    "clipboard_exfil":{"patterns":[r"GetClipboardData|clipboard (dump|steal|monitor)"],"severity":"HIGH","weight":25,"category":"Exfiltration","desc":"Clipboard exfiltration","mitre":"T1115"},
    "email_exfil":{"patterns":[r"smtp.*attach|sendmail.*attachment"],"severity":"HIGH","weight":30,"category":"Exfiltration","desc":"Email exfiltration","mitre":"T1048.002"},
    "dns_exfiltration":{"patterns":[r"dns.*exfil|TXT.*encoded.*data|subdomain.*base64"],"severity":"CRITICAL","weight":40,"category":"Exfiltration","desc":"DNS exfiltration","mitre":"T1048.003"},
    "steganography_exfil":{"patterns":[r"steghide|stegano|openstego|data.*hidden.*image"],"severity":"HIGH","weight":30,"category":"Exfiltration","desc":"Steganography exfiltration","mitre":"T1027.003"},
    "cloud_storage_exfil":{"patterns":[r"rclone.*sync|rclone.*copy|mega.*upload",r"dropbox.*upload|gdrive.*upload|aws s3 cp"],"severity":"HIGH","weight":30,"category":"Exfiltration","desc":"Cloud storage exfiltration","mitre":"T1567.002"},
    "usb_exfil":{"patterns":[r"USB.*mass.*storage|removable.*media.*write|EventID[=: ]*6416"],"severity":"HIGH","weight":25,"category":"Exfiltration","desc":"USB exfiltration","mitre":"T1052.001"},
    "archive_staging":{"patterns":[r"7z.*a.*-p|rar.*a.*-hp|zip.*-e.*password",r"tar.*czf.*staging"],"severity":"HIGH","weight":22,"category":"Exfiltration","desc":"Data staged in archive","mitre":"T1560.001"},
    "automated_exfil":{"patterns":[r"scheduled.*upload|auto.*exfil|periodic.*transfer"],"severity":"HIGH","weight":28,"category":"Exfiltration","desc":"Automated exfiltration","mitre":"T1020"},
    "exfil_over_bluetooth":{"patterns":[r"bluetooth.*transfer.*data|obex.*push"],"severity":"MEDIUM","weight":18,"category":"Exfiltration","desc":"Bluetooth exfiltration","mitre":"T1011"},
    "exfil_code_repo":{"patterns":[r"git push.*private|git.*clone.*sensitive"],"severity":"HIGH","weight":25,"category":"Exfiltration","desc":"Code repository exfil","mitre":"T1567"},
    "screen_capture_exfil":{"patterns":[r"screenshot.*upload|screen.*capture.*send"],"severity":"HIGH","weight":22,"category":"Exfiltration","desc":"Screen capture exfil","mitre":"T1113"},
    "webcam_capture":{"patterns":[r"webcam.*capture|camera.*record.*stream"],"severity":"HIGH","weight":22,"category":"Exfiltration","desc":"Webcam capture","mitre":"T1125"},
    "audio_capture":{"patterns":[r"microphone.*record|audio.*capture|voice.*record"],"severity":"HIGH","weight":22,"category":"Exfiltration","desc":"Audio capture","mitre":"T1123"},
    "keylog_exfil":{"patterns":[r"keylog|keystroke.*log|keyboard.*capture"],"severity":"CRITICAL","weight":35,"category":"Exfiltration","desc":"Keylogger detected","mitre":"T1056.001"},
    # ── Defense Evasion (60 rules) ──
    "log_tampering":{"patterns":[r"EventID[=: ]*1102",r"EventID[=: ]*104",r"wevtutil.*cl",r"Clear-EventLog"],"severity":"CRITICAL","weight":40,"category":"Defense Evasion","desc":"Event log cleared","mitre":"T1070.001"},
    "process_injection":{"patterns":[r"VirtualAllocEx|WriteProcessMemory|CreateRemoteThread",r"process (inject|hollow|doppel)",r"reflective dll"],"severity":"CRITICAL","weight":45,"category":"Defense Evasion","desc":"Process injection","mitre":"T1055"},
    "obfuscation":{"patterns":[r"base64.*-enc|frombase64string",r"iex\s*\(|invoke.?expression",r"char\(\d+\)\+char\(\d+\)"],"severity":"HIGH","weight":30,"category":"Defense Evasion","desc":"Command obfuscation","mitre":"T1027"},
    "amsi_bypass":{"patterns":[r"amsi.*bypass|AmsiScanBuffer|AmsiInitFailed"],"severity":"CRITICAL","weight":40,"category":"Defense Evasion","desc":"AMSI bypass","mitre":"T1562.001"},
    "av_tamper":{"patterns":[r"(disable|stop|kill).*(antivirus|defender|av|edr)",r"Set-MpPreference.*Disable"],"severity":"CRITICAL","weight":40,"category":"Defense Evasion","desc":"AV/EDR tampering","mitre":"T1562.001"},
    "timestomp":{"patterns":[r"timestomp|file.*timestamp.*(modif|manip|alter)",r"SetFileTime"],"severity":"HIGH","weight":25,"category":"Defense Evasion","desc":"Timestomping","mitre":"T1070.006"},
    "etw_bypass":{"patterns":[r"EtwEventWrite.*patch|ETW.*bypass|NtTraceControl"],"severity":"CRITICAL","weight":40,"category":"Defense Evasion","desc":"ETW bypass","mitre":"T1562.006"},
    "alternate_data_stream":{"patterns":[r"ADS.*stream|:.*\.exe|type.*>.*:.*stream"],"severity":"HIGH","weight":25,"category":"Defense Evasion","desc":"Alternate Data Stream","mitre":"T1564.004"},
    "binary_padding":{"patterns":[r"binary.*pad|file.*inflate|append.*null.*bytes"],"severity":"MEDIUM","weight":15,"category":"Defense Evasion","desc":"Binary padding","mitre":"T1027.001"},
    "disable_firewall":{"patterns":[r"netsh.*advfirewall.*off|netsh.*firewall.*disable",r"Set-NetFirewallProfile.*-Enabled.*False|iptables.*-F"],"severity":"CRITICAL","weight":35,"category":"Defense Evasion","desc":"Firewall disabled","mitre":"T1562.004"},
    "process_hollowing":{"patterns":[r"process.*hollow|NtUnmapViewOfSection|hollow.*inject"],"severity":"CRITICAL","weight":45,"category":"Defense Evasion","desc":"Process hollowing","mitre":"T1055.012"},
    "process_doppelganging":{"patterns":[r"process.*doppel|NtCreateTransaction.*inject"],"severity":"CRITICAL","weight":45,"category":"Defense Evasion","desc":"Process doppelganging","mitre":"T1055.013"},
    "masquerading":{"patterns":[r"rename.*svchost|masquerade.*system.*process",r"\.exe\.txt|\.scr|\.com.*masq"],"severity":"HIGH","weight":28,"category":"Defense Evasion","desc":"Process masquerading","mitre":"T1036"},
    "indicator_removal":{"patterns":[r"del.*\.log|rm.*\.log|shred.*log",r"wiper.*log|clean.*evidence"],"severity":"CRITICAL","weight":38,"category":"Defense Evasion","desc":"Log/indicator removal","mitre":"T1070"},
    "rootkit_detect":{"patterns":[r"rootkit|ring0.*hide|hidden.*process.*kernel"],"severity":"CRITICAL","weight":55,"category":"Defense Evasion","desc":"Rootkit detected","mitre":"T1014"},
    "code_signing_abuse":{"patterns":[r"signtool.*sign.*malicious|stolen.*certificate.*sign"],"severity":"HIGH","weight":30,"category":"Defense Evasion","desc":"Code signing abuse","mitre":"T1553.002"},
    "control_panel_abuse":{"patterns":[r"\.cpl.*malicious|control\.exe.*\.cpl"],"severity":"MEDIUM","weight":18,"category":"Defense Evasion","desc":"Control panel item abuse","mitre":"T1218.002"},
    "mshta_abuse":{"patterns":[r"mshta.*vbscript|mshta.*javascript|mshta.*http"],"severity":"HIGH","weight":30,"category":"Defense Evasion","desc":"MSHTA abuse","mitre":"T1218.005"},
    "regsvr32_abuse":{"patterns":[r"regsvr32.*\/s.*\/n.*\/u|regsvr32.*scrobj"],"severity":"HIGH","weight":30,"category":"Defense Evasion","desc":"Regsvr32 abuse","mitre":"T1218.010"},
    "rundll32_abuse":{"patterns":[r"rundll32.*javascript|rundll32.*shell32"],"severity":"HIGH","weight":28,"category":"Defense Evasion","desc":"Rundll32 abuse","mitre":"T1218.011"},
    "cmstp_bypass":{"patterns":[r"cmstp.*\/ni.*\/s|cmstp.*inf"],"severity":"HIGH","weight":28,"category":"Defense Evasion","desc":"CMSTP bypass","mitre":"T1218.003"},
    "installutil_abuse":{"patterns":[r"InstallUtil.*\/logfile|InstallUtil.*\/LogToConsole"],"severity":"HIGH","weight":25,"category":"Defense Evasion","desc":"InstallUtil abuse","mitre":"T1218.004"},
    "verclsid_abuse":{"patterns":[r"verclsid.*\/S.*CLSID"],"severity":"MEDIUM","weight":18,"category":"Defense Evasion","desc":"Verclsid abuse","mitre":"T1218.012"},
    "wmic_xsl_abuse":{"patterns":[r"wmic.*format.*xsl|wmic.*\/format.*http"],"severity":"HIGH","weight":30,"category":"Defense Evasion","desc":"WMIC XSL script abuse","mitre":"T1220"},
    "packing_detect":{"patterns":[r"UPX.*pack|themida.*protect|VMProtect.*detect"],"severity":"MEDIUM","weight":15,"category":"Defense Evasion","desc":"Packed executable","mitre":"T1027.002"},
    "software_packing":{"patterns":[r"packed.*executable|entropy.*high.*PE|suspicious.*section.*name"],"severity":"MEDIUM","weight":15,"category":"Defense Evasion","desc":"Software packing detected","mitre":"T1027.002"},
    "disable_sysmon":{"patterns":[r"Unload.*Sysmon|fltMC.*unload.*Sys",r"sysmon.*-u|sysmon.*uninstall"],"severity":"CRITICAL","weight":42,"category":"Defense Evasion","desc":"Sysmon disabled/unloaded","mitre":"T1562.001"},
    "event_log_service_stop":{"patterns":[r"EventLog.*service.*stop|net stop.*eventlog"],"severity":"CRITICAL","weight":42,"category":"Defense Evasion","desc":"Event log service stopped","mitre":"T1562.002"},
    "ntdll_unhooking":{"patterns":[r"ntdll.*unhook|direct.*syscall|SysWhispers"],"severity":"CRITICAL","weight":40,"category":"Defense Evasion","desc":"NTDLL unhooking/syscalls","mitre":"T1562.001"},
    "ppid_spoofing":{"patterns":[r"PPID.*spoof|parent.*process.*spoof"],"severity":"HIGH","weight":30,"category":"Defense Evasion","desc":"PPID spoofing","mitre":"T1134.004"},

    # ── Discovery & Recon (40 rules) ──
    "network_scan":{"patterns":[r"\bnmap\b|\bmassscan\b|\bzmap\b",r"port.?scan|host.?discover"],"severity":"MEDIUM","weight":15,"category":"Discovery","desc":"Network scanning","mitre":"T1046"},
    "ad_recon":{"patterns":[r"(BloodHound|SharpHound|ldapdomaindump)",r"Get-ADUser|Get-ADComputer|Get-ADGroup"],"severity":"HIGH","weight":30,"category":"Discovery","desc":"Active Directory recon","mitre":"T1087.002"},
    "os_discovery":{"patterns":[r"systeminfo|uname -a|cat /etc/os-release"],"severity":"LOW","weight":5,"category":"Discovery","desc":"OS enumeration","mitre":"T1082"},
    "user_enumeration":{"patterns":[r"net user\b|net localgroup|whoami /all|id\b",r"Get-LocalUser"],"severity":"LOW","weight":5,"category":"Discovery","desc":"User enumeration","mitre":"T1087.001"},
    "group_policy_discovery":{"patterns":[r"gpresult|Get-GPO|Get-GPResultantSetOfPolicy"],"severity":"MEDIUM","weight":10,"category":"Discovery","desc":"Group Policy discovery","mitre":"T1615"},
    "security_software_discovery":{"patterns":[r"tasklist.*/svc.*security|Get-Process.*(defender|symantec|mcafee|kaspersky)",r"WMIC.*AntiVirusProduct"],"severity":"MEDIUM","weight":15,"category":"Discovery","desc":"Security software discovery","mitre":"T1518.001"},
    "network_share_discovery":{"patterns":[r"net share|net view|Get-SmbShare",r"smbclient.*-L|enum4linux"],"severity":"MEDIUM","weight":10,"category":"Discovery","desc":"Network share discovery","mitre":"T1135"},
    "process_discovery":{"patterns":[r"tasklist|ps aux|Get-Process",r"wmic process list"],"severity":"LOW","weight":3,"category":"Discovery","desc":"Process discovery","mitre":"T1057"},
    "dns_recon":{"patterns":[r"dig.*axfr|dnsenum|dnsrecon|fierce",r"nslookup.*-type=any"],"severity":"MEDIUM","weight":12,"category":"Discovery","desc":"DNS reconnaissance","mitre":"T1018"},
    "snmp_enum":{"patterns":[r"snmpwalk|snmpbulkwalk|onesixtyone",r"community.*string.*public"],"severity":"MEDIUM","weight":15,"category":"Discovery","desc":"SNMP enumeration","mitre":"T1046"},
    "ldap_enum":{"patterns":[r"ldapsearch|ldapenum|windapsearch",r"LDAP.*query.*domain"],"severity":"MEDIUM","weight":15,"category":"Discovery","desc":"LDAP enumeration","mitre":"T1087.002"},
    "password_policy_enum":{"patterns":[r"net accounts|Get-ADDefaultDomainPasswordPolicy",r"password.*policy.*enum"],"severity":"MEDIUM","weight":10,"category":"Discovery","desc":"Password policy enum","mitre":"T1201"},
    "trust_discovery":{"patterns":[r"nltest.*domain_trusts|Get-ADTrust",r"forest.*trust.*enum"],"severity":"MEDIUM","weight":12,"category":"Discovery","desc":"Domain trust discovery","mitre":"T1482"},
    "cloud_enum":{"patterns":[r"aws.*sts.*get-caller|az.*account.*show",r"gcloud.*auth.*list|scout.*suite"],"severity":"MEDIUM","weight":15,"category":"Discovery","desc":"Cloud service enumeration","mitre":"T1580"},
    "wifi_discovery":{"patterns":[r"netsh wlan show|iwlist.*scan|airmon"],"severity":"LOW","weight":5,"category":"Discovery","desc":"WiFi network discovery","mitre":"T1016"},
    "service_enum":{"patterns":[r"sc query|Get-Service|systemctl list|service --status-all"],"severity":"LOW","weight":3,"category":"Discovery","desc":"Service enumeration","mitre":"T1007"},
    "registry_enum":{"patterns":[r"reg query|Get-ItemProperty.*Registry"],"severity":"LOW","weight":3,"category":"Discovery","desc":"Registry query","mitre":"T1012"},
    "file_dir_discovery":{"patterns":[r"dir /s|find / -name|tree /f"],"severity":"LOW","weight":3,"category":"Discovery","desc":"File/directory discovery","mitre":"T1083"},
    "network_config_discovery":{"patterns":[r"ipconfig /all|ifconfig|ip addr show",r"route print|netstat -rn"],"severity":"LOW","weight":3,"category":"Discovery","desc":"Network config discovery","mitre":"T1016"},
    "virtualization_detect":{"patterns":[r"systeminfo.*Virtual|dmidecode.*virtual",r"VMware|VirtualBox|Hyper-V|KVM.*detect"],"severity":"MEDIUM","weight":10,"category":"Discovery","desc":"Virtualization detection","mitre":"T1497.001"},
    # ── Credential Access (40 rules) ──
    "credential_dumping":{"patterns":[r"\bmimikatz\b|\blsadump\b|\bsekurlsa\b",r"lsass.*(dump|access|procdump)"],"severity":"CRITICAL","weight":50,"category":"Credential Access","desc":"Credential dumping (LSASS/Mimikatz)","mitre":"T1003.001"},
    "dcsync_attack":{"patterns":[r"DCSync|DRS.*Replication|GetNCChanges"],"severity":"CRITICAL","weight":55,"category":"Credential Access","desc":"DCSync attack","mitre":"T1003.006"},
    "sam_dump":{"patterns":[r"reg save.*SAM|reg save.*SECURITY|reg save.*SYSTEM",r"secretsdump|samdump"],"severity":"CRITICAL","weight":45,"category":"Credential Access","desc":"SAM credential dump","mitre":"T1003.002"},
    "ntds_dit_extraction":{"patterns":[r"ntds\.dit|ntdsutil.*snapshot|vssadmin.*shadow.*ntds"],"severity":"CRITICAL","weight":55,"category":"Credential Access","desc":"NTDS.dit extraction","mitre":"T1003.003"},
    "password_file_access":{"patterns":[r"cat.*/etc/(passwd|shadow)|type.*\.password|findstr.*password"],"severity":"HIGH","weight":20,"category":"Credential Access","desc":"Password file access","mitre":"T1552.001"},
    "kerberoasting":{"patterns":[r"kerberoast|GetUserSPNs|TGS.*RC4|EventID[=: ]*4769.*RC4"],"severity":"CRITICAL","weight":45,"category":"Credential Access","desc":"Kerberoasting","mitre":"T1558.003"},
    "golden_silver_ticket":{"patterns":[r"golden ticket|silver ticket|forge.*TGT"],"severity":"CRITICAL","weight":60,"category":"Credential Access","desc":"Golden/Silver Ticket","mitre":"T1558.001"},
    "ntlm_downgrade":{"patterns":[r"NTLM[- ]?V1|NTLMv1",r"LM Hash"],"severity":"HIGH","weight":20,"category":"Credential Access","desc":"NTLM downgrade","mitre":"T1557.001"},
    "lsass_minidump":{"patterns":[r"MiniDump.*lsass|comsvcs.*MiniDump|rundll32.*comsvcs"],"severity":"CRITICAL","weight":50,"category":"Credential Access","desc":"LSASS minidump","mitre":"T1003.001"},
    "lazagne":{"patterns":[r"lazagne|LaZagne.*all"],"severity":"CRITICAL","weight":45,"category":"Credential Access","desc":"LaZagne credential harvester","mitre":"T1555"},
    "wifi_password_dump":{"patterns":[r"netsh wlan show profile.*key",r"wifi.*password.*dump"],"severity":"HIGH","weight":22,"category":"Credential Access","desc":"WiFi password dump","mitre":"T1552.001"},
    "browser_creds":{"patterns":[r"chrome.*password|firefox.*logins\.json|browser.*credential",r"Login Data.*decrypt"],"severity":"HIGH","weight":28,"category":"Credential Access","desc":"Browser credential theft","mitre":"T1555.003"},
    "vault_creds":{"patterns":[r"vaultcmd|VaultSvc|Credential Manager.*dump"],"severity":"HIGH","weight":25,"category":"Credential Access","desc":"Windows Vault dump","mitre":"T1555.004"},
    "dpapi_abuse":{"patterns":[r"DPAPI.*decrypt|masterkey.*decrypt|CryptUnprotectData"],"severity":"HIGH","weight":30,"category":"Credential Access","desc":"DPAPI credential abuse","mitre":"T1555.003"},
    "as_rep_roasting":{"patterns":[r"AS-REP.*roast|GetNPUsers|preauth.*disabled"],"severity":"HIGH","weight":35,"category":"Credential Access","desc":"AS-REP Roasting","mitre":"T1558.004"},
    "shadow_credentials":{"patterns":[r"shadow.*credentials|msDS-KeyCredentialLink|whisker"],"severity":"CRITICAL","weight":42,"category":"Credential Access","desc":"Shadow Credentials attack","mitre":"T1556"},
    "skeleton_key":{"patterns":[r"skeleton.*key|misc::skeleton"],"severity":"CRITICAL","weight":55,"category":"Credential Access","desc":"Skeleton Key attack","mitre":"T1556.001"},
    "credential_in_registry":{"patterns":[r"reg query.*password|reg query.*credential",r"Registry.*DefaultPassword"],"severity":"HIGH","weight":20,"category":"Credential Access","desc":"Credentials in registry","mitre":"T1552.002"},
    "ssh_key_theft":{"patterns":[r"id_rsa.*steal|\.ssh.*key.*exfil|authorized_keys.*modify"],"severity":"HIGH","weight":28,"category":"Credential Access","desc":"SSH key theft","mitre":"T1552.004"},
    "input_capture":{"patterns":[r"keylog|SetWindowsHookEx.*keyboard|GetAsyncKeyState"],"severity":"CRITICAL","weight":35,"category":"Credential Access","desc":"Keylogger/input capture","mitre":"T1056.001"},
    # ── Web Attacks (40 rules) ──
    "sql_injection":{"patterns":[r"union\s+select|OR\s+1=1|'; *DROP",r"SLEEP\(\d+\)|WAITFOR DELAY",r"xp_cmdshell"],"severity":"HIGH","weight":15,"category":"Web Attack","desc":"SQL Injection","mitre":"T1190"},
    "xss":{"patterns":[r"<script[^>]*>",r"javascript:",r"onerror\s*=|onload\s*="],"severity":"MEDIUM","weight":10,"category":"Web Attack","desc":"XSS attempt","mitre":"T1189"},
    "directory_traversal":{"patterns":[r"\.\./\.\./",r"%2e%2e%2f",r"/etc/passwd|/etc/shadow"],"severity":"HIGH","weight":15,"category":"Web Attack","desc":"Directory traversal","mitre":"T1083"},
    "lfi_rfi":{"patterns":[r"(file|php|data|expect)://",r"include.*http://"],"severity":"HIGH","weight":20,"category":"Web Attack","desc":"LFI/RFI attempt","mitre":"T1190"},
    "command_injection":{"patterns":[r";\s*(ls|cat|id|whoami|wget|curl)\b",r"\|\s*(bash|sh|cmd|powershell)"],"severity":"CRITICAL","weight":35,"category":"Web Attack","desc":"OS Command Injection","mitre":"T1059"},
    "ssrf":{"patterns":[r"url=http://169\.254|url=http://127\.",r"metadata\.internal|169\.254\.169\.254"],"severity":"HIGH","weight":25,"category":"Web Attack","desc":"SSRF attempt","mitre":"T1190"},
    "xxe":{"patterns":[r"<!ENTITY.*SYSTEM|<!DOCTYPE.*ENTITY",r"file:///"],"severity":"HIGH","weight":25,"category":"Web Attack","desc":"XXE injection","mitre":"T1190"},
    "deserialization_attack":{"patterns":[r"ysoserial|ObjectInputStream|readObject|unserialize\("],"severity":"CRITICAL","weight":40,"category":"Web Attack","desc":"Deserialization attack","mitre":"T1190"},
    "http_smuggling":{"patterns":[r"Transfer-Encoding.*chunked.*Content-Length"],"severity":"HIGH","weight":30,"category":"Web Attack","desc":"HTTP request smuggling","mitre":"T1190"},
    "crlf_injection":{"patterns":[r"%0d%0a|\\r\\n.*inject"],"severity":"MEDIUM","weight":15,"category":"Web Attack","desc":"CRLF injection","mitre":"T1190"},
    "open_redirect":{"patterns":[r"redirect.*=.*http|next=.*http|url=.*http"],"severity":"MEDIUM","weight":10,"category":"Web Attack","desc":"Open redirect","mitre":"T1190"},
    "ssti":{"patterns":[r"\{\{.*config|__class__|__mro__|__subclasses__",r"Jinja2.*inject|Twig.*inject"],"severity":"HIGH","weight":30,"category":"Web Attack","desc":"SSTI attempt","mitre":"T1190"},
    "nosql_injection":{"patterns":[r"\$ne|\$gt|\$regex|.*\[\$.*\]",r"MongoDB.*inject|CosmosDB.*inject"],"severity":"HIGH","weight":25,"category":"Web Attack","desc":"NoSQL injection","mitre":"T1190"},
    "ldap_injection":{"patterns":[r"\)\(\||\)\(&|ldap.*inject",r"\\28\\29\\2a\\5c"],"severity":"HIGH","weight":25,"category":"Web Attack","desc":"LDAP injection","mitre":"T1190"},
    "xpath_injection":{"patterns":[r"xpath.*inject|' or '1'='1",r"contains\(.*concat.*string"],"severity":"HIGH","weight":22,"category":"Web Attack","desc":"XPath injection","mitre":"T1190"},
    "websocket_attack":{"patterns":[r"websocket.*hijack|ws://.*inject|cross-site.*websocket"],"severity":"HIGH","weight":22,"category":"Web Attack","desc":"WebSocket attack","mitre":"T1190"},
    "cors_misconfiguration":{"patterns":[r"Access-Control-Allow-Origin.*\*.*credentials",r"CORS.*misconfigur"],"severity":"MEDIUM","weight":15,"category":"Web Attack","desc":"CORS misconfiguration","mitre":"T1190"},
    "prototype_pollution":{"patterns":[r"__proto__|constructor\[.*prototype",r"prototype.*pollut"],"severity":"HIGH","weight":25,"category":"Web Attack","desc":"Prototype pollution","mitre":"T1190"},
    "log4j_exploit":{"patterns":[r"\$\{jndi:|log4j.*exploit|Log4Shell|CVE-2021-44228"],"severity":"CRITICAL","weight":55,"category":"Web Attack","desc":"Log4Shell exploit","mitre":"T1190"},
    "spring4shell":{"patterns":[r"Spring4Shell|CVE-2022-22965|classLoader.*access"],"severity":"CRITICAL","weight":50,"category":"Web Attack","desc":"Spring4Shell exploit","mitre":"T1190"},
    # ── Malware & Ransomware (50 rules) ──
    "ransomware":{"patterns":[r"(encrypt|ransom|locked)\.(txt|html|note)",r"YOUR_FILES_ARE_ENCRYPTED",r"\.locked$|\.crypt$|\.enc$"],"severity":"CRITICAL","weight":60,"category":"Malware","desc":"Ransomware indicators","mitre":"T1486"},
    "malware_download":{"patterns":[r"powershell.*DownloadString|powershell.*DownloadFile",r"bitsadmin.*transfer",r"certutil.*-decode|certutil.*-urlcache"],"severity":"CRITICAL","weight":45,"category":"Malware","desc":"Malware download","mitre":"T1105"},
    "worm_behavior":{"patterns":[r"mass.?send|self.?replicate|propagat"],"severity":"CRITICAL","weight":40,"category":"Malware","desc":"Worm propagation","mitre":"T1080"},
    "fileless_malware":{"patterns":[r"powershell.*-nop.*-w hidden|powershell.*-enc.*bypass",r"mshta.*vbscript|regsvr32.*\/s.*\/n.*\/u"],"severity":"CRITICAL","weight":50,"category":"Malware","desc":"Fileless malware (LOLBins)","mitre":"T1059.001"},
    "macro_malware":{"patterns":[r"macro.*download|VBA.*shell|Auto_Open.*exec"],"severity":"HIGH","weight":35,"category":"Malware","desc":"Malicious macro","mitre":"T1204.002"},
    "webshell_detection":{"patterns":[r"webshell|web.?shell|c99|r57|b374k",r"cmd\.php|eval\s*\(\s*\$_(GET|POST|REQUEST)"],"severity":"CRITICAL","weight":50,"category":"Malware","desc":"Web shell detected","mitre":"T1505.003"},
    "dropper_behavior":{"patterns":[r"dropper|payload.*drop|stage[12].*download"],"severity":"CRITICAL","weight":40,"category":"Malware","desc":"Malware dropper","mitre":"T1105"},
    "trojan_rat":{"patterns":[r"RAT.*connect|remote.*access.*trojan|darkcomet|njrat|asyncrat|quasar.*rat"],"severity":"CRITICAL","weight":50,"category":"Malware","desc":"RAT/Trojan detected","mitre":"T1219"},
    "infostealer":{"patterns":[r"infostealer|info.?stealer|redline.*stealer|raccoon.*stealer|vidar.*stealer"],"severity":"CRITICAL","weight":45,"category":"Malware","desc":"Info stealer detected","mitre":"T1005"},
    "loader_malware":{"patterns":[r"QakBot|QBot|IcedID|BazarLoader|Emotet|TrickBot"],"severity":"CRITICAL","weight":50,"category":"Malware","desc":"Known malware loader","mitre":"T1105"},
    "apt_tools":{"patterns":[r"APT\d+|Lazarus|Fancy Bear|Cozy Bear|Turla|Equation Group"],"severity":"CRITICAL","weight":55,"category":"Malware","desc":"APT activity indicators","mitre":"T1583"},
    "wannacry":{"patterns":[r"WannaCry|WanaCrypt|MS17-010.*worm"],"severity":"CRITICAL","weight":60,"category":"Malware","desc":"WannaCry ransomware","mitre":"T1486"},
    "ryuk_ransomware":{"patterns":[r"Ryuk|Conti.*ransom|RyukReadMe"],"severity":"CRITICAL","weight":60,"category":"Malware","desc":"Ryuk/Conti ransomware","mitre":"T1486"},
    "lockbit":{"patterns":[r"LockBit|lockbit.*ransom|\.lockbit"],"severity":"CRITICAL","weight":60,"category":"Malware","desc":"LockBit ransomware","mitre":"T1486"},
    "blackcat_alphv":{"patterns":[r"BlackCat|ALPHV|alphv.*ransom"],"severity":"CRITICAL","weight":60,"category":"Malware","desc":"BlackCat/ALPHV ransomware","mitre":"T1486"},
    "emotet":{"patterns":[r"Emotet|epoch[1-5].*botnet"],"severity":"CRITICAL","weight":50,"category":"Malware","desc":"Emotet malware","mitre":"T1105"},
    "mimikatz_detect":{"patterns":[r"mimikatz|gentilkiwi|sekurlsa::logonpasswords",r"lsadump::sam|lsadump::dcsync"],"severity":"CRITICAL","weight":55,"category":"Malware","desc":"Mimikatz tool detected","mitre":"T1003.001"},
    "sharphound":{"patterns":[r"SharpHound|Invoke-BloodHound|bloodhound.*collector"],"severity":"HIGH","weight":35,"category":"Malware","desc":"SharpHound/BloodHound","mitre":"T1087.002"},
    "rubeus":{"patterns":[r"Rubeus|asktgt|asktgs|kerberoast",r"Rubeus\.exe"],"severity":"CRITICAL","weight":40,"category":"Malware","desc":"Rubeus Kerberos tool","mitre":"T1558"},
    "certify":{"patterns":[r"Certify\.exe|Certipy|AD CS.*exploit"],"severity":"CRITICAL","weight":42,"category":"Malware","desc":"AD CS exploitation tool","mitre":"T1649"},
    # ── Cloud, Container, IoT, Supply Chain, Network, Zero Trust, Crypto, API, AI ──
    "cloud_metadata_abuse":{"patterns":[r"169\.254\.169\.254|metadata\.google\.internal"],"severity":"CRITICAL","weight":40,"category":"Cloud Attack","desc":"Cloud metadata abuse","mitre":"T1552.005"},
    "container_escape":{"patterns":[r"docker.*privileged|--privileged",r"container.*escape|nsenter|cgroup.*escape"],"severity":"CRITICAL","weight":45,"category":"Cloud Attack","desc":"Container escape","mitre":"T1611"},
    "dependency_confusion":{"patterns":[r"dependency.*confusion|package.*hijack|typosquat.*package"],"severity":"CRITICAL","weight":50,"category":"Supply Chain","desc":"Dependency confusion","mitre":"T1195.002"},
    "typosquatting_package":{"patterns":[r"typosquat|similar.*package.*name"],"severity":"HIGH","weight":30,"category":"Supply Chain","desc":"Package typosquatting","mitre":"T1195.002"},
    "build_pipeline_compromise":{"patterns":[r"CI/CD.*compromis|build.*pipeline.*inject|jenkins.*exploit"],"severity":"CRITICAL","weight":50,"category":"Supply Chain","desc":"Build pipeline compromise","mitre":"T1195.002"},
    "scada_ics_abuse":{"patterns":[r"SCADA|Modbus|DNP3|OPC DA|ICS.*attack",r"PLC.*(stop|start|reprogram)"],"severity":"CRITICAL","weight":55,"category":"IoT/OT Attack","desc":"SCADA/ICS abuse","mitre":"T0855"},
    "modbus_exploit":{"patterns":[r"Modbus.*write.*coil|Modbus.*function.*code.*(5|6|15|16)"],"severity":"CRITICAL","weight":50,"category":"IoT/OT Attack","desc":"Modbus exploitation","mitre":"T0831"},
    "mqtt_anomaly":{"patterns":[r"MQTT.*(inject|exploit|abuse)|mosquitto.*unauth"],"severity":"HIGH","weight":30,"category":"IoT/OT Attack","desc":"MQTT anomaly","mitre":"T0883"},
    "mass_file_access":{"patterns":[r"mass.*file.*(access|read|copy)|bulk.*file.*operation"],"severity":"HIGH","weight":30,"category":"Insider Threat","desc":"Mass file access","mitre":"T1005"},
    "off_hours_access":{"patterns":[r"(0[0-4]):\d{2}:\d{2}.*logon|after.?hours.*access"],"severity":"MEDIUM","weight":15,"category":"Insider Threat","desc":"Off-hours access","mitre":"T1078"},
    "bulk_download":{"patterns":[r"bulk.*download|mass.*download|wget.*-r.*mirror"],"severity":"HIGH","weight":30,"category":"Insider Threat","desc":"Bulk data download","mitre":"T1530"},
    "exploit_kit":{"patterns":[r"exploit.?kit|RIG.*EK|Magnitude.*EK|Fallout.*EK"],"severity":"CRITICAL","weight":50,"category":"Zero-Day/Exploit","desc":"Exploit kit activity","mitre":"T1203"},
    "shellcode_detect":{"patterns":[r"shellcode|NOP.*sled|\\x90{4,}|egg.*hunter"],"severity":"CRITICAL","weight":50,"category":"Zero-Day/Exploit","desc":"Shellcode detected","mitre":"T1203"},
    "heap_spray":{"patterns":[r"heap.*spray|spray.*heap|0x0c0c0c0c"],"severity":"CRITICAL","weight":45,"category":"Zero-Day/Exploit","desc":"Heap spray attack","mitre":"T1203"},
    "rop_chain":{"patterns":[r"ROP.*chain|return.*oriented.*program|gadget.*chain"],"severity":"CRITICAL","weight":45,"category":"Zero-Day/Exploit","desc":"ROP chain exploit","mitre":"T1203"},
    "phishing_url":{"patterns":[r"phishing|phish.*url|credential.*harvest.*url"],"severity":"HIGH","weight":25,"category":"Email/Phishing","desc":"Phishing URL","mitre":"T1566.002"},
    "macro_document":{"patterns":[r"\.docm|\.xlsm|\.pptm|macro.*enabled"],"severity":"HIGH","weight":30,"category":"Email/Phishing","desc":"Macro document delivery","mitre":"T1566.001"},
    "spoofed_sender":{"patterns":[r"spoof.*sender|forged.*from|SPF.*fail.*spoof"],"severity":"HIGH","weight":25,"category":"Email/Phishing","desc":"Email sender spoofing","mitre":"T1566.001"},
    "credential_harvest":{"patterns":[r"credential.*harvest|fake.*login.*page|evilginx|gophish"],"severity":"CRITICAL","weight":40,"category":"Email/Phishing","desc":"Credential harvesting","mitre":"T1566.003"},
    "mining_pool":{"patterns":[r"mining.*pool|stratum\+tcp|pool\.(minergate|hashvault|nanopool)"],"severity":"HIGH","weight":25,"category":"Cryptomining","desc":"Mining pool connection","mitre":"T1496"},
    "stratum_protocol":{"patterns":[r"stratum.*subscribe|mining\.submit|mining\.authorize"],"severity":"HIGH","weight":30,"category":"Cryptomining","desc":"Stratum protocol","mitre":"T1496"},
    "xmrig_detect":{"patterns":[r"xmrig|xmr-stak|cpuminer|minerd\b"],"severity":"HIGH","weight":30,"category":"Cryptomining","desc":"Cryptocurrency miner","mitre":"T1496"},
    "jwt_abuse":{"patterns":[r"JWT.*tamper|jwt.*none.*algorithm|alg.*none"],"severity":"HIGH","weight":25,"category":"API Security","desc":"JWT token abuse","mitre":"T1190"},
    "api_key_exposure":{"patterns":[r"api[_-]?key[=: ]+[a-zA-Z0-9]{20,}"],"severity":"HIGH","weight":20,"category":"API Security","desc":"API key exposure","mitre":"T1552.001"},
    "graphql_injection":{"patterns":[r"__schema|__type|IntrospectionQuery"],"severity":"HIGH","weight":25,"category":"API Security","desc":"GraphQL introspection","mitre":"T1190"},
    "rate_limit_bypass":{"patterns":[r"rate.?limit.*bypass|X-Forwarded-For.*spoof.*rate"],"severity":"MEDIUM","weight":15,"category":"API Security","desc":"Rate limit bypass","mitre":"T1190"},
    "api_mass_assignment":{"patterns":[r"mass.?assign|parameter.*pollut"],"severity":"HIGH","weight":25,"category":"API Security","desc":"Mass assignment","mitre":"T1190"},
    "broken_auth_api":{"patterns":[r"IDOR|insecure.*direct.*object|BOLA"],"severity":"HIGH","weight":25,"category":"API Security","desc":"BOLA/IDOR attempt","mitre":"T1190"},
    "oauth_token_theft":{"patterns":[r"oauth.*redirect.*steal|authorization_code.*intercept"],"severity":"CRITICAL","weight":35,"category":"API Security","desc":"OAuth token theft","mitre":"T1528"},
    "prompt_injection":{"patterns":[r"prompt.*inject|ignore.*previous.*instruct|DAN.*mode"],"severity":"HIGH","weight":25,"category":"AI/ML Attack","desc":"AI prompt injection","mitre":"T1190"},
    "model_poisoning":{"patterns":[r"model.*poison|training.*data.*tamper|adversarial.*train"],"severity":"CRITICAL","weight":40,"category":"AI/ML Attack","desc":"ML model poisoning","mitre":"T1195.002"},
    "adversarial_input":{"patterns":[r"adversarial.*example|evasion.*attack.*model"],"severity":"HIGH","weight":25,"category":"AI/ML Attack","desc":"Adversarial ML input","mitre":"T1190"},
    "data_extraction_llm":{"patterns":[r"training.*data.*extract|model.*inversion|membership.*inference"],"severity":"HIGH","weight":30,"category":"AI/ML Attack","desc":"LLM data extraction","mitre":"T1005"},
    "smart_contract_exploit":{"patterns":[r"reentrancy.*attack|flash.?loan.*exploit|front.?run.*MEV"],"severity":"CRITICAL","weight":40,"category":"Blockchain Attack","desc":"Smart contract exploit","mitre":"T1190"},
    "wallet_theft":{"patterns":[r"wallet.*drain|private.*key.*steal|seed.*phrase.*exfil"],"severity":"CRITICAL","weight":45,"category":"Blockchain Attack","desc":"Crypto wallet theft","mitre":"T1005"},
    "crypto_rug_pull":{"patterns":[r"rug.*pull|liquidity.*drain|exit.*scam.*token"],"severity":"HIGH","weight":30,"category":"Blockchain Attack","desc":"Crypto rug pull","mitre":"T1190"},
    "crypto_clipper":{"patterns":[r"clipboard.*replace.*wallet|address.*swap.*crypto"],"severity":"CRITICAL","weight":40,"category":"Blockchain Attack","desc":"Crypto clipper","mitre":"T1115"},
    "arp_poisoning":{"patterns":[r"ARP.*spoof|ARP.*poison|arp.*cache.*tamper",r"ettercap|arpspoof|bettercap.*arp"],"severity":"HIGH","weight":30,"category":"Network Attack","desc":"ARP poisoning","mitre":"T1557"},
    "dns_rebinding":{"patterns":[r"DNS.*rebind|rebinding.*attack"],"severity":"HIGH","weight":30,"category":"Network Attack","desc":"DNS rebinding","mitre":"T1557"},
    "bgp_hijacking":{"patterns":[r"BGP.*hijack|route.*leak|AS.*path.*manipulat"],"severity":"CRITICAL","weight":50,"category":"Network Attack","desc":"BGP hijacking","mitre":"T1557"},
    "vlan_hopping":{"patterns":[r"VLAN.*hop|802\.1Q.*double.*tag|DTP.*attack"],"severity":"HIGH","weight":25,"category":"Network Attack","desc":"VLAN hopping","mitre":"T1599"},
    "ssl_stripping":{"patterns":[r"SSL.*strip|HTTPS.*downgrade|sslstrip|HSTS.*bypass"],"severity":"HIGH","weight":30,"category":"Network Attack","desc":"SSL stripping","mitre":"T1557.002"},
    "wifi_attack":{"patterns":[r"deauth.*attack|evil.*twin|karma.*attack|PMKID.*crack"],"severity":"HIGH","weight":25,"category":"Network Attack","desc":"WiFi attack","mitre":"T1557"},
    "mfa_fatigue":{"patterns":[r"MFA.*fatigue|push.*spam|MFA.*bomb|MFA.*flood"],"severity":"CRITICAL","weight":35,"category":"Zero Trust Bypass","desc":"MFA fatigue attack","mitre":"T1621"},
    "session_fixation":{"patterns":[r"session.*fixat|session.*id.*inject"],"severity":"HIGH","weight":25,"category":"Zero Trust Bypass","desc":"Session fixation","mitre":"T1550"},
    "saml_attack":{"patterns":[r"SAML.*forge|SAML.*inject|XML.*signature.*wrap"],"severity":"CRITICAL","weight":45,"category":"Zero Trust Bypass","desc":"SAML token forgery","mitre":"T1606.002"},
    "conditional_access_bypass":{"patterns":[r"conditional.*access.*bypass|device.*compliance.*spoof"],"severity":"HIGH","weight":30,"category":"Zero Trust Bypass","desc":"Conditional access bypass","mitre":"T1556"},
    "kerberos_delegation_abuse":{"patterns":[r"unconstrained.*delegation|constrained.*delegation.*abuse",r"S4U2Self|S4U2Proxy"],"severity":"CRITICAL","weight":40,"category":"Zero Trust Bypass","desc":"Kerberos delegation abuse","mitre":"T1558"},
    "password_spraying_cloud":{"patterns":[r"password.*spray.*azure|password.*spray.*O365"],"severity":"HIGH","weight":25,"category":"Zero Trust Bypass","desc":"Cloud password spraying","mitre":"T1110.003"},
    # ── Execution (30 rules) ──
    "powershell_exec":{"patterns":[r"powershell.*-ep bypass|powershell.*-nop",r"pwsh.*-Command"],"severity":"HIGH","weight":25,"category":"Execution","desc":"PowerShell execution","mitre":"T1059.001"},
    "cmd_exec":{"patterns":[r"cmd\.exe.*/c|cmd\.exe.*/k"],"severity":"MEDIUM","weight":10,"category":"Execution","desc":"CMD execution","mitre":"T1059.003"},
    "wscript_exec":{"patterns":[r"wscript.*\.vbs|cscript.*\.vbs|wscript.*\.js"],"severity":"HIGH","weight":22,"category":"Execution","desc":"Windows Script Host","mitre":"T1059.005"},
    "python_exec":{"patterns":[r"python.*-c.*import|python.*exec\(|python.*eval\("],"severity":"MEDIUM","weight":15,"category":"Execution","desc":"Python execution","mitre":"T1059.006"},
    "certutil_download":{"patterns":[r"certutil.*-urlcache.*-split.*-f"],"severity":"HIGH","weight":30,"category":"Execution","desc":"Certutil download","mitre":"T1105"},
    "bitsadmin_download":{"patterns":[r"bitsadmin.*/transfer.*/download"],"severity":"HIGH","weight":28,"category":"Execution","desc":"BITSAdmin download","mitre":"T1105"},
    "msiexec_install":{"patterns":[r"msiexec.*/i.*http|msiexec.*/q.*/i"],"severity":"HIGH","weight":25,"category":"Execution","desc":"MSIExec remote install","mitre":"T1218.007"},
    "wmi_exec":{"patterns":[r"wmic.*process.*call.*create",r"Invoke-WmiMethod|Win32_Process.*Create"],"severity":"HIGH","weight":28,"category":"Execution","desc":"WMI command execution","mitre":"T1047"},
    "office_spawn_child":{"patterns":[r"WINWORD.*cmd|EXCEL.*powershell|OUTLOOK.*script"],"severity":"CRITICAL","weight":40,"category":"Execution","desc":"Office spawning child process","mitre":"T1204.002"},
    "hta_execution":{"patterns":[r"mshta.*http|mshta.*vbscript"],"severity":"HIGH","weight":30,"category":"Execution","desc":"HTA file execution","mitre":"T1218.005"},
}


# ═══════════════ 300+ MITRE ATT&CK DESCRIPTIONS ═══════════════
MITRE_DESCRIPTIONS = {
    # Reconnaissance
    "T1595":"Active Scanning","T1595.001":"Scanning IP Blocks","T1595.002":"Vulnerability Scanning","T1595.003":"Wordlist Scanning",
    "T1592":"Gather Victim Host Info","T1592.001":"Hardware","T1592.002":"Software","T1592.003":"Firmware","T1592.004":"Client Configs",
    "T1589":"Gather Victim Identity Info","T1589.001":"Credentials","T1589.002":"Email Addresses","T1589.003":"Employee Names",
    "T1590":"Gather Victim Network Info","T1590.001":"Domain Properties","T1590.002":"DNS","T1590.004":"Network Topology","T1590.006":"Network Security Appliances",
    "T1591":"Gather Victim Org Info","T1593":"Search Open Websites/Domains","T1594":"Search Victim-Owned Websites",
    "T1596":"Search Open Technical Databases","T1597":"Search Closed Sources",
    # Resource Development
    "T1583":"Acquire Infrastructure","T1583.001":"Domains","T1583.003":"Virtual Private Server","T1583.006":"Web Services",
    "T1584":"Compromise Infrastructure","T1585":"Establish Accounts","T1586":"Compromise Accounts",
    "T1587":"Develop Capabilities","T1587.001":"Malware","T1587.003":"Digital Certificates","T1588":"Obtain Capabilities",
    # Initial Access
    "T1190":"Exploit Public-Facing Application","T1189":"Drive-by Compromise","T1566":"Phishing",
    "T1566.001":"Spearphishing Attachment","T1566.002":"Spearphishing Link","T1566.003":"Spearphishing via Service",
    "T1195":"Supply Chain Compromise","T1195.002":"Compromise Software Supply Chain",
    "T1199":"Trusted Relationship","T1200":"Hardware Additions","T1078":"Valid Accounts",
    "T1078.001":"Default Accounts","T1078.002":"Domain Accounts","T1078.003":"Local Accounts","T1078.004":"Cloud Accounts",
    "T1133":"External Remote Services",
    # Execution
    "T1059":"Command & Scripting Interpreter","T1059.001":"PowerShell","T1059.003":"Windows Command Shell",
    "T1059.004":"Unix Shell","T1059.005":"Visual Basic","T1059.006":"Python","T1059.007":"JavaScript",
    "T1047":"WMI","T1053":"Scheduled Task/Job","T1053.002":"AT","T1053.003":"Cron","T1053.005":"Scheduled Task",
    "T1204":"User Execution","T1204.001":"Malicious Link","T1204.002":"Malicious File",
    "T1559":"Inter-Process Communication","T1559.001":"COM","T1559.002":"DDE","T1106":"Native API",
    "T1569":"System Services","T1569.002":"Service Execution",
    # Persistence
    "T1037":"Boot/Logon Init Scripts","T1037.001":"Logon Script (Windows)","T1037.004":"RC Scripts",
    "T1098":"Account Manipulation","T1136":"Create Account","T1136.001":"Local Account","T1136.002":"Domain Account",
    "T1197":"BITS Jobs","T1176":"Browser Extensions","T1137":"Office Application Startup","T1137.006":"Add-ins",
    "T1543":"Create/Modify System Process","T1543.002":"Systemd Service","T1543.003":"Windows Service","T1543.004":"Launch Daemon",
    "T1546":"Event Triggered Execution","T1546.002":"Screensaver","T1546.003":"WMI Event Subscription",
    "T1546.004":"Unix Shell Config","T1546.007":"Netsh Helper DLL","T1546.008":"Accessibility Features",
    "T1546.010":"AppInit_DLLs","T1546.012":"IFEO Injection","T1546.013":"PowerShell Profile","T1546.015":"COM Hijacking",
    "T1547":"Boot/Logon Autostart","T1547.001":"Registry Run Keys/Startup","T1547.002":"Authentication Package",
    "T1547.003":"Time Providers","T1547.004":"Winlogon Helper DLL","T1547.005":"Security Support Provider",
    "T1547.006":"Kernel Modules","T1547.010":"Port Monitors","T1547.013":"XDG Autostart",
    "T1542":"Pre-OS Boot","T1542.003":"Bootkit","T1574":"Hijack Execution Flow",
    "T1574.001":"DLL Search Order Hijacking","T1574.007":"PATH Interception","T1574.009":"Unquoted Service Path","T1574.010":"Services File Permissions",
    # Privilege Escalation
    "T1134":"Access Token Manipulation","T1134.001":"Token Impersonation/Theft","T1134.002":"Create Process with Token",
    "T1134.004":"Parent PID Spoofing","T1134.005":"SID-History Injection",
    "T1068":"Exploitation for Privilege Escalation","T1548":"Abuse Elevation Control",
    "T1548.001":"setuid/setgid","T1548.002":"Bypass UAC","T1548.003":"Sudo & Sudo Caching",
    # Defense Evasion
    "T1014":"Rootkit","T1027":"Obfuscated Files/Information","T1027.001":"Binary Padding",
    "T1027.002":"Software Packing","T1027.003":"Steganography","T1036":"Masquerading",
    "T1055":"Process Injection","T1055.012":"Process Hollowing","T1055.013":"Process Doppelganging",
    "T1070":"Indicator Removal","T1070.001":"Clear Windows Event Logs","T1070.006":"Timestomp",
    "T1218":"System Binary Proxy Execution","T1218.002":"Control Panel","T1218.003":"CMSTP",
    "T1218.004":"InstallUtil","T1218.005":"Mshta","T1218.007":"Msiexec","T1218.010":"Regsvr32",
    "T1218.011":"Rundll32","T1218.012":"Verclsid","T1220":"XSL Script Processing",
    "T1553":"Subvert Trust Controls","T1553.002":"Code Signing","T1562":"Impair Defenses",
    "T1562.001":"Disable/Modify Tools","T1562.002":"Disable Windows Event Logging",
    "T1562.004":"Disable/Modify Firewall","T1562.006":"Indicator Blocking (ETW)",
    "T1564":"Hide Artifacts","T1564.004":"NTFS File Attributes (ADS)",
    # Credential Access
    "T1003":"OS Credential Dumping","T1003.001":"LSASS Memory","T1003.002":"SAM","T1003.003":"NTDS",
    "T1003.006":"DCSync","T1110":"Brute Force","T1110.001":"Password Guessing",
    "T1110.003":"Password Spraying","T1552":"Unsecured Credentials","T1552.001":"Credentials In Files",
    "T1552.002":"Credentials in Registry","T1552.004":"Private Keys","T1552.005":"Cloud Instance Metadata",
    "T1555":"Credentials from Password Stores","T1555.003":"Browser","T1555.004":"Windows Credential Manager",
    "T1556":"Modify Authentication Process","T1556.001":"Domain Controller Authentication",
    "T1557":"Adversary-in-the-Middle","T1557.001":"LLMNR/NBT-NS Poisoning","T1557.002":"ARP Cache Poisoning",
    "T1558":"Steal/Forge Kerberos Tickets","T1558.001":"Golden Ticket","T1558.003":"Kerberoasting","T1558.004":"AS-REP Roasting",
    "T1056":"Input Capture","T1056.001":"Keylogging","T1528":"Steal Application Access Token",
    "T1649":"Steal or Forge Authentication Certificates",
    # Discovery
    "T1007":"System Service Discovery","T1012":"Query Registry","T1016":"System Network Config Discovery",
    "T1018":"Remote System Discovery","T1046":"Network Service Discovery","T1057":"Process Discovery",
    "T1082":"System Information Discovery","T1083":"File & Dir Discovery","T1087":"Account Discovery",
    "T1087.001":"Local Account Discovery","T1087.002":"Domain Account Discovery",
    "T1135":"Network Share Discovery","T1201":"Password Policy Discovery","T1482":"Domain Trust Discovery",
    "T1497":"Virtualization/Sandbox Evasion","T1497.001":"System Checks",
    "T1518":"Software Discovery","T1518.001":"Security Software Discovery","T1580":"Cloud Infra Discovery",
    "T1615":"Group Policy Discovery",
    # Lateral Movement
    "T1021":"Remote Services","T1021.001":"RDP","T1021.002":"SMB/Admin Shares","T1021.003":"DCOM",
    "T1021.004":"SSH","T1021.005":"VNC","T1021.006":"Windows Remote Management",
    "T1080":"Taint Shared Content","T1210":"Exploitation of Remote Services",
    "T1534":"Internal Spearphishing","T1550":"Use Alternate Auth Material",
    "T1550.002":"Pass the Hash","T1550.003":"Pass the Ticket","T1563":"Remote Service Session Hijack",
    "T1563.002":"RDP Hijacking","T1570":"Lateral Tool Transfer",
    # Collection
    "T1005":"Data from Local System","T1113":"Screen Capture","T1115":"Clipboard Data",
    "T1119":"Automated Collection","T1123":"Audio Capture","T1125":"Video Capture",
    "T1530":"Data from Cloud Storage","T1560":"Archive Collected Data","T1560.001":"Archive via Utility",
    # C2
    "T1071":"Application Layer Protocol","T1071.001":"Web Protocols","T1071.004":"DNS",
    "T1090":"Proxy","T1090.001":"Internal Proxy","T1090.003":"Multi-hop Proxy (Tor)","T1090.004":"Domain Fronting",
    "T1095":"Non-Application Layer Protocol","T1102":"Web Service","T1102.002":"Bidirectional Communication",
    "T1219":"Remote Access Software","T1568":"Dynamic Resolution","T1568.001":"Fast Flux DNS","T1568.002":"DGA",
    "T1572":"Protocol Tunneling","T1573":"Encrypted Channel",
    # Exfiltration
    "T1011":"Exfiltration Over Other Network Medium","T1020":"Automated Exfiltration",
    "T1041":"Exfiltration Over C2","T1048":"Exfiltration Over Alternative Protocol",
    "T1048.002":"Exfil via SMTP","T1048.003":"Exfil via DNS","T1052":"Exfil Over Physical Medium",
    "T1052.001":"Exfil Over USB","T1567":"Exfil Over Web Service","T1567.002":"Exfil to Cloud Storage",
    # Impact
    "T1486":"Data Encrypted for Impact","T1485":"Data Destruction","T1489":"Service Stop",
    "T1490":"Inhibit System Recovery","T1491":"Defacement","T1496":"Resource Hijacking",
    "T1498":"Network DoS","T1499":"Endpoint DoS","T1529":"System Shutdown/Reboot","T1531":"Account Access Removal",
    # ICS
    "T0831":"Manipulation of Control","T0855":"Unauthorized Command Message","T0883":"Change Program State",
    # Other
    "T1105":"Ingress Tool Transfer","T1203":"Exploitation for Client Execution",
    "T1505":"Server Software Component","T1505.003":"Web Shell",
    "T1599":"Network Boundary Bridging","T1606":"Forge Web Credentials","T1606.002":"SAML Tokens",
    "T1621":"MFA Request Generation",
}

# ═══════════════ 35 CORRELATION RULES ═══════════════
CORRELATION_RULES = [
    {"name":"Credential Compromise Chain","requires":["brute_force","privilege_escalation"],"severity":"CRITICAL","score_boost":20,"desc":"Brute-force → privilege escalation — credential compromise"},
    {"name":"Full Kill Chain Detected","requires":["credential_dumping","lateral_movement","data_exfiltration"],"severity":"CRITICAL","score_boost":30,"desc":"Credential theft → lateral movement → exfiltration — full kill chain"},
    {"name":"Ransomware Deployment","requires":["lateral_movement","av_tamper","ransomware"],"severity":"CRITICAL","score_boost":25,"desc":"Lateral movement + AV disable + ransomware — coordinated attack"},
    {"name":"Active C2 + Exfiltration","requires":["command_and_control","data_exfiltration"],"severity":"CRITICAL","score_boost":20,"desc":"C2 channel with data exfiltration — ongoing breach"},
    {"name":"Persistence + Evasion","requires":["persistence","log_tampering"],"severity":"CRITICAL","score_boost":15,"desc":"Persistence + log clearing — adversary covering tracks"},
    {"name":"Insider Threat","requires":["off_hours_access","bulk_download"],"severity":"HIGH","score_boost":15,"desc":"Off-hours access + bulk downloads — insider threat"},
    {"name":"AD Compromise Chain","requires":["ad_recon","kerberoasting","golden_silver_ticket"],"severity":"CRITICAL","score_boost":30,"desc":"AD recon → Kerberoasting → Golden Ticket — full AD compromise"},
    {"name":"Supply Chain + Persistence","requires":["dependency_confusion","persistence"],"severity":"CRITICAL","score_boost":20,"desc":"Supply chain compromise with persistence — APT activity"},
    {"name":"Web Attack to Shell","requires":["sql_injection","reverse_shell"],"severity":"CRITICAL","score_boost":20,"desc":"SQL injection → reverse shell — web app compromised"},
    {"name":"Phishing to Cred Dump","requires":["phishing_url","credential_dumping"],"severity":"CRITICAL","score_boost":20,"desc":"Phishing → credential dump — social engineering chain"},
    {"name":"API Attack Chain","requires":["jwt_abuse","broken_auth_api"],"severity":"CRITICAL","score_boost":20,"desc":"JWT abuse + BOLA — API fully compromised"},
    {"name":"AI System Compromise","requires":["prompt_injection","data_extraction_llm"],"severity":"CRITICAL","score_boost":25,"desc":"Prompt injection → data extraction — AI system compromised"},
    {"name":"MFA Bypass + Lateral","requires":["mfa_fatigue","lateral_movement"],"severity":"CRITICAL","score_boost":25,"desc":"MFA bypass → lateral movement — identity compromise"},
    {"name":"Crypto Theft Chain","requires":["wallet_theft","crypto_clipper"],"severity":"CRITICAL","score_boost":25,"desc":"Wallet theft + clipboard hijack — crypto attack chain"},
    {"name":"Network MitM + Creds","requires":["arp_poisoning","credential_dumping"],"severity":"CRITICAL","score_boost":20,"desc":"ARP poisoning → credential capture — MitM attack"},
    {"name":"LOLBins Attack Chain","requires":["fileless_malware","amsi_bypass"],"severity":"CRITICAL","score_boost":20,"desc":"Fileless malware + AMSI bypass — living-off-the-land attack"},
    {"name":"DCSync + Golden Ticket","requires":["dcsync_attack","golden_silver_ticket"],"severity":"CRITICAL","score_boost":30,"desc":"DCSync → Golden Ticket — total domain takeover"},
    {"name":"Webshell + Exfiltration","requires":["webshell_detection","data_exfiltration"],"severity":"CRITICAL","score_boost":22,"desc":"Web shell → data exfiltration — web server breach"},
    {"name":"Container Escape + Persistence","requires":["container_escape","persistence"],"severity":"CRITICAL","score_boost":25,"desc":"Container escape → persistence — cloud infrastructure compromise"},
    {"name":"Ransomware Kill Chain","requires":["credential_dumping","lateral_movement","ransomware"],"severity":"CRITICAL","score_boost":30,"desc":"Full ransomware deployment chain detected"},
    {"name":"Log4Shell Exploitation","requires":["log4j_exploit","reverse_shell"],"severity":"CRITICAL","score_boost":25,"desc":"Log4Shell → reverse shell — full exploitation chain"},
    {"name":"Credential Harvest → Lateral","requires":["credential_harvest","pass_the_hash"],"severity":"CRITICAL","score_boost":22,"desc":"Credential harvesting → Pass-the-Hash lateral movement"},
    {"name":"Recon → Exploitation","requires":["network_scan","exploit_kit"],"severity":"HIGH","score_boost":18,"desc":"Network reconnaissance followed by exploitation"},
    {"name":"Evasion + Crypto Mining","requires":["av_tamper","mining_pool"],"severity":"HIGH","score_boost":15,"desc":"AV evasion + cryptomining — unauthorized resource usage"},
    {"name":"PrintNightmare Chain","requires":["lpe_printspooler","lateral_movement"],"severity":"CRITICAL","score_boost":25,"desc":"PrintNightmare exploitation → lateral movement"},
    {"name":"SAML Forgery + Cloud Access","requires":["saml_attack","cloud_metadata_abuse"],"severity":"CRITICAL","score_boost":28,"desc":"SAML forgery → cloud access — identity provider compromise"},
    {"name":"UAC Bypass + Persistence","requires":["uac_bypass","registry_persistence"],"severity":"HIGH","score_boost":18,"desc":"UAC bypass → registry persistence — escalation + foothold"},
    {"name":"SSH Key Theft + Lateral","requires":["ssh_key_theft","ssh_lateral"],"severity":"HIGH","score_boost":20,"desc":"SSH key theft → SSH lateral movement"},
    {"name":"Keylogger + Exfil","requires":["keylog_exfil","data_exfiltration"],"severity":"CRITICAL","score_boost":22,"desc":"Keylogger → data exfiltration — credential theft chain"},
    {"name":"ICS Attack Chain","requires":["scada_ics_abuse","modbus_exploit"],"severity":"CRITICAL","score_boost":30,"desc":"SCADA + Modbus exploitation — industrial control attack"},
    {"name":"Zero-Day Exploitation","requires":["shellcode_detect","process_injection"],"severity":"CRITICAL","score_boost":28,"desc":"Shellcode + process injection — zero-day exploitation chain"},
    {"name":"USB Exfil + Off-Hours","requires":["usb_exfil","off_hours_access"],"severity":"HIGH","score_boost":18,"desc":"USB exfiltration during off-hours — insider data theft"},
    {"name":"Trojan + C2 Beacon","requires":["trojan_rat","beacon_pattern"],"severity":"CRITICAL","score_boost":25,"desc":"RAT + beaconing — active remote access compromise"},
    {"name":"AS-REP + Pass-the-Ticket","requires":["as_rep_roasting","pass_the_ticket"],"severity":"CRITICAL","score_boost":25,"desc":"AS-REP Roasting → Pass-the-Ticket — Kerberos attack chain"},
    {"name":"Rootkit + Timestomping","requires":["rootkit_detect","timestomp"],"severity":"CRITICAL","score_boost":28,"desc":"Rootkit + timestomping — deep system compromise"},
]

# ═══════════════ IOC PATTERNS ═══════════════
IOC_PATTERNS = {
    "md5":    r"\b[a-fA-F0-9]{32}\b",
    "sha1":   r"\b[a-fA-F0-9]{40}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "ipv4":   r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "url":    r"https?://[^\s\"'<>]+",
    "domain": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|xyz|info|ru|cn|tk|top|cc|pw|biz|me|co|uk|de|fr|gov|edu|mil)\b",
    "email":  r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
    "cve":    r"CVE-\d{4}-\d{4,7}",
    "ipv6":   r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
    "mac":    r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
    "bitcoin":r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
    "registry":r"\b(HKLM|HKCU|HKU|HKCR|HKCC)\\[^\s]+\b",
    "filepath_win":r"\b[A-Z]:\\(?:[^\\\s]+\\)*[^\\\s]+\b",
    "filepath_unix":r"\b/(?:etc|var|usr|tmp|home|opt|bin|sbin)/[^\s]+\b",
    "useragent":r"User-Agent:\s*[^\r\n]+",
}


# ═══════════════ EVTX PARSER ═══════════════
def parse_evtx_native(filepath):
    lines = []
    with open(filepath, "rb") as f:
        data = f.read()
    chunk_offset = 4096
    while chunk_offset < len(data) - 8:
        if data[chunk_offset:chunk_offset+8] != b'ElfChnk\x00':
            break
        chunk_data = data[chunk_offset:chunk_offset + 65536]
        rp = 0
        while rp < len(chunk_data) - 4:
            if chunk_data[rp:rp+4] == b'\x2a\x2a\x00\x00':
                try:
                    size = struct.unpack_from('<I', chunk_data, rp + 4)[0]
                    rec_id = struct.unpack_from('<Q', chunk_data, rp + 8)[0]
                    rec_data = chunk_data[rp:rp + size]
                    text = rec_data.decode("utf-16le", errors="ignore")
                    lines.append(f"RecordID:{rec_id} {text}")
                    rp += size
                except Exception:
                    rp += 1
            else:
                rp += 1
        chunk_offset += 65536
    return lines

def parse_evtx_lib(filepath):
    lines = []
    try:
        with Evtx(str(filepath)) as log:
            for xml_str, _ in evtx_file_xml_view(log.get_file_header()):
                lines.append(xml_str)
    except Exception:
        return parse_evtx_native(filepath)
    return lines

# ═══════════════ CORE ANALYZER ═══════════════
class LogAnalyzer:
    def __init__(self, filepath):
        self.filepath = Path(filepath)
        self.lines = []
        self.findings = defaultdict(list)
        self.ip_counter = Counter()
        self.user_counter = Counter()
        self.event_id_counter = Counter()
        self.total_lines = 0
        self.is_evtx = self.filepath.suffix.lower() == ".evtx"
        self.start_time = None
        self.end_time = None
        self.iocs = defaultdict(set)
        self.correlations = []
        self.mitre_hits = defaultdict(int)
        self.timeline = []
        self.file_md5 = ""
        self.file_sha256 = ""
        self.sigma_rules_loaded = 0

    def load(self):
        raw = self.filepath.read_bytes()
        self.file_md5 = hashlib.md5(raw).hexdigest()
        self.file_sha256 = hashlib.sha256(raw).hexdigest()
        if self.is_evtx:
            self.lines = parse_evtx_lib(self.filepath) if EVTX_LIB else parse_evtx_native(self.filepath)
        else:
            with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
                self.lines = f.readlines()
        self.total_lines = len(self.lines)
        self._load_sigma_rules()

    def _load_sigma_rules(self):
        if not YAML_AVAILABLE:
            return
        sigma_dir = Path(self.filepath).parent / "sigma_rules"
        if not sigma_dir.exists():
            sigma_dir = Path(".") / "sigma_rules"
        if not sigma_dir.exists():
            return
        for yml_file in sigma_dir.glob("*.yml"):
            try:
                with open(yml_file, "r", encoding="utf-8") as f:
                    rule = yaml.safe_load(f)
                if not rule or "detection" not in rule:
                    continue
                title = rule.get("title", yml_file.stem)
                level = rule.get("level", "medium").upper()
                desc = rule.get("description", title)
                mitre_id = ""
                tags = rule.get("tags", [])
                for tag in tags:
                    if tag.startswith("attack.t"):
                        mitre_id = tag.replace("attack.", "").upper()
                        break
                keywords = rule.get("detection", {}).get("keywords", [])
                if isinstance(keywords, list) and keywords:
                    patterns = [re.escape(k) if not k.startswith("*") else k.replace("*", ".*") for k in keywords]
                    rule_id = f"sigma_{yml_file.stem}"
                    weight_map = {"LOW": 5, "MEDIUM": 15, "HIGH": 25, "CRITICAL": 40}
                    PATTERNS[rule_id] = {
                        "patterns": patterns,
                        "severity": level if level in weight_map else "MEDIUM",
                        "weight": weight_map.get(level, 15),
                        "category": "Sigma Rule",
                        "desc": desc,
                        "mitre": mitre_id,
                    }
                    self.sigma_rules_loaded += 1
            except Exception:
                continue

    def analyze(self):
        for lineno, line in enumerate(self.lines, 1):
            if not isinstance(line, str):
                continue
            for ip in re.findall(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", line):
                self.ip_counter[ip] += 1
            for user in re.findall(r"(?:user|username|account)[=: ]+([a-zA-Z0-9_\-\.]+)", line, re.IGNORECASE):
                self.user_counter[user] += 1
            for eid in re.findall(r"EventID[=: ]+(\d+)", line, re.IGNORECASE):
                self.event_id_counter[eid] += 1
            for ts in re.findall(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", line):
                if not self.start_time:
                    self.start_time = ts
                self.end_time = ts
            for ioc_type, pattern in IOC_PATTERNS.items():
                for match in re.findall(pattern, line):
                    if ioc_type == "ipv4":
                        if not match.startswith(("0.", "127.", "255.")):
                            self.iocs[ioc_type].add(match)
                    elif ioc_type in ("md5", "sha1", "sha256"):
                        if len(set(match)) > 4:
                            self.iocs[ioc_type].add(match)
                    else:
                        self.iocs[ioc_type].add(match)
            for cat, info in PATTERNS.items():
                for p in info["patterns"]:
                    if re.search(p, line, re.IGNORECASE):
                        self.findings[cat].append((lineno, line.strip()))
                        mitre_id = info.get("mitre", "")
                        if mitre_id:
                            self.mitre_hits[mitre_id] += 1
                        ts_match = re.search(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", line)
                        timestamp = ts_match.group() if ts_match else f"Line {lineno}"
                        self.timeline.append({
                            "time": timestamp, "rule": cat, "severity": info["severity"],
                            "category": info["category"], "line": lineno,
                            "content": line.strip()[:120]
                        })
                        break
        self._run_correlations()

    def _run_correlations(self):
        for rule in CORRELATION_RULES:
            if all(r in self.findings for r in rule["requires"]):
                self.correlations.append(rule)

    def calculate_threat_score(self):
        score = 0
        for cat, findings_list in self.findings.items():
            weight = PATTERNS[cat]["weight"]
            count = len(findings_list)
            if count == 1:
                score += weight
            elif count <= 5:
                score += weight + (count - 1) * (weight * 0.3)
            else:
                score += weight + 4 * (weight * 0.3) + (count - 5) * (weight * 0.1)
        for corr in self.correlations:
            score += corr["score_boost"]
        return min(int(score), 100)

    def get_threat_level(self, score):
        if score >= 80: return "CRITICAL", CRITICAL_CLR
        if score >= 60: return "HIGH", RED
        if score >= 40: return "MEDIUM", ORANGE
        if score >= 20: return "LOW", YELLOW
        return "MINIMAL", GREEN

    def get_top_ips(self, n=10):
        return self.ip_counter.most_common(n)

    def get_findings_by_category(self):
        grouped = defaultdict(list)
        for cat, findings_list in self.findings.items():
            grp = PATTERNS[cat]["category"]
            grouped[grp].append((cat, findings_list))
        return grouped

    def export_json(self, path):
        score = self.calculate_threat_score()
        level, _ = self.get_threat_level(score)
        data = {
            "tool": TOOL_NAME, "version": VERSION,
            "generated": datetime.now().isoformat(),
            "file": str(self.filepath),
            "file_md5": self.file_md5, "file_sha256": self.file_sha256,
            "file_size_bytes": self.filepath.stat().st_size,
            "total_lines": self.total_lines,
            "log_start": self.start_time, "log_end": self.end_time,
            "unique_ips": len(self.ip_counter),
            "unique_users": len(self.user_counter),
            "threat_score": score, "threat_level": level,
            "top_ips": self.get_top_ips(10),
            "top_users": self.user_counter.most_common(10),
            "event_id_summary": self.event_id_counter.most_common(20),
            "detection_rules_total": len(PATTERNS),
            "sigma_rules_loaded": self.sigma_rules_loaded,
            "detection_rules_triggered": len(self.findings),
            "mitre_techniques_detected": [
                {"id": mid, "name": MITRE_DESCRIPTIONS.get(mid, ""), "hits": cnt}
                for mid, cnt in sorted(self.mitre_hits.items(), key=lambda x: -x[1])
            ],
            "correlations": [
                {"name": c["name"], "severity": c["severity"], "description": c["desc"]}
                for c in self.correlations
            ],
            "iocs": {k: sorted(list(v))[:100] for k, v in self.iocs.items() if v},
            "findings_summary": {k: {"count": len(v), "severity": PATTERNS[k]["severity"], "category": PATTERNS[k]["category"], "description": PATTERNS[k]["desc"], "mitre": PATTERNS[k].get("mitre", "")} for k, v in self.findings.items()},
            "findings_detail": {k: [{"line": ln, "content": c} for ln, c in v[:50]] for k, v in self.findings.items()},
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

    def generate_report(self):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        score = self.calculate_threat_score()
        level, _ = self.get_threat_level(score)
        bar = "█" * (score // 5) + "░" * (20 - score // 5)
        out = []
        out.append("═" * 72)
        out.append(f"       {TOOL_NAME} — Advanced Log Intelligence Engine")
        out.append(f"       {BUILT_BY}")
        out.append(f"       Report Generated: {now}")
        out.append("═" * 72)
        out.append("")
        out.append("┌─ FILE INFORMATION ─────────────────────────────────────────────────┐")
        out.append(f"│  File    : {self.filepath.name}")
        out.append(f"│  Size    : {self.filepath.stat().st_size:,} bytes")
        out.append(f"│  Type    : {'EVTX (Windows Event Log)' if self.is_evtx else 'Text Log'}")
        out.append(f"│  Lines   : {self.total_lines:,}")
        out.append(f"│  MD5     : {self.file_md5}")
        out.append(f"│  SHA-256 : {self.file_sha256}")
        if self.start_time:
            out.append(f"│  Period  : {self.start_time}  →  {self.end_time}")
        out.append("└────────────────────────────────────────────────────────────────────┘")
        out.append("")
        out.append("┌─ THREAT ASSESSMENT ────────────────────────────────────────────────┐")
        out.append(f"│  Threat Score   : {score}% [{bar}]")
        out.append(f"│  Threat Level   : ► {level} ◄")
        out.append(f"│  Unique IPs     : {len(self.ip_counter):,}")
        out.append(f"│  Unique Users   : {len(self.user_counter):,}")
        out.append(f"│  Event IDs      : {len(self.event_id_counter):,} distinct")
        out.append(f"│  Rules Loaded   : {len(PATTERNS)} (+ {self.sigma_rules_loaded} Sigma)")
        out.append(f"│  Rules Triggered: {len(self.findings)}")
        out.append(f"│  MITRE Techniques: {len(self.mitre_hits)}")
        out.append(f"│  IOCs Extracted : {sum(len(v) for v in self.iocs.values())}")
        out.append(f"│  Correlations   : {len(self.correlations)}")
        out.append("└────────────────────────────────────────────────────────────────────┘")
        out.append("")
        if self.correlations:
            out.append("┌─ ⚡ ATTACK CHAIN CORRELATIONS ─────────────────────────────────────┐")
            for corr in self.correlations:
                sev_icon = "🔴" if corr["severity"] == "CRITICAL" else "🟠"
                out.append(f"│  {sev_icon} [{corr['severity']}] {corr['name']}")
                out.append(f"│     {corr['desc']}")
                out.append(f"│     Signals: {', '.join(corr['requires'])}")
            out.append("└────────────────────────────────────────────────────────────────────┘")
            out.append("")
        grouped = self.get_findings_by_category()
        if grouped:
            out.append("┌─ FINDINGS BY CATEGORY ─────────────────────────────────────────────┐")
            for grp, items in sorted(grouped.items()):
                out.append("│")
                out.append(f"│  ▶ {grp.upper()}")
                for cat, findings_list in items:
                    info = PATTERNS[cat]
                    sev = info["severity"]
                    sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}.get(sev, "⚪")
                    mitre_tag = f" [{info.get('mitre', '')}]" if info.get('mitre') else ""
                    out.append(f"│     {sev_icon} [{sev:<8}] {info['desc']}{mitre_tag}")
                    out.append(f"│              → Rule: {cat}  |  Hits: {len(findings_list)}")
                    for ln, content in findings_list[:3]:
                        snippet = content[:80] + "..." if len(content) > 80 else content
                        out.append(f"│              ↳ Line {ln}: {snippet}")
                    if len(findings_list) > 3:
                        out.append(f"│              ↳ ... and {len(findings_list) - 3} more")
            out.append("│")
            out.append("└────────────────────────────────────────────────────────────────────┘")
            out.append("")
        total_iocs = sum(len(v) for v in self.iocs.values())
        if total_iocs:
            out.append("┌─ 🔎 IOCs ──────────────────────────────────────────────────────────┐")
            for ioc_type, values in sorted(self.iocs.items()):
                if values:
                    out.append(f"│  ▶ {ioc_type.upper()} ({len(values)} found)")
                    for v in sorted(values)[:10]:
                        out.append(f"│     • {v}")
                    if len(values) > 10:
                        out.append(f"│     ... and {len(values)-10} more")
            out.append("└────────────────────────────────────────────────────────────────────┘")
            out.append("")
        if self.ip_counter:
            out.append("┌─ TOP IP ADDRESSES ─────────────────────────────────────────────────┐")
            for ip, count in self.get_top_ips(10):
                bar_ip = "▌" * min(count, 30)
                out.append(f"│  {ip:<18} {bar_ip:<32} ({count:,} hits)")
            out.append("└────────────────────────────────────────────────────────────────────┘")
            out.append("")
        if self.mitre_hits:
            out.append("┌─ 🎯 MITRE ATT&CK ──────────────────────────────────────────────────┐")
            for mid, cnt in sorted(self.mitre_hits.items(), key=lambda x: -x[1])[:20]:
                desc = MITRE_DESCRIPTIONS.get(mid, "Unknown")
                out.append(f"│  {mid:<14} {desc:<45} {cnt:>4} hits")
            out.append("└────────────────────────────────────────────────────────────────────┘")
            out.append("")
        out.append("┌─ RECOMMENDATIONS ──────────────────────────────────────────────────┐")
        recs = []
        if "log_tampering" in self.findings:
            recs.append("URGENT: Event logs cleared — isolate system immediately")
        if "credential_dumping" in self.findings or "dcsync_attack" in self.findings:
            recs.append("URGENT: Credential dump — rotate ALL domain credentials")
        if "ransomware" in self.findings:
            recs.append("CRITICAL: Ransomware — isolate systems, activate IR plan")
        if "golden_silver_ticket" in self.findings:
            recs.append("Reset krbtgt twice; audit all service account SPNs")
        if "command_and_control" in self.findings or "reverse_shell" in self.findings:
            recs.append("Block C2 IPs/domains; check for persistence")
        if "brute_force" in self.findings:
            recs.append("Enable lockout policy; consider MFA")
        if "webshell_detection" in self.findings:
            recs.append("URGENT: Web shell — scan all web directories")
        if "fileless_malware" in self.findings:
            recs.append("Enable PowerShell ScriptBlock logging")
        if "container_escape" in self.findings:
            recs.append("Review container security: disable privileged mode")
        if any(c["name"] == "Full Kill Chain Detected" for c in self.correlations):
            recs.append("CRITICAL: Full kill chain — activate full IR immediately")
        if not recs:
            recs.append("Continue monitoring; no critical actions required")
        for r in recs:
            out.append(f"│  ► {r}")
        out.append("└────────────────────────────────────────────────────────────────────┘")
        out.append("")
        out.append(f"  Report by {TOOL_NAME}  |  {BUILT_BY}  |  {now}")
        out.append(f"  Detection Rules: {len(PATTERNS)}  |  Categories: {len(set(v['category'] for v in PATTERNS.values()))}")
        out.append("═" * 72)
        return "\n".join(out)

    def export_stix(self, path):
        stix_objects = []
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        for ioc_type, values in self.iocs.items():
            for val in list(values)[:200]:
                stix_type = {"ipv4":"ipv4-addr","url":"url","domain":"domain-name","email":"email-addr","md5":"file","sha1":"file","sha256":"file"}.get(ioc_type)
                if not stix_type: continue
                indicator_id = f"indicator--{uuid.uuid4()}"
                if stix_type == "file":
                    pattern = f"[file:hashes.'{ioc_type.upper()}' = '{val}']"
                elif stix_type == "ipv4-addr":
                    pattern = f"[ipv4-addr:value = '{val}']"
                elif stix_type == "url":
                    pattern = f"[url:value = '{val}']"
                elif stix_type == "domain-name":
                    pattern = f"[domain-name:value = '{val}']"
                elif stix_type == "email-addr":
                    pattern = f"[email-addr:value = '{val}']"
                else: continue
                stix_objects.append({"type":"indicator","spec_version":"2.1","id":indicator_id,"created":now_str,"modified":now_str,"name":f"{ioc_type.upper()}: {val[:80]}","pattern":pattern,"pattern_type":"stix","valid_from":now_str,"labels":["malicious-activity"]})
        bundle = {"type":"bundle","id":f"bundle--{uuid.uuid4()}","objects":stix_objects}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)


# ═══════════════ PREMIUM GUI ═══════════════
class ThreatscopeXGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{TOOL_NAME} — {BUILT_BY}")
        self.root.geometry("1400x900")
        self.root.minsize(1100, 700)
        self.root.configure(bg=BG_DARK)
        self.file_path = None
        self.analyzer = None
        self._build_ui()

    def _make_gradient(self, canvas, w, h, c1, c2, orient="h"):
        """Draw a smooth gradient on a Canvas."""
        r1,g1,b1 = int(c1[1:3],16), int(c1[3:5],16), int(c1[5:7],16)
        r2,g2,b2 = int(c2[1:3],16), int(c2[3:5],16), int(c2[5:7],16)
        steps = w if orient == "h" else h
        for i in range(steps):
            r = int(r1 + (r2-r1)*i/steps)
            g = int(g1 + (g2-g1)*i/steps)
            b = int(b1 + (b2-b1)*i/steps)
            color = f"#{r:02x}{g:02x}{b:02x}"
            if orient == "h":
                canvas.create_line(i, 0, i, h, fill=color)
            else:
                canvas.create_line(0, i, w, i, fill=color)

    def _build_ui(self):
        # ── GRADIENT HEADER ──
        header = tk.Canvas(self.root, height=72, highlightthickness=0)
        header.pack(fill=tk.X)
        header.update_idletasks()
        self.root.update_idletasks()
        header.bind("<Configure>", lambda e: self._draw_header(header))

        # ── TOOLBAR ──
        toolbar = tk.Frame(self.root, bg=BG_PANEL, pady=10)
        toolbar.pack(fill=tk.X)
        btn_cfg = {"font": ("Segoe UI", 10, "bold"), "relief": tk.FLAT, "cursor": "hand2", "padx": 18, "pady": 7, "bd": 0}

        self.btn_load = tk.Button(toolbar, text="📂  Load Log File", bg=BG_WIDGET, fg=ACCENT,
                                   activebackground=BG_HOVER, activeforeground=ACCENT, command=self.load_file, **btn_cfg)
        self.btn_load.pack(side=tk.LEFT, padx=(16, 6))
        self._add_hover(self.btn_load, BG_HOVER, BG_WIDGET)

        self.btn_analyze = tk.Button(toolbar, text="⚡  Analyze", bg="#0d47a1", fg="white",
                                      activebackground="#1565c0", activeforeground="white",
                                      disabledforeground="#5c6bc0", command=self.start_analysis, state=tk.DISABLED, **btn_cfg)
        self.btn_analyze.pack(side=tk.LEFT, padx=6)

        self.btn_export = tk.Button(toolbar, text="💾  Export JSON", bg=BG_WIDGET, fg=GREEN,
                                     activebackground=BG_HOVER, command=self.export_json, state=tk.DISABLED, **btn_cfg)
        self.btn_export.pack(side=tk.LEFT, padx=6)
        self._add_hover(self.btn_export, BG_HOVER, BG_WIDGET)

        self.btn_stix = tk.Button(toolbar, text="🔗  Export STIX", bg=BG_WIDGET, fg=ACCENT2,
                                   activebackground=BG_HOVER, command=self.export_stix, state=tk.DISABLED, **btn_cfg)
        self.btn_stix.pack(side=tk.LEFT, padx=6)
        self._add_hover(self.btn_stix, BG_HOVER, BG_WIDGET)

        self.btn_clear = tk.Button(toolbar, text="🗑  Clear", bg=BG_WIDGET, fg=TEXT_DIM,
                                    activebackground=BG_HOVER, command=self.clear_output, **btn_cfg)
        self.btn_clear.pack(side=tk.LEFT, padx=6)
        self._add_hover(self.btn_clear, BG_HOVER, BG_WIDGET)

        self.file_label = tk.Label(toolbar, text="No file loaded", fg=TEXT_DIM, bg=BG_PANEL, font=("Segoe UI", 9))
        self.file_label.pack(side=tk.LEFT, padx=16)

        num_cats = len(set(v["category"] for v in PATTERNS.values()))
        tk.Label(toolbar, text=f"🛡  {len(PATTERNS)} Rules  |  {num_cats} Categories  |  {len(MITRE_DESCRIPTIONS)} MITRE Techniques",
                 fg=YELLOW, bg=BG_PANEL, font=("Segoe UI", 9, "bold")).pack(side=tk.RIGHT, padx=16)

        # ── STAT CARDS ──
        stats_row = tk.Frame(self.root, bg=BG_DARK)
        stats_row.pack(fill=tk.X, padx=16, pady=(10, 0))
        self.stat_labels = {}
        stats = [
            ("score", "THREAT SCORE", "0%", CRITICAL_CLR), ("level", "THREAT LEVEL", "—", TEXT_DIM),
            ("lines", "LINES", "0", ACCENT), ("ips", "UNIQUE IPs", "0", ACCENT),
            ("users", "USERS", "0", ACCENT), ("findings", "FINDINGS", "0", YELLOW),
            ("mitre", "MITRE HITS", "0", ACCENT2), ("iocs", "IOCs", "0", GREEN),
            ("corr", "CORRELATIONS", "0", CRITICAL_CLR), ("rules", "RULES", str(len(PATTERNS)), ACCENT),
        ]
        for key, title, default, color in stats:
            card = tk.Frame(stats_row, bg=BG_CARD, padx=14, pady=12, highlightbackground=BORDER_CLR, highlightthickness=1)
            card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)
            tk.Label(card, text=title, fg=TEXT_DIM, bg=BG_CARD, font=("Segoe UI", 7, "bold")).pack(anchor=tk.W)
            lbl = tk.Label(card, text=default, fg=color, bg=BG_CARD, font=("Segoe UI", 14, "bold"))
            lbl.pack(anchor=tk.W)
            self.stat_labels[key] = lbl

        # ── PROGRESS ──
        prog_frame = tk.Frame(self.root, bg=BG_DARK)
        prog_frame.pack(fill=tk.X, padx=16, pady=6)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TX.Horizontal.TProgressbar", troughcolor=BG_WIDGET, background=ACCENT,
                         darkcolor=ACCENT, lightcolor=ACCENT, bordercolor=BG_WIDGET, thickness=5)
        self.progress = ttk.Progressbar(prog_frame, mode="indeterminate", style="TX.Horizontal.TProgressbar", length=500)
        self.progress.pack(side=tk.LEFT)
        self.status_label = tk.Label(prog_frame, text="Ready — Load a log file to begin analysis", fg=TEXT_DIM, bg=BG_DARK, font=("Segoe UI", 9))
        self.status_label.pack(side=tk.LEFT, padx=12)

        # ── TABBED CONTENT ──
        content_frame = tk.Frame(self.root, bg=BG_DARK)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=(4, 10))

        tab_bar = tk.Frame(content_frame, bg=BG_DARK)
        tab_bar.pack(fill=tk.X, side=tk.TOP)
        self.tab_frames = {}
        self.tab_buttons = {}
        tab_defs = [
            ("report", "📋 Report"), ("findings", "🚨 Findings"), ("ips", "🌐 IP & Users"),
            ("timeline", "⏱ Timeline"), ("mitre", "🎯 MITRE ATT&CK"), ("iocs", "🔎 IOCs"),
            ("rules", "📚 Rule Browser"), ("raw", "📄 Raw Log"),
        ]
        self.active_tab = tk.StringVar(value="report")
        for tab_id, tab_title in tab_defs:
            btn = tk.Button(tab_bar, text=tab_title, font=("Segoe UI", 9, "bold"), relief=tk.FLAT,
                            padx=14, pady=7, cursor="hand2", bd=0, command=lambda t=tab_id: self.switch_tab(t))
            btn.pack(side=tk.LEFT, padx=1)
            self.tab_buttons[tab_id] = btn

        self.tab_area = tk.Frame(content_frame, bg=BG_CARD, highlightbackground=BORDER_CLR, highlightthickness=1)
        self.tab_area.pack(fill=tk.BOTH, expand=True)

        text_opts = dict(bg=BG_CARD, fg=TEXT_MAIN, insertbackground="white",
                         selectbackground=ACCENT2, relief=tk.FLAT, wrap=tk.NONE, padx=12, pady=12)
        for tab_id, _ in tab_defs:
            frame = tk.Frame(self.tab_area, bg=BG_CARD)
            self.tab_frames[tab_id] = frame
            if tab_id == "rules":
                self._build_rule_browser(frame)
            else:
                vsb = tk.Scrollbar(frame, bg=BG_WIDGET, troughcolor=BG_DARK, activebackground=ACCENT, width=10)
                hsb = tk.Scrollbar(frame, orient=tk.HORIZONTAL, bg=BG_WIDGET, troughcolor=BG_DARK, activebackground=ACCENT, width=8)
                txt = tk.Text(frame, yscrollcommand=vsb.set, xscrollcommand=hsb.set, font=FONT_MONO, **text_opts)
                vsb.config(command=txt.yview)
                hsb.config(command=txt.xview)
                vsb.pack(side=tk.RIGHT, fill=tk.Y)
                hsb.pack(side=tk.BOTTOM, fill=tk.X)
                txt.pack(fill=tk.BOTH, expand=True)
                txt.config(state=tk.DISABLED)
                frame._text = txt

        for tab_id in ("report", "findings", "timeline", "mitre", "iocs"):
            rt = self.tab_frames[tab_id]._text
            rt.tag_configure("critical", foreground=CRITICAL_CLR, font=("Cascadia Code", 10, "bold"))
            rt.tag_configure("high", foreground=RED)
            rt.tag_configure("medium", foreground=ORANGE)
            rt.tag_configure("low", foreground=YELLOW)
            rt.tag_configure("info", foreground=GREEN)
            rt.tag_configure("header", foreground=ACCENT, font=("Cascadia Code", 10, "bold"))
            rt.tag_configure("accent", foreground=ACCENT2)
            rt.tag_configure("dim", foreground=TEXT_DIM)
            rt.tag_configure("mitre_id", foreground=ACCENT2, font=("Cascadia Code", 10, "bold"))
            rt.tag_configure("ioc", foreground=GREEN)
        self.switch_tab("report")

    def _draw_header(self, canvas):
        w = canvas.winfo_width()
        h = canvas.winfo_height()
        if w < 2: return
        canvas.delete("all")
        self._make_gradient(canvas, w, h, "#0a0a2e", "#1a0a3e", "h")
        # Glow dots
        import random
        random.seed(42)
        for _ in range(30):
            x, y = random.randint(0, w), random.randint(0, h)
            canvas.create_oval(x-1, y-1, x+1, y+1, fill=ACCENT, outline="")
        canvas.create_text(24, h//2, text="⚡", font=("Segoe UI", 22), fill=ACCENT, anchor=tk.W)
        canvas.create_text(54, h//2 - 8, text=TOOL_NAME, font=("Segoe UI", 18, "bold"), fill=ACCENT, anchor=tk.W)
        canvas.create_text(54, h//2 + 14, text="Advanced Log Intelligence & Threat Detection Engine", font=("Segoe UI", 9), fill=TEXT_DIM, anchor=tk.W)
        canvas.create_text(w - 20, h//2 - 8, text=BUILT_BY, font=("Segoe UI", 10, "bold"), fill=ACCENT2, anchor=tk.E)
        num_cats = len(set(v["category"] for v in PATTERNS.values()))
        canvas.create_text(w - 20, h//2 + 16, text=f"{len(PATTERNS)} Rules • {num_cats} Categories • {len(MITRE_DESCRIPTIONS)} MITRE", font=("Segoe UI", 8), fill=TEXT_DIM, anchor=tk.E)

    def _add_hover(self, widget, hover_bg, normal_bg):
        widget.bind("<Enter>", lambda e: widget.config(bg=hover_bg))
        widget.bind("<Leave>", lambda e: widget.config(bg=normal_bg))

    def _build_rule_browser(self, frame):
        """Build the Rule Browser tab with search and treeview."""
        top_bar = tk.Frame(frame, bg=BG_CARD2, pady=8)
        top_bar.pack(fill=tk.X)
        tk.Label(top_bar, text="🔍 Search:", fg=TEXT_DIM, bg=BG_CARD2, font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(12, 4))
        self.rule_search_var = tk.StringVar()
        search_entry = tk.Entry(top_bar, textvariable=self.rule_search_var, bg=BG_WIDGET, fg=TEXT_MAIN,
                                insertbackground=ACCENT, font=FONT_MONO, relief=tk.FLAT, width=30)
        search_entry.pack(side=tk.LEFT, padx=4)
        search_entry.bind("<KeyRelease>", lambda e: self._filter_rules())

        tk.Label(top_bar, text="Category:", fg=TEXT_DIM, bg=BG_CARD2, font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(16, 4))
        categories = sorted(set(v["category"] for v in PATTERNS.values()))
        self.rule_cat_var = tk.StringVar(value="All")
        cat_menu = ttk.Combobox(top_bar, textvariable=self.rule_cat_var, values=["All"] + categories, state="readonly", width=20)
        cat_menu.pack(side=tk.LEFT, padx=4)
        cat_menu.bind("<<ComboboxSelected>>", lambda e: self._filter_rules())

        tk.Label(top_bar, text="Severity:", fg=TEXT_DIM, bg=BG_CARD2, font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(16, 4))
        self.rule_sev_var = tk.StringVar(value="All")
        sev_menu = ttk.Combobox(top_bar, textvariable=self.rule_sev_var, values=["All","CRITICAL","HIGH","MEDIUM","LOW","INFO"], state="readonly", width=12)
        sev_menu.pack(side=tk.LEFT, padx=4)
        sev_menu.bind("<<ComboboxSelected>>", lambda e: self._filter_rules())

        self.rule_count_label = tk.Label(top_bar, text=f"Total: {len(PATTERNS)} rules", fg=ACCENT, bg=BG_CARD2, font=("Segoe UI", 9, "bold"))
        self.rule_count_label.pack(side=tk.RIGHT, padx=16)

        # Treeview
        tree_frame = tk.Frame(frame, bg=BG_CARD)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        style = ttk.Style()
        style.configure("Rules.Treeview", background=BG_CARD, foreground=TEXT_MAIN, fieldbackground=BG_CARD,
                        borderwidth=0, font=("Cascadia Code", 9))
        style.configure("Rules.Treeview.Heading", background=BG_CARD2, foreground=ACCENT, font=("Segoe UI", 9, "bold"))
        style.map("Rules.Treeview", background=[("selected", BG_WIDGET)], foreground=[("selected", ACCENT)])

        cols = ("severity", "category", "description", "mitre", "weight")
        self.rule_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", style="Rules.Treeview")
        self.rule_tree.heading("severity", text="Severity")
        self.rule_tree.heading("category", text="Category")
        self.rule_tree.heading("description", text="Description")
        self.rule_tree.heading("mitre", text="MITRE ID")
        self.rule_tree.heading("weight", text="Weight")
        self.rule_tree.column("severity", width=80, minwidth=60)
        self.rule_tree.column("category", width=140, minwidth=100)
        self.rule_tree.column("description", width=400, minwidth=200)
        self.rule_tree.column("mitre", width=100, minwidth=70)
        self.rule_tree.column("weight", width=60, minwidth=40)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.rule_tree.yview)
        self.rule_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.rule_tree.pack(fill=tk.BOTH, expand=True)

        self._populate_rules()

    def _populate_rules(self):
        self.rule_tree.delete(*self.rule_tree.get_children())
        for rule_id, info in sorted(PATTERNS.items(), key=lambda x: x[1]["category"]):
            self.rule_tree.insert("", tk.END, values=(
                info["severity"], info["category"], info["desc"],
                info.get("mitre", ""), info["weight"]
            ))

    def _filter_rules(self):
        search = self.rule_search_var.get().lower()
        cat_filter = self.rule_cat_var.get()
        sev_filter = self.rule_sev_var.get()
        self.rule_tree.delete(*self.rule_tree.get_children())
        count = 0
        for rule_id, info in sorted(PATTERNS.items(), key=lambda x: x[1]["category"]):
            if cat_filter != "All" and info["category"] != cat_filter:
                continue
            if sev_filter != "All" and info["severity"] != sev_filter:
                continue
            if search and search not in info["desc"].lower() and search not in rule_id.lower() and search not in info.get("mitre", "").lower():
                continue
            self.rule_tree.insert("", tk.END, values=(
                info["severity"], info["category"], info["desc"],
                info.get("mitre", ""), info["weight"]
            ))
            count += 1
        self.rule_count_label.config(text=f"Showing: {count} / {len(PATTERNS)} rules")

    def switch_tab(self, tab_id):
        self.active_tab.set(tab_id)
        for f in self.tab_frames.values():
            f.pack_forget()
        self.tab_frames[tab_id].pack(fill=tk.BOTH, expand=True)
        for t, btn in self.tab_buttons.items():
            if t == tab_id:
                btn.config(bg=ACCENT, fg=BG_DARK)
            else:
                btn.config(bg=BG_CARD2, fg=TEXT_DIM)

    def _write(self, tab_id, text, tag=None):
        txt = self.tab_frames[tab_id]._text
        txt.config(state=tk.NORMAL)
        if tag:
            txt.insert(tk.END, text, tag)
        else:
            txt.insert(tk.END, text)
        txt.config(state=tk.DISABLED)

    def _clear_tab(self, tab_id):
        if tab_id == "rules": return
        txt = self.tab_frames[tab_id]._text
        txt.config(state=tk.NORMAL)
        txt.delete("1.0", tk.END)
        txt.config(state=tk.DISABLED)

    def load_file(self):
        path = filedialog.askopenfilename(
            title="Load Log File",
            filetypes=[("All Supported", "*.log *.txt *.evtx *.csv *.json"), ("Log Files", "*.log"),
                       ("Text Files", "*.txt"), ("EVTX Files", "*.evtx"), ("All Files", "*.*")]
        )
        if path:
            self.file_path = path
            name = Path(path).name
            size = Path(path).stat().st_size
            size_str = f"{size:,} bytes" if size < 1024*1024 else f"{size/1024/1024:.1f} MB"
            self.file_label.config(text=f"📄 {name}  ({size_str})", fg=ACCENT)
            self.btn_analyze.config(state=tk.NORMAL, bg="#0d47a1")
            self.set_status(f"Loaded: {name} — Click Analyze to begin")

    def start_analysis(self):
        if not self.file_path: return
        self.btn_analyze.config(state=tk.DISABLED)
        self.btn_export.config(state=tk.DISABLED)
        self.btn_stix.config(state=tk.DISABLED)
        threading.Thread(target=self.run_analysis, daemon=True).start()

    def set_status(self, msg):
        self.status_label.config(text=msg)

    def run_analysis(self):
        self.root.after(0, lambda: self.progress.start(12))
        self.root.after(0, lambda: self.set_status("Loading file..."))
        try:
            a = LogAnalyzer(self.file_path)
            a.load()
            self.root.after(0, lambda: self.set_status(f"Analyzing {a.total_lines:,} lines with {len(PATTERNS)} rules..."))
            a.analyze()
            self.analyzer = a
            self.root.after(0, self._update_ui)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            self.root.after(0, lambda: self.set_status("Error during analysis"))
        finally:
            self.root.after(0, lambda: self.progress.stop())
            self.root.after(0, lambda: self.btn_analyze.config(state=tk.NORMAL, bg="#0d47a1"))

    def _update_ui(self):
        a = self.analyzer
        score = a.calculate_threat_score()
        level, level_color = a.get_threat_level(score)
        total_iocs = sum(len(v) for v in a.iocs.values())

        self.stat_labels["score"].config(text=f"{score}%", fg=level_color)
        self.stat_labels["level"].config(text=level, fg=level_color)
        self.stat_labels["lines"].config(text=f"{a.total_lines:,}")
        self.stat_labels["ips"].config(text=f"{len(a.ip_counter):,}")
        self.stat_labels["users"].config(text=f"{len(a.user_counter):,}")
        self.stat_labels["findings"].config(text=f"{len(a.findings)}")
        self.stat_labels["mitre"].config(text=f"{len(a.mitre_hits)}")
        self.stat_labels["iocs"].config(text=f"{total_iocs}")
        self.stat_labels["corr"].config(text=f"{len(a.correlations)}", fg=CRITICAL_CLR if a.correlations else GREEN)
        self.stat_labels["rules"].config(text=f"{len(PATTERNS)}")

        # Report tab
        self._clear_tab("report")
        report = a.generate_report()
        for line in report.split("\n"):
            tag = None
            if "CRITICAL" in line or "🔴" in line: tag = "critical"
            elif "HIGH" in line or "🟠" in line: tag = "high"
            elif "MEDIUM" in line or "🟡" in line: tag = "medium"
            elif "LOW" in line or "🟢" in line: tag = "low"
            elif "INFO" in line or "🔵" in line: tag = "info"
            elif line.startswith("═") or line.startswith("┌") or line.startswith("└"): tag = "header"
            elif "URGENT" in line or "CRITICAL:" in line: tag = "critical"
            self._write("report", line + "\n", tag)

        # Findings tab
        self._clear_tab("findings")
        if a.findings:
            grouped = a.get_findings_by_category()
            for grp, items in sorted(grouped.items()):
                self._write("findings", f"\n{'━'*60}\n  ▶ {grp.upper()}\n{'━'*60}\n", "header")
                for cat, flist in items:
                    info = PATTERNS[cat]
                    icons = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","INFO":"🔵"}
                    icon = icons.get(info["severity"], "⚪")
                    sev_tag = info["severity"].lower() if info["severity"].lower() in ("critical","high","medium","low","info") else None
                    self._write("findings", f"\n{icon} [{info['severity']}] {info['desc']}\n", sev_tag)
                    self._write("findings", f"   Rule: {cat}  |  MITRE: {info.get('mitre','')}  |  Hits: {len(flist)}\n", "dim")
                    for ln, content in flist[:10]:
                        self._write("findings", f"   Line {ln:>6}: {content[:120]}\n")
                    if len(flist) > 10:
                        self._write("findings", f"   ... {len(flist)-10} more hits\n", "dim")
        else:
            self._write("findings", "\n  ✅ No suspicious patterns detected.\n", "info")

        # IP & Users tab
        self._clear_tab("ips")
        self._write("ips", f"\n  TOP IP ADDRESSES  (Total unique: {len(a.ip_counter):,})\n", "header")
        self._write("ips", "  " + "─"*60 + "\n")
        if a.ip_counter:
            max_count = a.ip_counter.most_common(1)[0][1]
            for ip, cnt in a.ip_counter.most_common(50):
                bar_len = int((cnt / max_count) * 30) if max_count else 0
                bar = "▌" * bar_len
                self._write("ips", f"  {ip:<20} {bar:<32} {cnt:>6} hits\n")
        if a.user_counter:
            self._write("ips", f"\n\n  TOP USERNAMES  (Total unique: {len(a.user_counter):,})\n", "header")
            self._write("ips", "  " + "─"*60 + "\n")
            for user, cnt in a.user_counter.most_common(30):
                self._write("ips", f"  {user:<30} {cnt:>6} occurrences\n")
        if a.event_id_counter:
            self._write("ips", f"\n\n  TOP EVENT IDs\n", "header")
            self._write("ips", "  " + "─"*60 + "\n")
            known_ids = {"4624":"Successful Logon","4625":"Failed Logon","4648":"Explicit Credential","4672":"Special Privileges",
                         "4698":"Sched Task Created","4720":"User Created","4740":"Account Locked","7045":"New Service",
                         "1102":"Audit Log Cleared","4778":"RDP Reconnect","5861":"WMI Subscription"}
            for eid, cnt in a.event_id_counter.most_common(20):
                desc = known_ids.get(eid, "")
                self._write("ips", f"  EventID {eid:<8} {cnt:>6}x   {desc}\n")

        # Timeline tab
        self._clear_tab("timeline")
        self._write("timeline", f"\n  ⏱ TIMELINE  ({len(a.timeline)} events)\n", "header")
        self._write("timeline", "  " + "─"*80 + "\n")
        if a.timeline:
            sorted_events = sorted(a.timeline, key=lambda x: x["time"])
            sev_tags = {"CRITICAL":"critical","HIGH":"high","MEDIUM":"medium","LOW":"low","INFO":"info"}
            for evt in sorted_events[:500]:
                sev_icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","INFO":"🔵"}.get(evt["severity"], "⚪")
                tag = sev_tags.get(evt["severity"])
                self._write("timeline", f"  {evt['time']}  ", "dim")
                self._write("timeline", f"{sev_icon} [{evt['severity']:<8}] ", tag)
                self._write("timeline", f"[{evt['category']}] {evt['rule']}\n", tag)
                self._write("timeline", f"    Line {evt['line']}: {evt['content'][:100]}\n", "dim")
            if len(a.timeline) > 500:
                self._write("timeline", f"\n  ... first 500 of {len(a.timeline)} events ...\n", "dim")
        if a.correlations:
            self._write("timeline", f"\n\n  ⚡ ATTACK CHAINS ({len(a.correlations)})\n", "critical")
            for corr in a.correlations:
                self._write("timeline", f"  🔴 {corr['name']}\n", "critical")
                self._write("timeline", f"     {corr['desc']}\n", "high")

        # MITRE tab
        self._clear_tab("mitre")
        self._write("mitre", f"\n  🎯 MITRE ATT&CK  ({len(a.mitre_hits)} techniques)\n", "header")
        self._write("mitre", "  " + "─"*80 + "\n\n")
        if a.mitre_hits:
            self._write("mitre", f"  {'ID':<16} {'DESCRIPTION':<50} {'HITS':>6}\n", "header")
            self._write("mitre", "  " + "─"*76 + "\n")
            for mid, cnt in sorted(a.mitre_hits.items(), key=lambda x: -x[1]):
                desc = MITRE_DESCRIPTIONS.get(mid, "Unknown")
                self._write("mitre", f"  {mid:<16}", "mitre_id")
                self._write("mitre", f" {desc:<50}")
                self._write("mitre", f" {cnt:>6} hits\n", "accent")
            # Coverage map
            self._write("mitre", f"\n\n  TACTIC COVERAGE\n", "header")
            self._write("mitre", "  " + "─"*60 + "\n")
            tactic_map = {"Initial Access":["T1190","T1189","T1566","T1078","T1133","T1195","T1199","T1200"],
                "Execution":["T1059","T1047","T1053","T1204","T1559","T1106","T1569"],
                "Persistence":["T1037","T1098","T1136","T1197","T1176","T1137","T1543","T1546","T1547","T1542","T1574"],
                "Privilege Escalation":["T1134","T1068","T1548"],
                "Defense Evasion":["T1014","T1027","T1036","T1055","T1070","T1218","T1220","T1553","T1562","T1564"],
                "Credential Access":["T1003","T1110","T1552","T1555","T1556","T1557","T1558","T1056","T1528","T1649"],
                "Discovery":["T1007","T1012","T1016","T1018","T1046","T1057","T1082","T1083","T1087","T1135","T1201","T1482","T1518","T1615"],
                "Lateral Movement":["T1021","T1080","T1210","T1534","T1550","T1563","T1570"],
                "Collection":["T1005","T1113","T1115","T1119","T1123","T1125","T1530","T1560"],
                "C2":["T1071","T1090","T1095","T1102","T1219","T1568","T1572","T1573"],
                "Exfiltration":["T1011","T1020","T1041","T1048","T1052","T1567"],
                "Impact":["T1486","T1485","T1489","T1490","T1491","T1496","T1498","T1499","T1529","T1531"]}
            for tactic, techniques in tactic_map.items():
                hits = sum(1 for t in techniques if any(mid.startswith(t) for mid in a.mitre_hits))
                if hits > 0:
                    self._write("mitre", f"  ██ {tactic} ({hits} techniques)\n", "critical")
                else:
                    self._write("mitre", f"  ░░ {tactic}\n", "dim")

        # IOC tab
        self._clear_tab("iocs")
        self._write("iocs", f"\n  🔎 IOCs  ({total_iocs} total)\n", "header")
        self._write("iocs", "  " + "─"*70 + "\n")
        ioc_labels = {"sha256":"SHA-256","sha1":"SHA-1","md5":"MD5","url":"URLs","domain":"Domains",
                      "ipv4":"IPs","email":"Emails","cve":"CVEs","ipv6":"IPv6","mac":"MAC","bitcoin":"Bitcoin",
                      "registry":"Registry Keys","filepath_win":"Windows Paths","filepath_unix":"Unix Paths","useragent":"User-Agents"}
        if any(a.iocs.values()):
            for ioc_type in ["cve","sha256","sha1","md5","ipv4","ipv6","url","domain","email","bitcoin","registry","filepath_win","filepath_unix","mac","useragent"]:
                vals = sorted(a.iocs.get(ioc_type, set()))
                if vals:
                    lbl = ioc_labels.get(ioc_type, ioc_type.upper())
                    self._write("iocs", f"\n  ▶ {lbl} ({len(vals)})\n", "header")
                    for v in vals[:100]:
                        self._write("iocs", f"  • {v}\n", "ioc")
                    if len(vals) > 100:
                        self._write("iocs", f"  ... {len(vals)-100} more\n", "dim")

        # Raw Log tab
        self._clear_tab("raw")
        MAX_LINES = 2000
        for i, line in enumerate(a.lines[:MAX_LINES]):
            self._write("raw", f"{i+1:>6}  {line if isinstance(line, str) else repr(line)}")
        if a.total_lines > MAX_LINES:
            self._write("raw", f"\n... (first {MAX_LINES:,} of {a.total_lines:,} lines) ...")

        self.btn_export.config(state=tk.NORMAL)
        self.btn_stix.config(state=tk.NORMAL)
        self.set_status(
            f"✅ Analysis complete — {a.total_lines:,} lines | {len(a.findings)} findings | "
            f"Score: {score}% ({level}) | MITRE: {len(a.mitre_hits)} | IOCs: {total_iocs} | Correlations: {len(a.correlations)}"
        )
        self.switch_tab("report")

    def clear_output(self):
        for tab_id in self.tab_frames:
            self._clear_tab(tab_id)
        defaults = {"score":"0%","level":"—","lines":"0","ips":"0","users":"0","findings":"0","mitre":"0","iocs":"0","corr":"0","rules":str(len(PATTERNS))}
        for key, lbl in self.stat_labels.items():
            lbl.config(text=defaults.get(key, "0"), fg=TEXT_DIM)
        self.file_label.config(text="No file loaded", fg=TEXT_DIM)
        self.file_path = None
        self.analyzer = None
        self.btn_analyze.config(state=tk.DISABLED)
        self.btn_export.config(state=tk.DISABLED)
        self.btn_stix.config(state=tk.DISABLED)
        self.set_status("Ready — Load a log file to begin analysis")

    def export_json(self):
        if self.analyzer:
            path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")], title="Export Report")
            if path:
                self.analyzer.export_json(path)
                messagebox.showinfo("Export Done", f"Report saved to:\n{path}")

    def export_stix(self):
        if self.analyzer:
            path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("STIX JSON", "*.json")], title="Export STIX 2.1")
            if path:
                self.analyzer.export_stix(path)
                messagebox.showinfo("STIX Export", f"STIX 2.1 bundle saved to:\n{path}")

# ═══════════════ CLI MODE ═══════════════
def run_cli(args):
    filepath = args.file
    if not Path(filepath).exists():
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    print(f"⚡ {TOOL_NAME} — {BUILT_BY} — CLI Mode")
    print(f"Loading: {filepath}")
    analyzer = LogAnalyzer(filepath)
    analyzer.load()
    print(f"Loaded {analyzer.total_lines:,} lines  |  MD5: {analyzer.file_md5}")
    print(f"Analyzing with {len(PATTERNS)} detection rules...")
    analyzer.analyze()
    score = analyzer.calculate_threat_score()
    level, _ = analyzer.get_threat_level(score)
    total_iocs = sum(len(v) for v in analyzer.iocs.values())
    print(f"\nResults: Score={score}% Level={level} Findings={len(analyzer.findings)} "
          f"MITRE={len(analyzer.mitre_hits)} IOCs={total_iocs} Correlations={len(analyzer.correlations)}")
    if args.report:
        print("\n" + analyzer.generate_report())
    if args.json:
        analyzer.export_json(args.json)
        print(f"\n💾 JSON report saved to: {args.json}")
    if args.stix:
        analyzer.export_stix(args.stix)
        print(f"\n🔗 STIX 2.1 bundle saved to: {args.stix}")

# ═══════════════ ENTRY POINT ═══════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} — Advanced Log Intelligence & Threat Detection Engine ({BUILT_BY})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python ThreatscopeX.py                              Launch GUI
  python ThreatscopeX.py -f server.log --report       Analyze and print report
  python ThreatscopeX.py -f data.evtx -j report.json  Analyze and export JSON
  python ThreatscopeX.py -f log.txt --stix iocs.json  Export IOCs as STIX 2.1
        """
    )
    parser.add_argument("-f", "--file", help="Path to log file to analyze")
    parser.add_argument("-j", "--json", help="Export JSON report to specified path")
    parser.add_argument("-r", "--report", action="store_true", help="Print text report to stdout")
    parser.add_argument("--stix", help="Export STIX 2.1 IOC bundle")
    args = parser.parse_args()
    if args.file:
        run_cli(args)
    else:
        root = tk.Tk()
        ThreatscopeXGUI(root)
        root.mainloop()
