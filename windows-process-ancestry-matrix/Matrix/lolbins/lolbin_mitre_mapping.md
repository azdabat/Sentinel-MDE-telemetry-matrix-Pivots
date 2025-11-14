# LOLBin → MITRE ATT&CK Mapping (Full Context)

This matrix explains:

- **Which MITRE ATT&CK techniques each LOLBin aligns to**
- **Which MITRE tactics they support**
- **Why attackers use the LOLBin for that technique**
- **What the behaviour normally looks like in real-world incidents**

Use this to justify detections, write rules, improve hunts, and explain alerts in incident reports.

---

| LOLBin | MITRE Technique (ID + Name) | MITRE Tactic(s) | Why the LOLBin Is Used (Context) |
|--------|------------------------------|------------------|----------------------------------|
| **powershell.exe** | **T1059.001 – PowerShell**<br>**T1105 – Exfiltration/Ingress Tool Transfer**<br>**T1082 – System Information Discovery**<br>**T1018 – Remote System Discovery** | Execution, Command & Control, Discovery, Lateral Movement | PowerShell provides full scripting support, remote execution, WMI access, .NET loading, encoded payload execution, and easy C2 communication. Attackers use it for recon, payload staging, downloading malware, running C2 beacons, and automating post-exploitation. |
| **cmd.exe** | **T1059.003 – Windows Command Shell**<br>**T1105 – Remote File Copy**<br>**T1053 – Scheduled Task/Job** | Execution, Persistence, Lateral Movement, Discovery | Attackers use cmd.exe as a universal LOLBin to chain commands, drop files, launch other LOLBins, automate persistence (schtasks), or pivot laterally through scripts. It is often the “glue” in attack chains. |
| **wscript.exe** | **T1059.005 – Visual Basic / JScript Execution**<br>**T1204 – User Execution**<br>**T1105 – Download & Execute Payloads** | Execution, Initial Access, Defense Evasion | Used to execute malicious VBS/JS payloads delivered via phishing or HTML smuggling. Supports heavy obfuscation. Frequently used by Emotet, QakBot, RATs, and script-heavy malware. |
| **cscript.exe** | **T1059.005 – Visual Basic / JScript Execution**<br>**T1204 – User Execution**<br>**T1105 – Remote Payload Download** | Execution, Initial Access, Delivery | Same abuse model as wscript.exe but console-based. Used by malware for scripted recon, payload staging, and running obfuscated script logic. |
| **mshta.exe** | **T1218.005 – Mshta.exe** (Signed Binary Proxy Execution)<br>**T1204 – User Execution**<br>**T1105 – Download/Execute** | Execution, Defense Evasion, Initial Access | Allows execution of remote or inline HTML/JS/VBS with trusted signed Microsoft binary. Used heavily in HTML smuggling, stagers, remote payload execution, and bypassing AppLocker/EDR. |
| **rundll32.exe** | **T1218.011 – Rundll32.exe**<br>**T1105 – Remote Payload Loading**<br>**T1055 – Process Injection / DLL Execution** | Execution, Defense Evasion, Privilege Escalation | Used to execute DLL exports without needing an EXE. Perfect for DLL sideloading, process injection, and executing shellcode. Popular in Cobalt Strike, QakBot, TrickBot, and ransomware loaders. |
| **regsvr32.exe** | **T1218.010 – Regsvr32 (Signed Binary Proxy)**<br>**T1547 – Persistence (Registry/COM)**<br>**T1055 – DLL Execution** | Execution, Persistence, Defense Evasion | Allows registering (or silently loading) COM DLLs from web, SMB, or user-writable folders. Used for COM hijacking, remote DLL execution, and fileless stagers via “/s” or scriptlet abuse. |
| **reg.exe** | **T1112 – Modify Registry**<br>**T1547 – Run Keys/Startup Folder**<br>**T1562 – Defense Evasion** | Persistence, Defense Evasion | Attackers modify registry for Run keys, service tampering, UAC bypass, RDP enabling, EDR tampering, password caching modification, etc. |
| **schtasks.exe** | **T1053.005 – Scheduled Task**<br>**T1059 – Command Execution**<br>**T1055 – Task → Payload Execution** | Persistence, Execution, Lateral Movement | Used to create persistent tasks, scheduled beacons, lateral task execution on remote hosts, and repeated malware launch points. |
| **sc.exe** | **T1543.003 – Windows Services**<br>**T1059 – Execution**<br>**T1569.002 – Service Execution** | Persistence, Privilege Escalation, Lateral Movement | Used to create malicious services, run service-executed payloads remotely (PsExec-like), modify service configs, and load drivers (BYOVD). |
| **certutil.exe** | **T1105 – Payload Download**<br>**T1140 – Deobfuscate/Decode Files**<br>**T1041 – Exfiltration Over C2 Channel** | Command & Control, Exfiltration, Execution | Allows attackers to download malware, decode base64 payloads, export certificates for exfiltration, and bypass proxy/EDR controls. |
| **bitsadmin.exe** | **T1105 – Ingress Tool Transfer**<br>**T1071.001 – Application Layer Protocol (Web)** | Command & Control, Delivery | Although deprecated, still abused for stealthy downloads via BITS jobs, often used by APTs for long-running, low-profile payload staging. |
| **msiexec.exe** | **T1218.007 – Msiexec Execution**<br>**T1105 – Payload Delivery** | Execution, Initial Access | Used for installing malicious MSI payloads, executing DLLs, side-loading malicious installers, or pulling MSI packages from remote URLs. |
| **installutil.exe** | **T1218.004 – InstallUtil.exe Abused**<br>**T1059 – Execution** | Execution, Defense Evasion | Executes .NET assemblies via a signed Microsoft binary. Perfect for attackers hiding C# payloads or shellcode runners in “installer classes.” |
| **regedit.exe** | **T1112 – Modify Registry**<br>**T1547 – Registry-Based Persistence** | Persistence | Attackers use regedit to manually or programmatically modify persistence keys, disable security features, or stage environment changes. |
| **msbuild.exe** | **T1127 – MSBuild Abuse**<br>**T1059 – C# In-Memory Execution** | Execution, Defense Evasion | Allows inline C# execution via XAML tasks. Used by APTs and pentesters to run C# implants filelessly inside a signed Microsoft binary. |
| **wmic.exe** | **T1047 – WMI Execution**<br>**T1059 – Command Execution** | Execution, Discovery, Lateral Movement | Used for remote command execution, process spawning, recon (users, groups, processes), and distributed lateral movement via WMI. |
| **psexec / psexesvc.exe** | **T1021.002 – SMB/Service Lateral Movement**<br>**T1569.002 – Service Execution** | Lateral Movement, Privilege Escalation | Used to execute commands remotely via ADMIN$ + service creation. Seen in ransomware propagation and APT lateral movement. |
| **rdpclip.exe** | **T1021.001 – Remote Desktop Protocol** (supporting) | Lateral Movement, Collection | Used as a staging point for clipboard data exfiltration inside RDP sessions. Rarely launched by malware directly but signals RDP abuse. |
| **dllhost.exe** | **T1055 – Process Injection**<br>**T1547.009 – COM Hijacking** | Persistence, Execution, Defense Evasion | Used for COM object hijacking, shellcode hosting, in-memory injection, DLL surrogate abuse, and evading EDR by hiding execution inside dllhost.exe. |

