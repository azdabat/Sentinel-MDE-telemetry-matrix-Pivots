# 🔥 LOLBIN Detection Rulepack (20 Rules, MDE-KQL, GitHub-Ready)

This file contains **20 Living-off-the-Land Binary (LOLBIN) detection rules** for **Microsoft Defender for Endpoint (MDE)**, all written in **valid Advanced Hunting KQL** with correct table and field names.

Each rule includes:

- **Rule Number & Name**
- **MDE Table**
- **Concrete KQL Query**
- **What It Detects & Why It Matters**

You can paste this file **directly into GitHub** as `lolbin_rulepack.md` or similar.

---

## 1. Suspicious Rundll32 with Rare Function

**MDE Table:** `DeviceProcessEvents`

**What it detects & why**  
**Attack:** `rundll32.exe` executing DLLs via **ordinal values** (like `#1`, `#2`) or functions like `DllRegisterServer` often associated with registration or side-loading behaviour.  
**Why:** Using ordinals or DllRegisterServer is a way to **obfuscate the called export** and hide intent from casual inspection and basic detections.

```kql
// Rundll32 using rare/abused export functions or ordinal values
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_any ("#1", "#2", "DllRegisterServer")
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## 2. Rundll32 Executing from Unusual Path

**MDE Table:** `DeviceProcessEvents`

**What it detects & why**  
**Attack:** `rundll32.exe` executing from **non-standard directories**, such as `C:\Users\Public\` or temp folders.  
**Why:** Legitimate `rundll32.exe` lives under `C:\Windows\System32` or `C:\Windows\SysWOW64`.  
Execution elsewhere is a strong indicator of a **dropped / rogue binary** (masquerading).

```kql
// Rundll32 not running from normal Windows system paths
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName =~ "rundll32.exe"
| where FolderPath !startswith @"C:\Windows\System32"
  and FolderPath !startswith @"C:\Windows\SysWOW64"
| project Timestamp, DeviceName, AccountName,
          FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## 3. Regsvr32 with Remote Scriptlet

**MDE Table:** `DeviceProcessEvents`

**What it detects & why**  
**Attack:** `regsvr32.exe` using **`scrobj.dll`** with `/s` and loading a scriptlet via `http` URL.  
**Why:** This is the classic **scriptlet proxy execution** pattern that allows running code from the web through a signed Windows binary, often bypassing allowlisting.

```kql
// Regsvr32 using scrobj.dll and remote scriptlet URLs
DeviceProcessEvents
| where Timestamp >= ago(14d)
| where FileName =~ "regsvr32.exe"
| where ProcessCommandLine has "scrobj.dll"
      and ProcessCommandLine has "/s"
      and ProcessCommandLine has "http"
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## 4. Mshta Executing Remote HTA or Script

**MDE Table:** `DeviceProcessEvents`

**What it detects & why**  
**Attack:** `mshta.exe` running remote HTA/JavaScript/VBScript from a URL or inline `javascript:`/`vbscript:` prefix.  
**Why:** `mshta.exe` is a legacy signed binary often abused to execute script-based payloads directly from the internet.

```kql
// Mshta executing HTA / JavaScript / VBScript from URLs or inline script
DeviceProcessEvents
| where Timestamp >= ago(14d)
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has_any ("http", "https", "javascript:", "vbscript:")
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## 5. Certutil Downloading Files

**MDE Table:** `DeviceProcessEvents`

**What it detects & why**  
**Attack:** `certutil.exe` abused with **`-urlcache` / `-split` / `-ping`** to download or retrieve remote files.  
**Why:** `certutil` is a legitimate certificate utility, but its download parameters are often abused to bypass network controls and stage payloads.

```kql
// Certutil used as a download / staging LOLBin
DeviceProcessEvents
| where Timestamp >= ago(14d)
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-urlcache", "-split", "-ping")
      and ProcessCommandLine has_any ("http", "https")
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## 6. BITSAdmin Downloading to Suspicious Location

**MDE Table:** `DeviceProcessEvents`

**What it detects & why**  
**Attack:** `bitsadmin.exe` using `/transfer` to download content to **user-writable locations** such as `C:\Users\`, `C:\Temp\`, or to `.exe` payloads.  
**Why:** BITS is normally used for patching or background system activity; custom downloads to user paths are highly suspicious.

```kql
// BITSAdmin downloads to user/temporary locations
DeviceProcessEvents
| where Timestamp >= ago(14d)
| where FileName =~ "bitsadmin.exe"
| where ProcessCommandLine has " /transfer "
      and ProcessCommandLine has_any ("C:\Users\", "C:\Temp\", ".exe")
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## 7. MSBuild Executing from Non-Dev Paths

**MDE Table:** `DeviceProcessEvents`

**What it detects & why**  
**Attack:** `MSBuild.exe` executing from paths **not tied to Visual Studio / MSBuild bins**.  
**Why:** This pattern is typical for **inline C#/project-based payloads** — MSBuild is used as a “compiler LOLBin” to run arbitrary code.

```kql
// MSBuild running projects from unusual locations
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where FileName =~ "msbuild.exe"
| where FolderPath !contains "Microsoft Visual Studio"
  and FolderPath !contains "MSBuild\Current\Bin"
| project Timestamp, DeviceName, AccountName,
          FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## 8. WMI for Remote Process Creation

**MDE Table:** `DeviceProcessEvents`

**What it detects & why**  
**Attack:** `wmic.exe` used to create processes on **remote hosts** via `process call create \\TARGET`.  
**Why:** This is a classic technique for **lateral movement** using WMI without dropping dedicated tooling.

```kql
// WMI command-line used for remote process creation
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where FileName =~ "wmic.exe"
| where ProcessCommandLine has_all ("process", "call", "create", "\\")
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## 9. Script Engines Spawning LOLBins

**MDE Table:** `DeviceProcessEvents`

**What it detects & why**  
**Attack:** `wscript.exe` / `cscript.exe` acting as **parents** to LOLBins such as `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `msbuild.exe`.  
**Why:** Common infection chains: phishing → script (VBS/JS) → LOLBin payload runner.

```kql
// Script engines spawning common LOLBins
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe")
| where FileName in~ ("rundll32.exe","regsvr32.exe","mshta.exe","msbuild.exe")
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine
```

---

## 10. Suspicious LOLBin Network Connections

**MDE Table:** `DeviceNetworkEvents`

**What it detects & why**  
**Attack:** LOLBins making outbound connections to **low-reputation / commodity TLDs** often associated with cybercrime (`.xyz`, `.top`, `.live`, etc.).  
**Why:** When signed Windows binaries (LOLBins) reach out to sketchy TLDs, it strongly suggests **C2 or payload fetch**.

```kql
// LOLBins connecting to suspicious / commodity TLDs
DeviceNetworkEvents
| where Timestamp >= ago(14d)
| where InitiatingProcessFileName in~ (
    "rundll32.exe","regsvr32.exe","mshta.exe",
    "msbuild.exe","wscript.exe","cscript.exe"
)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any (".xyz", ".top", ".live", ".biz", ".club",
                           ".download", ".ga", ".gq", ".ml", ".cf")
| project Timestamp, DeviceName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          RemoteUrl, RemoteIP, RemotePort
```

---

## 11. Control.exe & App Whitelisting Bypass

**MDE Table:** `DeviceProcessEvents`

**What it detects & why**  
**Attack:** `control.exe` invoked with `ms-settings:` protocol to indirectly execute functionality in **trusted system components**.  
**Why:** This pattern can be used to bypass some application control/whitelisting policies.

```kql
// Control.exe abusing ms-settings protocol
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where FileName =~ "control.exe"
| where ProcessCommandLine has "ms-settings:"
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## 12. Forfiles.exe for DLL / EXE Execution

**MDE Table:** `DeviceProcessEvents`

**What it detects & why**  
**Attack:** `forfiles.exe` abused with `/c` to invoke `.dll` or `.exe` across files, often in user directories.  
**Why:** Another **iteration / execution LOLBin**, useful for side-loading or mass execution.

```kql
// Forfiles used to execute DLL/EXE payloads
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where FileName =~ "forfiles.exe"
| where ProcessCommandLine has " /c "
      and ProcessCommandLine has_any (".dll", ".exe")
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## 13. Pubprn.vbs & Scriptlet Abuse

**MDE Table:** `DeviceProcessEvents`

**What it detects & why**  
**Attack:** `cscript.exe` running `pubprn.vbs` with a remote `http` URL to execute scriptlets.  
**Why:** Variation on scriptlet-based LOLBIN abuse, similar to regsvr32 scriptlet patterns.

```kql
// Pubprn.vbs used with remote scriptlet URLs
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where InitiatingProcessFileName =~ "cscript.exe"
| where ProcessCommandLine has "pubprn.vbs"
      and ProcessCommandLine has_any ("http","https")
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine
```

---

## 14. Register-CimProvider with Suspicious DLL

**MDE Table:** `DeviceProcessEvents`

**What it detects & why**  
**Attack:** `Register-CimProvider.exe` loading DLLs from `C:\Users\` or `C:\Temp\`.  
**Why:** This binary can register **WMI providers**, and if pointed to a malicious DLL, can execute with high integrity.

```kql
// Register-CimProvider loading DLLs from user/temporary paths
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where FileName =~ "Register-CimProvider.exe"
| where ProcessCommandLine has ".dll"
      and ProcessCommandLine has_any ("C:\Users\","C:\Temp\")
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## 15. Suspicious Xwizard.exe Usage

**MDE Table:** `DeviceProcessEvents`

**What it detects & why**  
**Attack:** `xwizard.exe` (Extensible Wizard Host) used with `run` to execute arbitrary commands.  
**Why:** Less well-known LOLBin which can host **custom execution logic**.

```kql
// Xwizard.exe invoked with 'run' command
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where FileName =~ "xwizard.exe"
| where ProcessCommandLine has " run"
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## 16. Advanced Msiexec Web Installation

**MDE Table:** `DeviceProcessEvents`

**What it detects & why**  
**Attack:** `msiexec.exe /i` installing packages directly from **non-corporate HTTP(S) sources**.  
**Why:** Direct MSI install from the internet is a common malware delivery method.

```kql
// Msiexec installing MSI from untrusted web sources
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine has "/i"
      and ProcessCommandLine has_any ("http","https")
      and ProcessCommandLine !has "your-corporate-server.com"
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## 17. PowerShell → Rundll32 Multi-Stage Chain

**MDE Table:** `DeviceProcessEvents`

**What it detects & why**  
**Attack:** `powershell.exe` as parent spawning `rundll32.exe` with suspicious command line content (scripts, URLs, etc.).  
**Why:** Typical of multi-stage chains where PowerShell handles download/decode, and rundll32 executes payload.

```kql
// PowerShell spawning Rundll32 with suspicious parameters
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where InitiatingProcessFileName =~ "powershell.exe"
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_any ("javascript", "http", "https", ".vbs")
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine
```

---

## 18. Suspicious Pcalua.exe Usage

**MDE Table:** `DeviceProcessEvents`

**What it detects & why**  
**Attack:** `pcalua.exe` (Program Compatibility Assistant Launcher) invoked with `-a` to start arbitrary executables.  
**Why:** Legacy helper binary which may **evade some detection logic** focused on more common loaders.

```kql
// Pcalua.exe used to launch arbitrary executables
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where FileName =~ "pcalua.exe"
| where ProcessCommandLine has "-a"
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## 19. Explorer.exe with Suspicious Child LOLBins

**MDE Table:** `DeviceProcessEvents`

**What it detects & why**  
**Attack:** `explorer.exe` spawning script engines or LOLBins (`cmd.exe`, `powershell.exe`, `rundll32.exe`) with suspicious parameters.  
**Why:** While users do legitimately launch these from Explorer, **script-like flags** (`/c`, `-Command`, `javascript`) point to malicious shortcut / exploit behaviour.

```kql
// Explorer launching LOLBins with suspicious command-line switches
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("cmd.exe","powershell.exe","rundll32.exe")
| where ProcessCommandLine has_any ("/c","-Command","javascript")
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine
```

---

## 20. Suspicious Odbcinstall Usage

**MDE Table:** `DeviceProcessEvents`

**What it detects & why**  
**Attack:** `odbcinstall.exe` registering DLLs using `-f <path>.dll`.  
**Why:** Another system tool that can be repurposed for **DLL side-loading or persistence**.

```kql
// Odbcinstall.exe registering DLLs
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where FileName =~ "odbcinstall.exe"
| where ProcessCommandLine has "-f"
      and ProcessCommandLine has ".dll"
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## 💡 Deployment and Tuning Recommendations

**1. Test Thoroughly First**  
Run these queries in **Advanced Hunting** before promoting them to analytics rules:

- Check which rules are **noisiest** in your estate.  
- Add **environment-specific allowlists** for known admin tools, management servers, or EDR orchestrators.

---

**2. Promote to Custom Detection Rules**  

For rules with good signal:

- Create **Custom detection rules** in the Defender portal.  
- Set:
  - Clear **Alert title** (e.g., _“LOLBIN – Mshta Remote Script Execution”_)
  - **Severity** based on impact (e.g., Medium/High)
  - **MITRE ATT&CK mapping** (e.g., T1218, T1059, T1105)

---

**3. Use Continuous (NRT) for High-Signal Patterns**  

For rules that:

- Use a **single supported table** (e.g., only `DeviceProcessEvents`), and  
- Have been tuned to low noise  

→ consider **Continuous (Near-Real Time)** frequency so that alerts trigger **within minutes** of suspicious activity.

---

**4. Build Hunt Playbooks Around These Rules**  

For each detection, define:

- **Triage steps** (what to check next: network, file, registry, logon)  
- **Pivot queries** (e.g., join with `DeviceNetworkEvents`, `DeviceFileEvents`)  
- **Containment actions** (isolate device, block hash, revoke token, disable user, etc.)

This rulepack is designed as an **L2–L3 analyst accelerator**: you can use it as both a **hunting workbook** and a **custom detection seed list**.

