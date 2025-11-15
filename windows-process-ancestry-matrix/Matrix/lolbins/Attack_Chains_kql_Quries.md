# Attack Chain KQL Detection Pack (1–20)
> With Basic / Medium / Advanced queries  
> Advanced queries include broad LOLBin coverage (beyond the core LOLBAS set)

All queries assume Defender for Endpoint schema (MDE / Sentinel advanced hunting):
This is a starter kit. You can create the rest of your rules on this rule logic as most LOLBin logic is the same.
Once you learn these types of the rules, threat modelling other attacks and attack chains becomes easier.

- `DeviceProcessEvents`
- `DeviceNetworkEvents`
- `DeviceFileEvents`
- `DeviceRegistryEvents`
- `DeviceImageLoadEvents` (if enabled)
- `SecurityEvent` (if connected)

You can adapt easily to Sentinel-only environments.

---

## 🌐 Common Let Blocks (Reuse Across Queries)

```kql
// Global lookback
let Lookback = 7d;

// Core LOLBins (heavily abused, documented in LOLBAS)
let CoreLolBins = dynamic([
  "powershell.exe","pwsh.exe","cmd.exe",
  "wscript.exe","cscript.exe","mshta.exe",
  "rundll32.exe","regsvr32.exe","reg.exe",
  "schtasks.exe","sc.exe","certutil.exe",
  "bitsadmin.exe","msiexec.exe","installutil.exe",
  "msbuild.exe","wmic.exe","wbemtest.exe"
]);

// Extended LOLBins / “near-LOLBins” commonly abused in real intrusions
// (goes beyond strict LOLBAS list – admin tools, built-in components, etc.)
let ExtendedLolBins = dynamic([
  "xwizard.exe","odbcconf.exe","rdrleakdiag.exe","hh.exe",
  "control.exe","presentationhost.exe","pcalua.exe","csc.exe",
  "forfiles.exe","netsh.exe","robocopy.exe","taskmgr.exe",
  "wevtutil.exe","at.exe","atbroker.exe","wmiprvse.exe",
  "dllhost.exe","msdt.exe","scriptrunner.exe","print.exe",
  "printui.exe","regedit.exe"
]);

// Union of both sets for “max suspicious binaries”
let AllSuspiciousBins = array_concat(CoreLolBins, ExtendedLolBins);
```

---

## 1. Phishing Doc → Macro → PowerShell Loader → C2

### Basic

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "powershell.exe"
| where ParentProcessName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
```

### Medium

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "powershell.exe"
| where ParentProcessName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| where ProcessCommandLine has_any ("-enc","FromBase64String","IEX","DownloadString","-executionpolicy","bypass","http","https")
```

### Advanced (Office → any LOLBin → staging + C2)

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in (AllSuspiciousBins)
| where ParentProcessName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| extend Cmd = tostring(ProcessCommandLine)
| summarize
    Earliest=min(Timestamp),
    Latest=max(Timestamp),
    Examples=make_set(Cmd, 5),
    ChildBins=make_set(FileName, 10)
  by DeviceId, DeviceName, AccountName, ParentProcessName
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp >= ago(Lookback)
) on DeviceId
| summarize
    Earliest=min(Earliest),
    Latest=max(Latest),
    AnyRemoteIps=make_set(RemoteIP, 10),
    AnyUrls=make_set(RemoteUrl, 10),
    ChildBins=any(ChildBins),
    ExampleCmds=any(Examples)
  by DeviceId, DeviceName, AccountName, ParentProcessName
| project Earliest, Latest, DeviceName, AccountName, ParentProcessName, ChildBins, AnyRemoteIps, AnyUrls, ExampleCmds
```

---

## 2. HTML Smuggling → MSHTA → PowerShell → Payload

### Basic

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "mshta.exe"
| where ParentProcessName in~ ("chrome.exe","msedge.exe","firefox.exe","iexplore.exe","winword.exe","outlook.exe")
```

### Medium

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "mshta.exe"
| where ParentProcessName in~ ("chrome.exe","msedge.exe","firefox.exe","iexplore.exe","winword.exe","outlook.exe")
| where ProcessCommandLine has_any ("http://","https://","javascript:","vbscript:",".hta")
```

### Advanced (mshta + script + PS, plus XSL-based LOLBin abuse)

```kql
let MshtaParents = dynamic(["chrome.exe","msedge.exe","firefox.exe","iexplore.exe","winword.exe","outlook.exe"]);
let XslConsumers = dynamic(["wmic.exe","wscript.exe","cscript.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where (FileName =~ "mshta.exe" and ParentProcessName in (MshtaParents))
   or (FileName in (XslConsumers) and ProcessCommandLine has ".xsl")
| extend Cmd = tostring(ProcessCommandLine)
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName in ("powershell.exe","pwsh.exe")
) on DeviceId, ParentProcessId == ProcessId
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp >= ago(Lookback)
) on DeviceId, InitiatingProcessId == ProcessId1
| project
    MshtaOrXslTime = Timestamp,
    DeviceName,
    ParentProcessName,
    InitialBinary = FileName,
    InitialCmd = Cmd,
    PowerShellCmd = ProcessCommandLine1,
    RemoteUrl,
    RemoteIP
```

---

## 3. Script Dropper → WScript/CScript → PowerShell → Scheduled Task

### Basic

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in~ ("wscript.exe","cscript.exe")
```

### Medium

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in~ ("wscript.exe","cscript.exe")
| where ProcessCommandLine has_any (".vbs",".vbe",".js",".jse")
```

### Advanced (Script host → PS → schtasks / other persistence LOLBins)

```kql
let ScriptHosts = dynamic(["wscript.exe","cscript.exe"]);
let PersistenceBins = dynamic(["schtasks.exe","reg.exe","regsvr32.exe","rundll32.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in (ScriptHosts)
| extend ScriptCmd = ProcessCommandLine
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName in ("powershell.exe","pwsh.exe")
) on DeviceId, ProcessId == ParentProcessId
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName in (PersistenceBins)
    | where ProcessCommandLine has_any ("/create","Run","CurrentVersion\\Run","InprocServer32","/SC","/TN","/TR")
) on DeviceId, ProcessId1 == ParentProcessId
| project
    ScriptTime = Timestamp,
    DeviceName,
    AccountName,
    ScriptHost = FileName,
    ScriptCmd,
    PowerShellCmd = ProcessCommandLine1,
    PersistenceTool = FileName2,
    PersistenceCmd = ProcessCommandLine2
```

---

## 4. MSI Loader → Rundll32 → Payload DLL

### Basic

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine has_any ("http://","https://",".msi")
```

### Medium

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine has_any ("http://","https://",".msi")
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName =~ "rundll32.exe"
) on DeviceId, ProcessId == ParentProcessId
```

### Advanced (msiexec + rundll32 + DLL from user/writable path)

```kql
let WritablePaths = @'(?i)\\users\\|\\appdata\\|\\programdata\\|\\temp\\';
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine has_any ("http://","https://",".msi","/i","/qn")
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName =~ "rundll32.exe"
) on DeviceId, ProcessId == ParentProcessId
| join kind=leftouter (
    DeviceImageLoadEvents
    | where Timestamp >= ago(Lookback)
    | where FolderPath matches regex WritablePaths
) on DeviceId, InitiatingProcessId == ProcessId1
| project
    TimeGenerated,
    DeviceName,
    MsiexecCmd = ProcessCommandLine,
    RundllCmd = ProcessCommandLine1,
    LoadedDll = FileName2,
    DllPath = FolderPath2
```

---

## 5. Certutil Download → Decode → Execute

### Basic

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-urlcache","-decode","http","https",".b64")
```

### Medium

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "certutil.exe"
| extend Cmd = ProcessCommandLine
| where Cmd has_any ("-urlcache","-decode","http","https",".b64")
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp >= ago(Lookback)
    | where FileName endswith ".b64" or FileName endswith ".txt" or FileName contains ".tmp"
) on DeviceId
```

### Advanced (certutil chains + any LOLBin execution of output)

```kql
let CertEvents =
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "certutil.exe"
| extend Cmd = ProcessCommandLine
| where Cmd has_any ("-urlcache","-decode","-split","http","https",".b64")
| project DeviceId, CertTime = Timestamp, CertCmd = Cmd, InitiatingProcessId, ProcessId;
CertEvents
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp >= ago(Lookback)
    | extend LowerPath = tolower(FolderPath)
) on DeviceId, InitiatingProcessId == ProcessId
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName in (AllSuspiciousBins)
) on DeviceId, FolderPath == FolderPath1
| project
    CertTime,
    DeviceName,
    CertCmd,
    WrittenFile = FileName1,
    WrittenPath = FolderPath1,
    LolbinConsumer = FileName2,
    LolbinCmd = ProcessCommandLine2
```

---

## 6. Malicious Service Creation (sc.exe) → SYSTEM Payload

### Basic

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "sc.exe"
| where ProcessCommandLine has " create "
```

### Medium

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "sc.exe"
| where ProcessCommandLine has " create "
| where ProcessCommandLine matches regex @"(?i)\\users\\|\\appdata\\|\\temp\\"
```

### Advanced (service creation + suspicious binPath + follow-on LOLBin/System activity)

```kql
let SvcCreate =
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "sc.exe"
| where ProcessCommandLine has " create "
| extend BinPath = extract(@"binPath= ?\"([^\"]+)\"", 1, ProcessCommandLine)
| project DeviceId, TimeGenerated, DeviceName, AccountName, ProcessCommandLine, BinPath;
SvcCreate
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName in (AllSuspiciousBins) or ParentProcessName =~ "services.exe"
) on DeviceId
| project
    SvcCreateTime = TimeGenerated,
    DeviceName,
    AccountName,
    SvcCmd = ProcessCommandLine,
    BinPath,
    ChildProcess = FileName1,
    ChildCmd = ProcessCommandLine1
```

---

## 7. WMI Remote Execution

### Basic

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "wmic.exe"
| where ProcessCommandLine has "process" and ProcessCommandLine has "call" and ProcessCommandLine has "create"
```

### Medium

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "wmic.exe"
| extend Cmd = ProcessCommandLine
| where Cmd has "process" and Cmd has "call" and Cmd has "create"
| extend Target = extract(@"(?i)/node:([^ ]+)", 1, Cmd)
```

### Advanced (wmic/xsl LOLBin abuse + remote process)

```kql
let WmiExec =
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "wmic.exe"
| extend Cmd = ProcessCommandLine
| where Cmd has_any ("process call create",".xsl","/format:")
| extend Target = extract(@"(?i)/node:([^ ]]+)", 1, Cmd);
WmiExec
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName in (AllSuspiciousBins)
) on DeviceId
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    WmiCmd = Cmd,
    Target,
    RemoteCreatedProc = FileName1,
    RemoteCreatedCmd = ProcessCommandLine1
```

---

## 8. PsExec Lateral Spread

### Basic

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "psexec.exe"
```

### Medium

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "psexec.exe"
| where ProcessCommandLine has_any ("\\","-s","-d","-u","-p")
```

### Advanced (psexec + ADMIN$ writes + post-exec encryption/ransom patterns)

```kql
let PsExecProcs =
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "psexec.exe"
| project DeviceId, TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessId, ProcessId;
PsExecProcs
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp >= ago(Lookback)
    | where FolderPath matches regex @"(?i)\\\\[^\\]+\\ADMIN\$\\"
) on DeviceId
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName in (AllSuspiciousBins) or FileName has_any ("encrypt","locker","ryuk","conti","notpetya")
) on DeviceId
| project
    TimeGenerated,
    DeviceName,
    PsExecCmd = ProcessCommandLine,
    AdminSharePath = FolderPath,
    SuspiciousChild = FileName1,
    SuspiciousChildCmd = ProcessCommandLine1
```

---

## 9. Fileless LOLBin Chain (Office → Script → PS → Rundll32 → Dllhost)

### Basic

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in~ ("wscript.exe","cscript.exe","powershell.exe","rundll32.exe","dllhost.exe")
```

### Medium

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in~ ("wscript.exe","cscript.exe","powershell.exe","rundll32.exe","dllhost.exe")
| where ParentProcessName in~ ("winword.exe","excel.exe","outlook.exe","powerpnt.exe")
```

### Advanced (full ancestry + LOLBin coverage + outbound C2)

```kql
let InterestingBins = dynamic(["wscript.exe","cscript.exe","powershell.exe","rundll32.exe","dllhost.exe"]);
let OfficeParents = dynamic(["winword.exe","excel.exe","outlook.exe","powerpnt.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in (InterestingBins)
| project DeviceId, DeviceName, Timestamp, FileName, ProcessCommandLine, ParentProcessName, ProcessId, ParentProcessId
| order by Timestamp asc
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp >= ago(Lookback)
) on DeviceId, InitiatingProcessId == ProcessId
| summarize
    Start=min(Timestamp),
    End=max(Timestamp),
    ChainBins=make_set(FileName, 10),
    Parents=make_set(ParentProcessName, 10),
    ExampleCmds=make_set(ProcessCommandLine, 10),
    RemoteIPs=make_set(RemoteIP, 10),
    RemoteUrls=make_set(RemoteUrl, 10)
  by DeviceId, DeviceName
| where array_length(ChainBins) >= 3 and set_intersects(ChainBins, InterestingBins)
```

---

## 10. DLL Search Order Hijacking

### Basic

```kql
DeviceImageLoadEvents
| where Timestamp >= ago(Lookback)
| where FileName endswith ".dll"
| where FolderPath matches regex @"(?i)\\users\\|\\appdata\\|\\temp\\|\\programdata\\"
```

### Medium

```kql
DeviceImageLoadEvents
| where Timestamp >= ago(Lookback)
| where FolderPath matches regex @"(?i)\\users\\|\\appdata\\|\\temp\\|\\programdata\\"
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
) on DeviceId, InitiatingProcessId == ProcessId
```

### Advanced (user/writable DLL load + suspicious parent and child LOLBins)

```kql
let WritablePaths = @"(?i)\\users\\|\\appdata\\|\\temp\\|\\programdata\\";
DeviceImageLoadEvents
| where Timestamp >= ago(Lookback)
| where FileName endswith ".dll"
| where FolderPath matches regex WritablePaths
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
) on DeviceId, InitiatingProcessId == ProcessId
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName in (AllSuspiciousBins)
) on DeviceId, ParentProcessId == ProcessId1
| project
    Timestamp,
    DeviceName,
    HostProcess = FileName1,
    HostCmd = ProcessCommandLine1,
    LoadedDll = FileName,
    DllPath = FolderPath,
    SuspiciousChild = FileName2,
    SuspiciousChildCmd = ProcessCommandLine2
```

---

## 11. Browser Exploit → LOLBin (PS/Rundll32)

### Basic

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in ("powershell.exe","pwsh.exe","rundll32.exe","mshta.exe")
| where ParentProcessName in ("chrome.exe","msedge.exe","firefox.exe","iexplore.exe")
```

### Medium

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in ("powershell.exe","pwsh.exe","rundll32.exe","mshta.exe")
| where ParentProcessName in ("chrome.exe","msedge.exe","firefox.exe","iexplore.exe")
| where ProcessCommandLine has_any ("http","https","-enc","FromBase64String")
```

### Advanced (browser → any LOLBin with suspicious network)

```kql
let Browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","iexplore.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in (AllSuspiciousBins)
| where ParentProcessName in (Browsers)
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp >= ago(Lookback)
) on DeviceId, InitiatingProcessId == ProcessId
| project
    Timestamp,
    DeviceName,
    Browser = ParentProcessName,
    Lolbin = FileName,
    Cmd = ProcessCommandLine,
    RemoteUrl,
    RemoteIP
```

---

## 12. ISO/VHD → App.exe → Malicious DLL

### Basic

*(If you don't have mount telemetry, treat “weird path” app exec + DLL load)*

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FolderPath has_any (".iso\\",".vhd\\")
```

### Medium

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where ProcessCommandLine has_any (".iso",".vhd")
```

### Advanced (app from non-standard path + DLL from same folder)

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FolderPath matches regex @"(?i)\\temp\\|\\downloads\\|\\desktop\\"
| project DeviceId, DeviceName, Timestamp, AppName = FileName, AppPath = FolderPath, ProcessId
| join kind=leftouter (
    DeviceImageLoadEvents
    | where Timestamp >= ago(Lookback)
) on DeviceId, InitiatingProcessId == ProcessId
| where FolderPath startswith AppPath
| project
    Timestamp,
    DeviceName,
    AppName,
    AppPath,
    LoadedDll = FileName1,
    DllPath = FolderPath1
```

---

## 13. LNK → LOLBin → Payload

### Basic

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where ParentProcessName =~ "explorer.exe"
| where FileName in (AllSuspiciousBins)
```

### Medium

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where ParentProcessName =~ "explorer.exe"
| where FileName in (AllSuspiciousBins)
| where ProcessCommandLine has ".lnk"
```

### Advanced (explorer → LOLBin + related .lnk file on disk)

```kql
let Lnks =
DeviceFileEvents
| where Timestamp >= ago(Lookback)
| where FileName endswith ".lnk"
| project DeviceId, LnkTime = Timestamp, LnkPath = FolderPath, LnkName = FileName;
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where ParentProcessName =~ "explorer.exe"
| where FileName in (AllSuspiciousBins)
| project DeviceId, ProcTime = Timestamp, DeviceName, Lolbin = FileName, LolbinCmd = ProcessCommandLine
| join kind=leftouter Lnks on DeviceId
| where abs(datetime_diff("minute", ProcTime, LnkTime)) <= 5
| project
    DeviceName,
    ProcTime,
    Lolbin,
    LolbinCmd,
    LnkTime,
    LnkPath,
    LnkName
```

---

## 14. ZIP → Script → LOLBin → Payload

### Basic

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in ("wscript.exe","cscript.exe")
| where ProcessCommandLine has_any (".vbs",".js",".vbe",".jse")
```

### Medium

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in ("wscript.exe","cscript.exe")
| where ProcessCommandLine has_any (".vbs",".js",".vbe",".jse")
| where ParentProcessName =~ "explorer.exe"
```

### Advanced (script host → LOLBin → network/write)

```kql
let ScriptHosts = dynamic(["wscript.exe","cscript.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in (ScriptHosts)
| extend ScriptCmd = ProcessCommandLine
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName in (AllSuspiciousBins)
) on DeviceId, ProcessId == ParentProcessId
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp >= ago(Lookback)
) on DeviceId, InitiatingProcessId == ProcessId1
| project
    DeviceName,
    ScriptHost = FileName,
    ScriptCmd,
    Lolbin = FileName1,
    LolbinCmd = ProcessCommandLine1,
    RemoteUrl,
    RemoteIP
```

---

## 15. Browser → CMD → PowerShell → Payload

### Basic

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "cmd.exe"
| where ParentProcessName in ("chrome.exe","msedge.exe","firefox.exe","iexplore.exe")
```

### Medium

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "cmd.exe"
| where ParentProcessName in ("chrome.exe","msedge.exe","firefox.exe","iexplore.exe")
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName in ("powershell.exe","pwsh.exe")
) on DeviceId, ProcessId == ParentProcessId
```

### Advanced (browser → cmd → any LOLBin + network)

```kql
let Browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","iexplore.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "cmd.exe"
| where ParentProcessName in (Browsers)
| extend CmdCmd = ProcessCommandLine
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName in (AllSuspiciousBins)
) on DeviceId, ProcessId == ParentProcessId
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp >= ago(Lookback)
) on DeviceId, InitiatingProcessId == ProcessId1
| project
    DeviceName,
    Browser = ParentProcessName,
    CmdCmd,
    Lolbin = FileName1,
    LolbinCmd = ProcessCommandLine1,
    RemoteUrl,
    RemoteIP
```

---

## 16. PowerShell → Rundll32 → dllhost Injection / C2

### Basic

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "rundll32.exe"
| where ParentProcessName in ("powershell.exe","pwsh.exe")
```

### Medium

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "rundll32.exe"
| where ParentProcessName in ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (".dll","javascript:","vbscript:")
```

### Advanced (PS → Rundll32 + dllhost child + outbound)

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "rundll32.exe"
| where ParentProcessName in ("powershell.exe","pwsh.exe")
| project DeviceId, DeviceName, Timestamp, RundllCmd = ProcessCommandLine, ProcessId
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName =~ "dllhost.exe"
) on DeviceId, ProcessId == ParentProcessId
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp >= ago(Lookback)
) on DeviceId, InitiatingProcessId == ProcessId1
| project
    DeviceName,
    RundllCmd,
    DllhostCmd = ProcessCommandLine1,
    RemoteUrl,
    RemoteIP
```

---

## 17. PowerShell Inline C# → Memory Beacon

### Basic

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in ("powershell.exe","pwsh.exe")
```

### Medium

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("-enc","-nop","bypass","FromBase64String","Add-Type","Reflection")
```

### Advanced (inline C#/reflection + network)

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("Add-Type","Reflection","FromBase64String","System.Convert::FromBase64String")
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp >= ago(Lookback)
) on DeviceId, InitiatingProcessId == ProcessId
| project
    DeviceName,
    ProcessCommandLine,
    RemoteUrl,
    RemoteIP
```

---

## 18. RDPClip Clipboard Exfil

### Basic

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "rdpclip.exe"
```

### Medium

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "rdpclip.exe"
| summarize Count = count() by DeviceName, AccountName
| where Count > 100  // tune threshold
```

### Advanced (RDP sessions + suspicious outbound followed)

```kql
let RdpSessions =
SecurityEvent
| where TimeGenerated >= ago(Lookback)
| where EventID in (4624, 4625)
| where LogonType == 10  // RemoteInteractive
| project DeviceId, DeviceName, Account = SubjectUserName, TimeGenerated;
RdpSessions
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName =~ "rdpclip.exe"
) on DeviceId
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp >= ago(Lookback)
) on DeviceId
| where Timestamp2 between (Timestamp1 .. Timestamp1 + 30m)
| summarize
    RdpClipCount = countif(FileName1 == "rdpclip.exe"),
    OutboundCount = countif(isnotempty(RemoteIP))
  by DeviceName, Account
| where RdpClipCount > 50 and OutboundCount > 0
```

---

## 19. BYOVD → Driver Install → Payload

### Basic

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "sc.exe"
| where ProcessCommandLine has " create "
| where ProcessCommandLine has ".sys"
```

### Medium

```kql
DeviceFileEvents
| where Timestamp >= ago(Lookback)
| where FileName endswith ".sys"
| where FolderPath matches regex @"(?i)system32\\drivers"
```

### Advanced (driver creation + suspicious LOLBin/ransom behaviour after)

```kql
let DriverCreates =
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "sc.exe"
| where ProcessCommandLine has " create " and ProcessCommandLine has ".sys"
| project DeviceId, DeviceName, TimeGenerated, SvcCmd = ProcessCommandLine;
DriverCreates
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp >= ago(Lookback)
    | where FileName endswith ".sys"
) on DeviceId
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName in (AllSuspiciousBins) or ProcessCommandLine has_any ("vssadmin delete shadows","wbadmin delete","bcdedit /set {default} recoveryenabled No")
) on DeviceId
| project
    DeviceName,
    SvcCmd,
    DriverFile = FileName1,
    DriverPath = FolderPath1,
    SuspiciousProc = FileName2,
    SuspiciousCmd = ProcessCommandLine2
```

---

## 20. LSASS Dump → Exfil

### Basic

```kql
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where ProcessCommandLine has_any ("lsass.dmp","comsvcs.dll, MiniDump","procdump","lsass")
```

### Medium

```kql
DeviceFileEvents
| where Timestamp >= ago(Lookback)
| where FileName has "lsass" and FileName endswith ".dmp"
| where FolderPath matches regex @"(?i)\\users\\|\\temp\\|\\appdata\\"
```

### Advanced (dump file + suspicious process + outbound near in time)

```kql
let Dumps =
DeviceFileEvents
| where Timestamp >= ago(Lookback)
| where FileName has "lsass" and FileName endswith ".dmp"
| project DeviceId, DeviceName, DumpTime = Timestamp, DumpFile = FileName, DumpPath = FolderPath;
Dumps
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName in (AllSuspiciousBins) or ProcessCommandLine has_any ("comsvcs.dll, MiniDump","procdump","lsass")
) on DeviceId
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp >= ago(Lookback)
) on DeviceId
| where Timestamp2 between (DumpTime .. DumpTime + 30m)
| project
    DeviceName,
    DumpTime,
    DumpFile,
    DumpPath,
    SuspectProc = FileName1,
    SuspectCmd = ProcessCommandLine1,
    RemoteIP,
    RemoteUrl
```

---
