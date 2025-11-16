# ⚔️ LOLBin KQL Examples  
## (Top 20 – Correct MDE Field Names)

Below are all **20 corrected LOLBIN rules** using **valid MDE fields**, no Sysmon-style parents, no invalid field names.

---

## 1. Abnormal PowerShell parents
```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName =~ "powershell.exe"
| where InitiatingProcessFileName !in~ ("explorer.exe","cmd.exe","powershell.exe","services.exe")
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine
```

## 2. Office → LOLBin
```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName in~ ("powershell.exe","wscript.exe","cscript.exe","cmd.exe","mshta.exe")
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
```

## 3. MSHTA Smuggling
```kql
DeviceProcessEvents
| where FileName =~ "mshta.exe"
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","winword.exe","onenote.exe")
```

## 4. Certutil Abuse
```kql
DeviceProcessEvents
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-urlcache","-decode","http","https")
```

## 5. Rundll32 Script/URL Abuse
```kql
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_any (".js",".vbs","http://","https://","javascript:")
```

## 6. Regsvr32 Remote Script Load
```kql
DeviceProcessEvents
| where FileName =~ "regsvr32.exe"
| where ProcessCommandLine has_any (".sct","http://","https://")
```

## 7. Msbuild User-Writable Execution
```kql
DeviceProcessEvents
| where FileName =~ "msbuild.exe"
| where ProcessCommandLine has_any ("\\Users\\","AppData","Temp",".xml",".csproj")
```

## 8. InstallUtil Abuse
```kql
DeviceProcessEvents
| where FileName =~ "installutil.exe"
| where ProcessCommandLine has_any ("\\Users\\","AppData","Temp",".exe",".dll")
```

## 9. Bitsadmin Download/Transfer
```kql
DeviceProcessEvents
| where FileName =~ "bitsadmin.exe"
| where ProcessCommandLine has_any ("/transfer","http://","https://")
```

## 10. CMSTP UAC Bypass
```kql
DeviceProcessEvents
| where FileName =~ "cmstp.exe"
| where ProcessCommandLine has_any (".inf","/au","/s")
```

## 11. Msiexec Online Install
```kql
DeviceProcessEvents
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine has_any ("http://","https://","/i","/qn")
```

## 12. WMI Command-Line Abuse
```kql
DeviceProcessEvents
| where FileName =~ "wmic.exe"
| where ProcessCommandLine has_any ("process call create","shadowcopy","/node:")
```

## 13. Regasm/Regsvcs Unsigned DLL Load
```kql
DeviceProcessEvents
| where FileName in~ ("regasm.exe","regsvcs.exe")
| where ProcessCommandLine has_any ("\\Users\\","AppData","Temp",".dll")
```

## 14. Sdbinst Shim Abuse
```kql
DeviceProcessEvents
| where FileName =~ "sdbinst.exe"
| where ProcessCommandLine has_any ("\\Users\\","AppData","Temp",".sdb")
```

## 15. Odbcconf DLL Load
```kql
DeviceProcessEvents
| where FileName =~ "odbcconf.exe"
| where ProcessCommandLine has_any ("/a","regsvr",".dll")
```

## 16. PresentationHost XBAP Execution
```kql
DeviceProcessEvents
| where FileName =~ "presentationhost.exe"
| where ProcessCommandLine has_any (".xbap",".xaml","http://","https://")
```

## 17. Control.exe CPL Abuse
```kql
DeviceProcessEvents
| where FileName =~ "control.exe"
| where ProcessCommandLine has ".cpl"
      and ProcessCommandLine has_any ("\\Users\\","AppData","Temp")
```

## 18. LOLBin + Network Egress
```kql
let Lolbins = dynamic([
 "powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe",
 "regsvr32.exe","installutil.exe","msbuild.exe","certutil.exe","bitsadmin.exe",
 "cmstp.exe","msiexec.exe","wmic.exe","regasm.exe","regsvcs.exe","sdbinst.exe",
 "odbcconf.exe","presentationhost.exe","control.exe"
]);

DeviceProcessEvents
| where FileName in~ Lolbins
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp >= ago(7d)
) on DeviceId
| project Timestamp, DeviceName, FileName,
          RemoteIP, RemotePort, RemoteUrl,
          ProcessCommandLine
```

## 19. LOLBin Droppers (FileCreated)
```kql
let Lolbins = dynamic([
 "powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe",
 "regsvr32.exe","installutil.exe","msbuild.exe","certutil.exe","bitsadmin.exe"
]);

DeviceFileEvents
| where ActionType == "FileCreated"
| where InitiatingProcessFileName in~ Lolbins
| where FolderPath has_any ("\\Users\\","AppData","Temp","Downloads")
```

## 20. LOLBin Persistence
```kql
let Lolbins = dynamic([
 "powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe",
 "regsvr32.exe","installutil.exe","msbuild.exe","bitsadmin.exe"
]);

DeviceRegistryEvents
| where RegistryKey has_any (
 "CurrentVersion\\Run",
 "CurrentVersion\\RunOnce",
 "SYSTEM\\CurrentControlSet\\Services"
)
| where RegistryValueData has_any Lolbins
```
