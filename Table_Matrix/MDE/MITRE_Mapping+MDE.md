# 🛰️ DeviceProcessEvents — MITRE ATT&CK Mapping (Compact KQL)

**Strength Levels:**  
⭐⭐⭐ = High-fidelity | ⭐⭐ = Medium (needs correlation) | ⭐ = Context only

---

# 🔹 Execution (TA0002)

| Technique | Name | ⭐ | Why Detectable | Compact KQL |
|----------|------|----|----------------|-------------|
| T1059 | Cmd/Scripting | ⭐⭐⭐ | PowerShell, CMD, WScript execution | `FileName in~ ("powershell.exe","cmd.exe")` |
| T1059.001 | PowerShell | ⭐⭐⭐ | PS execution + args | `FileName has "power"` |
| T1059.003 | CMD | ⭐⭐⭐ | Detects cmd.exe invocations | `FileName == "cmd.exe"` |
| T1059.005 | VB / WScript | ⭐⭐⭐ | Macro → WScript chains | `FileName in ("wscript.exe","cscript.exe")` |
| T1059.006 | Python | ⭐⭐⭐ | Python loaders | `FileName == "python.exe"` |
| T1218 | LOLBins | ⭐⭐⭐ | Rundll32, Regsvr32, Mshta, Certutil | `FileName in ("mshta.exe","rundll32.exe")` |
| T1204.002 | User Exec | ⭐⭐ | Execution from Temp/AppData | `FolderPath has "AppData"` |

---

# 🔹 Persistence (TA0003)

| Technique | Name | ⭐ | Why Detectable | Compact KQL |
|----------|------|----|----------------|-------------|
| T1547.001 | Run Keys | ⭐⭐ | Run key child procs | `InitiatingProcessFileName has "reg"` |
| T1547.004 | Winlogon | ⭐⭐ | Winlogon launching odd procs | `InitiatingProcessFileName == "winlogon.exe"` |
| T1053.005 | Scheduled Task | ⭐⭐⭐ | schtasks.exe use | `FileName == "schtasks.exe"` |
| T1543.003 | Services | ⭐⭐⭐ | services.exe spawning payloads | `InitiatingProcessFileName=="services.exe"` |
| T1574.002 | DLL Hijack | ⭐⭐⭐ | rundll32 misuse | `FileName=="rundll32.exe"` |

---

# 🔹 Credential Access (TA0006)

| Technique | Name | ⭐ | Why Detectable | Compact KQL |
|----------|------|----|----------------|-------------|
| T1003.001 | LSASS Dump | ⭐⭐⭐ | procdump / comsvcs | `ProcessCommandLine has "lsass"` |
| T1558 | Kerberos Theft | ⭐⭐ | mimikatz-like procs | `ProcessCommandLine has "katz"` |
| T1555 | Password Stores | ⭐⭐ | DPAPI tools | `ProcessCommandLine has "dpapi"` |

---

# 🔹 Discovery (TA0007)

| Technique | Name | ⭐ | Why Detectable | Compact KQL |
|----------|------|----|----------------|-------------|
| T1082 | System Info | ⭐⭐⭐ | systeminfo, wmic | `FileName in ("systeminfo.exe","wmic.exe")` |
| T1087 | Account Discovery | ⭐⭐⭐ | net user/group | `"net " in ProcessCommandLine` |
| T1046 | Network Scan | ⭐⭐ | nmap tools | `FileName in ("nmap.exe","ncat.exe")` |
| T1018 | Remote Discovery | ⭐⭐ | net view enumeration | `ProcessCommandLine has "net view"` |
| T1083 | File Discovery | ⭐⭐⭐ | dir/ls enumeration | `ProcessCommandLine has "dir"` |

---

# 🔹 Lateral Movement (TA0008)

| Technique | Name | ⭐ | Why Detectable | Compact KQL |
|----------|------|----|----------------|-------------|
| T1021.001 | RDP | ⭐⭐ | mstsc.exe usage | `FileName=="mstsc.exe"` |
| T1021.002 | SMB / PsExec | ⭐⭐⭐ | psexec.exe invocation | `FileName=="psexec.exe"` |
| T1055 | Proc Injection | ⭐⭐ | injector tools | `ProcessCommandLine has "inject"` |
| T1072 | Remote Services | ⭐⭐⭐ | MMC / remote PS | `FileName=="mmc.exe"` |

---

# 🔹 Collection (TA0009)

| Technique | Name | ⭐ | Why Detectable | Compact KQL |
|----------|------|----|----------------|-------------|
| T1113 | Screen Capture | ⭐⭐ | screenshot tools | `FileName in ("nircmd.exe")` |
| T1114 | Email Collection | ⭐⭐ | outlook automation | `ProcessCommandLine has "outlook"` |

---

# 🔹 Exfiltration (TA0010)

| Technique | Name | ⭐ | Why Detectable | Compact KQL |
|----------|------|----|----------------|-------------|
| T1041 | C2 Exfil | ⭐⭐⭐ | curl/wget staging | `ProcessCommandLine has_any ("curl","wget")` |
| T1567 | Web Exfil | ⭐⭐ | cloud CLI exfil | `FileName in ("azcopy.exe","aws.exe")` |

---

# 🔹 Command & Control (TA0011)

| Technique | Name | ⭐ | Why Detectable | Compact KQL |
|----------|------|----|----------------|-------------|
| T1071.001 | Web C2 | ⭐⭐⭐ | HTTP-based implants | `ProcessCommandLine has "http"` |
| T1105 | Tool Transfer | ⭐⭐⭐ | download cradles | `ProcessCommandLine has "wget"` |
| T1095 | Non-App Protocol | ⭐⭐ | ncat/socat usage | `FileName in ("ncat.exe","socat.exe")` |

---

# 🔹 Impact (TA0040)

| Technique | Name | ⭐ | Why Detectable | Compact KQL |
|----------|------|----|----------------|-------------|
| T1486 | Ransomware | ⭐⭐⭐ | encryption tooling | `ProcessCommandLine has "encrypt"` |
| T1490 | Service Kill | ⭐⭐⭐ | net/sc stop | `ProcessCommandLine has "stop"` |
