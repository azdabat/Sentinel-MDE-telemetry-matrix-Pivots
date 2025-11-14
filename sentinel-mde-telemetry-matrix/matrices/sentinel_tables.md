# 📘 Sentinel Table Matrix

Below is the full Microsoft Sentinel table reference — expanded, MITRE-mapped, with attack coverage and pivot guidance.

---

# 1. Endpoint Telemetry (via MDE → Sentinel)

## 1.1 DeviceProcessEvents

| Field | Value |
|-------|-------|
| **Purpose** | Process creation & termination telemetry from MDE |
| **Source** | MDE Sensor |
| **Key Fields** | Timestamp, DeviceName, FileName, ProcessCommandLine, ParentProcessName, SHA1, AccountName, FolderPath, ProcessId |
| **Attack Coverage** | Malware execution, LOLBins, initial access, persistence tools, ransomware loaders, webshell child processes, lateral tooling (PsExec, wmiexec), UAC bypass |
| **MITRE** | T1059, T1105, T1204, T1218, T1569.002, T1053 |
| **Common Pivots** | ParentProcessName → ancestry; SHA1 → FileEvents; ProcessId → NetworkEvents |
| **Example KQL** | ```DeviceProcessEvents \n| where FileName =~ "powershell.exe" \n| summarize count() by ParentProcessName``` |

---

## 1.2 DeviceNetworkEvents

| Field | Value |
|-------|-------|
| **Purpose** | Process-level network flows |
| **Source** | MDE Sensor |
| **Key Fields** | Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine |
| **Attack Coverage** | C2 beacons, scanning, enumeration, SMB/RDP lateral movement, exfiltration, crypto-mining |
| **MITRE** | T1041, T1046, T1105, T1021.002, T1021.001 |
| **Common Pivots** | RemoteIP → TI; InitiatingProcessFileName → ProcessEvents; URL → OfficeActivity |
| **Example KQL** | ```DeviceNetworkEvents \n| where RemotePort == 445 \n| summarize count() by InitiatingProcessFileName``` |

---

## 1.3 DeviceFileEvents

| Field | Value |
|-------|-------|
| **Purpose** | File creation, modification, deletion |
| **Key Fields** | ActionType, FileName, FolderPath, SHA1, InitiatingProcessFileName |
| **Attack Coverage** | Ransomware encryption, data staging, droppers, EXE/DLL writes to user directories |
| **MITRE** | T1486, T1105, T1055, T1074 |
| **Common Pivots** | FolderPath → suspicious locations; SHA1 → ProcessEvents; ProcessName → NetworkEvents |
| **Example KQL** | ```DeviceFileEvents \n| where ActionType=="FileCreated" and FileName endswith ".exe"``` |

---

## 1.4 DeviceRegistryEvents

| Field | Value |
|-------|-------|
| **Purpose** | Registry edits indicating persistence or configuration tampering |
| **Key Fields** | RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName |
| **Attack Coverage** | Run keys, services, IFEO, COM hijack, LSA tampering, RDP enabling |
| **MITRE** | T1547, T1112, T1556, T1543 |
| **Common Pivots** | RegistryValueData → file path → FileEvents; InitiatingProcessFileName → ancestry |
| **Example KQL** | ```DeviceRegistryEvents \n| where RegistryKey has "Run"``` |

---

## 1.5 DeviceLogonEvents

| Field | Value |
|-------|-------|
| **Purpose** | Logon activity (interactive, network, RDP) |
| **Key Fields** | AccountName, LogonType, RemoteIP, IsLocalAdmin |
| **Attack Coverage** | RDP brute-force, lateral movement, credential abuse |
| **MITRE** | T1110, T1021.001, T1021.002 |
| **Common Pivots** | RemoteIP → pivot host; AccountName → SecurityEvent |
| **Example KQL** | ```DeviceLogonEvents \n| where LogonType==10``` |

---

## 1.6 DeviceEvents

| Field | Value |
|-------|-------|
| **Purpose** | Misc events, AV hits, exploit prevention, scheduled tasks |
| **Attack Coverage** | Malware detection, exploitation blocked events, persistence via tasks |
| **MITRE** | T1053, T1203, T1562 |
| **Example** | ```DeviceEvents | where ActionType=="ScheduledTaskCreated"``` |

---

# 2. Windows Security Logs

## 2.1 SecurityEvent

| Field | Value |
|-------|-------|
| **Purpose** | Full Windows Security logs |
| **Primary Attack Coverage** | Kerberoasting, AS-REP roasting, brute-force, service creation, log clearing |
| **MITRE** | T1110, T1558, T1543, T1078 |
| **Key EventIDs** | 4624, 4625, 4768, 4769, 7045, 1102 |
| **KQL** | ```SecurityEvent | where EventID==4769``` |

---

# 3. Cloud / Identity

## 3.1 SigninLogs

| Field | Value |
|-------|-------|
| **Purpose** | Azure AD / Entra sign-in events |
| **Attack Coverage** | Password spray, ATO, MFA fatigue, impossible travel |
| **MITRE** | T1110, T1078 |
| **Key Fields** | IPAddress, Location, ResultType, RiskDetail, AuthenticationRequirement |
| **KQL** | ```SigninLogs | where ResultType != 0``` |

---

## 3.2 AuditLogs

| Field | Value |
|-------|-------|
| **Purpose** | Directory changes (roles, SPNs, service principal credentials) |
| **Attack Coverage** | OAuth abuse, service principal backdooring, privilege escalation |
| **MITRE** | T1098, T1548 |
| **Key Fields** | OperationName, InitiatedBy, TargetResources |
| **KQL** | ```AuditLogs | where OperationName=="Add service principal credentials"``` |

---

## 3.3 OfficeActivity

| Field | Value |
|-------|-------|
| **Purpose** | Exchange/SharePoint/OneDrive/Teams audit |
| **Attack Coverage** | BEC rule creation, mailbox manipulation, mass downloads |
| **MITRE** | T1114, T1530 |
| **KQL** | ```OfficeActivity | where Operation=="New-InboxRule"``` |

---

## 3.4 AzureActivity

| Field | Value |
|-------|-------|
| **Purpose** | Azure resource configuration events |
| **Attack Coverage** | Cloud persistence, role assignment attacks |
| **MITRE** | T1098, T1098.003 |
| **KQL** | ```AzureActivity | where OperationName has "role assignment"``` |

---

# 4. Network / Perimeter Logs

## 4.1 CommonSecurityLog

| Field | Value |
|-------|-------|
| **Purpose** | Firewalls, proxies, WAF, VPN |
| **Attack Coverage** | Perimeter scanning, C2, VPN compromise, outbound exfil, inbound exploit attempts |
| **MITRE** | T1190, T1041, T1133 |
| **KQL** | ```CommonSecurityLog | where DeviceAction=="Allow"``` |

---

# 5. Threat Intel

## 5.1 ThreatIntelligenceIndicator

| Field | Value |
|-------|-------|
| **Purpose** | TI ingestion (MISP, TAXII, CSV, vendors) |
| **Attack Coverage** | Any match of hash, IP, domain, URL |
| **MITRE** | Supports all techniques via enrichment |
| **KQL** | ```ThreatIntelligenceIndicator | take 50``` |

