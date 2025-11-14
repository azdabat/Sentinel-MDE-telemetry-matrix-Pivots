# 🖥 MDE Core Endpoint Tables

---

## 1. DeviceInfo

| Field | Value |
|-------|-------|
| Purpose | Endpoint inventory and metadata |
| Key Fields | DeviceName, OSPlatform, OSVersion, OnboardingStatus, IsAzureADJoined, AADDeviceId, Tags, LoggedOnUsers |
| Typical Attack Coverage | Context only – crucial to know OS, role, join state, critical asset status |
| MITRE | Pre-attack scoping |
| KQL Starter | ```kql\nDeviceInfo\n| summarize Count = count() by OSPlatform, OSVersion\n``` |

---

## 2. DeviceProcessEvents

| Field | Value |
|-------|-------|
| Purpose | Process creation telemetry |
| Key Fields | Timestamp, DeviceName, FileName, ProcessCommandLine, ParentProcessName, FolderPath, AccountName, ProcessId, SHA1 |
| Typical Attack Coverage | Malware execution, LOLBins, script engines, webshell child shells, lateral tools, ransomware execution processes |
| MITRE | T1059, T1218, T1053, T1569.002 |
| KQL Starter | ```kql\nDeviceProcessEvents\n| where Timestamp >= ago(7d)\n| where FileName in~ (\"powershell.exe\",\"wscript.exe\",\"cscript.exe\",\"mshta.exe\",\"rundll32.exe\")\n| project Timestamp, DeviceName, AccountName, ParentProcessName, FileName, ProcessCommandLine\n``` |

---

## 3. DeviceNetworkEvents

| Field | Value |
|-------|-------|
| Purpose | Process-level outbound network events |
| Key Fields | Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol |
| Typical Attack Coverage | C2, scanning, SMB/RDP lateral, exfiltration, mining |
| MITRE | T1041, T1046, T1105, T1021.002, T1021.001 |
| KQL Starter | ```kql\nDeviceNetworkEvents\n| where Timestamp >= ago(1d)\n| where isnotempty(RemoteUrl)\n| summarize Count = count() by InitiatingProcessFileName, RemoteUrl\n| order by Count desc\n``` |

---

## 4. DeviceFileEvents

| Field | Value |
|-------|-------|
| Purpose | File system operations (create, modify, delete, rename) |
| Key Fields | Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine |
| Typical Attack Coverage | Ransomware behaviour, dropper activity, staging of exfil data, suspicious binaries in user-writable paths |
| MITRE | T1486, T1074, T1105 |
| KQL Starter | ```kql\nDeviceFileEvents\n| where Timestamp >= ago(7d)\n| where ActionType == \"FileCreated\" and FileName endswith \".exe\"\n| where FolderPath has_any (\"\\\\Users\\\\\",\"\\\\Desktop\\\\\",\"\\\\Downloads\\\\\",\"AppData\")\n``` |

---

## 5. DeviceRegistryEvents

| Field | Value |
|-------|-------|
| Purpose | Registry operations (create, set, delete) |
| Key Fields | Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, AccountName |
| Typical Attack Coverage | Persistence keys, IFEO, COM hijack, LSA changes, RDP enabling, AV tampering |
| MITRE | T1112, T1547, T1543, T1556 |
| KQL Starter | ```kql\nDeviceRegistryEvents\n| where Timestamp >= ago(7d)\n| where RegistryKey has_any (\"Run\",\"RunOnce\",\"CurrentControlSet\\\\Services\")\n``` |

---

## 6. DeviceLogonEvents

| Field | Value |
|-------|-------|
| Purpose | Device logon events |
| Key Fields | Timestamp, DeviceName, AccountName, AccountDomain, LogonType, LogonId, RemoteIP, IsLocalAdmin |
| Typical Attack Coverage | RDP brute force and lateral, suspicious admin activity, interactive service account logons |
| MITRE | T1021.001, T1021.002, T1078 |
| KQL Starter | ```kql\nDeviceLogonEvents\n| where Timestamp >= ago(7d)\n| where LogonType == 10\n| summarize Count = count() by AccountName, RemoteIP, DeviceName\n| where Count > 10\n``` |

---

## 7. DeviceEvents

| Field | Value |
|-------|-------|
| Purpose | Miscellaneous events (AV, exploit guard, ASR, task-related, etc.) |
| Key Fields | Timestamp, DeviceName, ActionType, AdditionalFields |
| Typical Attack Coverage | AV detections, exploit block events, network protection, scheduled tasks persistence |
| MITRE | T1203, T1562, T1053 |
| KQL Starter | ```kql\nDeviceEvents\n| where Timestamp >= ago(7d)\n| where ActionType has_any (\"Antivirus\",\"ExploitGuard\",\"NetworkProtection\",\"ScheduledTask\")\n``` |
