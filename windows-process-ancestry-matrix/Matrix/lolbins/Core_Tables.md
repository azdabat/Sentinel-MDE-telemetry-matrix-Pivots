# 🖥 MDE Core Endpoint Tables

---

## 1. DeviceInfo

| Field | Value |
|-------|-------|
| Purpose | Endpoint inventory and metadata |
| Key Fields | DeviceName, OSPlatform, OSBuild, AadDeviceId, IsAzureADJoined, JoinType, LoggedOnUsers |
| Typical Attack Use | Context only – critical for triage & asset classification |
| MITRE | Pre-attack / environment mapping |

```kql
DeviceInfo
| summarize Count = count() by OSPlatform, OSBuild
| order by Count desc
```

---

## 2. DeviceProcessEvents

| Field | Value |
|-------|-------|
| Purpose | Process creation telemetry |
| Key Fields | Timestamp, DeviceName, FileName, ProcessCommandLine, FolderPath, ProcessId, SHA1, AccountName, InitiatingProcessFileName |
| Typical Attack Use | Malware execution, LOLBins, script engines, ransomware |
| MITRE | T1059, T1218, T1053, T1569.002 |

```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| summarize Count = count() by FileName, InitiatingProcessFileName
| top 50 by Count desc
```

---

## 3. DeviceNetworkEvents

| Field | Value |
|-------|-------|
| Purpose | Outbound & inbound process-level network visibility |
| Key Fields | Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol |
| Typical Attack Use | C2, scanning, exfil, SMB/RDP lateral |
| MITRE | T1041, T1046, T1105, T1021.002, T1021.001 |

```kql
DeviceNetworkEvents
| where Timestamp >= ago(1d)
| where isnotempty(RemoteIP) or isnotempty(RemoteUrl)
| summarize DistinctRemotes = dcount(strcat(RemoteIP, RemoteUrl))
    by DeviceName, InitiatingProcessFileName
| top 50 by DistinctRemotes desc
```

---

## 4. DeviceFileEvents

| Field | Value |
|-------|-------|
| Purpose | File create/delete/modify |
| Key Fields | Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine |
| Attack Coverage | Ransomware, droppers, staging |
| MITRE | T1486, T1074, T1105 |

```kql
DeviceFileEvents
| where Timestamp >= ago(7d)
| where ActionType == "FileCreated"
| where FileName endswith ".exe"
| where FolderPath has_any ("\\Users\\","\\Downloads\\","AppData")
```

---

## 5. DeviceRegistryEvents

| Field | Value |
|-------|-------|
| Purpose | Registry set/create/delete |
| Key Fields | Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, AccountName |
| Attack Coverage | Persistence, IFEO, COM hijack, LSA tampering |
| MITRE | T1112, T1547, T1543, T1556 |

```kql
DeviceRegistryEvents
| where Timestamp >= ago(7d)
| where RegistryKey has_any (
   "CurrentVersion\\Run",
   "CurrentVersion\\RunOnce",
   "SYSTEM\\CurrentControlSet\\Services"
)
```

---

## 6. DeviceLogonEvents

| Field | Value |
|-------|-------|
| Purpose | Logon activity |
| Key Fields | Timestamp, DeviceName, AccountName, AccountDomain, LogonType, RemoteIP, IsLocalAdmin |
| Attack Coverage | RDP, lateral, admin misuse |
| MITRE | T1021.001, T1021.002, T1078 |

```kql
DeviceLogonEvents
| where Timestamp >= ago(7d)
| where LogonType == "RemoteInteractive"
| summarize Count = count() by AccountName, RemoteIP, DeviceName
| where Count > 10
```

---

## 7. DeviceEvents

| Field | Value |
|-------|-------|
| Purpose | Misc events (AV, ASR, Exploit Guard) |
| Key Fields | Timestamp, DeviceName, ActionType, FileName, AdditionalFields |
| Attack Coverage | AV hits, blocked exploits, tamper |
| MITRE | T1203, T1562, T1053 |

```kql
DeviceEvents
| where Timestamp >= ago(7d)
| where ActionType has_any (
   "AntivirusDetection","AsrRuleBlocked",
   "ExploitGuardNetworkProtectionBlocked",
   "ScheduledTaskCreated"
)
```
