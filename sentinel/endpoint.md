# 🖥 Sentinel Endpoint / Host Telemetry

All tables below are typically present in Sentinel when Defender for Endpoint, agents, or connectors are configured.

---

## 1. DeviceProcessEvents

| Field | Value |
|-------|-------|
| Purpose | Process creation / termination from Microsoft Defender for Endpoint |
| Source | Defender for Endpoint connector into Sentinel |
| Key Fields | Timestamp, DeviceName, FileName, ProcessCommandLine, ParentProcessName, FolderPath, AccountName, ProcessId, SHA1 |
| Typical Attack Coverage | Malware execution, LOLBin abuse (powershell, cmd, mshta, rundll32, certutil, regsvr32), UAC bypass, lateral tools (PsExec, WMI), ransomware encryptors, webshell child processes |
| MITRE | T1059 (Command and Scripting Interpreter), T1218 (Signed Binary Proxy Execution), T1053 (Scheduled Task/Job), T1569.002 (Service Execution), T1105 (Ingress Tool Transfer) |
| Common Pivots | ParentProcessName → baseline normal vs suspicious; ProcessId or SHA1 → DeviceNetworkEvents and DeviceFileEvents; AccountName → DeviceLogonEvents and SecurityEvent |
| KQL Starter | ```kql\nDeviceProcessEvents\n| where Timestamp >= ago(7d)\n| where FileName =~ \"powershell.exe\" and (ProcessCommandLine has \"-enc\" or ProcessCommandLine has \"http\")\n| project Timestamp, DeviceName, AccountName, ParentProcessName, FileName, ProcessCommandLine\n``` |

---

## 2. DeviceNetworkEvents

| Field | Value |
|-------|-------|
| Purpose | Network connections at process level |
| Source | Defender for Endpoint connector |
| Key Fields | Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, LocalIP, InitiatingProcessFileName, InitiatingProcessCommandLine |
| Typical Attack Coverage | C2 beacons, data exfiltration, SMB lateral movement (445), RDP traffic (3389, depending on sensor), crypto-mining pools, webshell outbound |
| MITRE | T1041 (Exfiltration Over C2 Channel), T1105 (Ingress Tool Transfer), T1021.002 (SMB/Windows Admin Shares), T1021.001 (RDP), T1046 (Network Service Scanning) |
| Common Pivots | RemoteIP / RemoteUrl → ThreatIntelligenceIndicator and CommonSecurityLog; InitiatingProcessFileName → DeviceProcessEvents; DeviceName → DeviceInfo for host context |
| KQL Starter | ```kql\nDeviceNetworkEvents\n| where Timestamp >= ago(1d)\n| where RemotePort == 445\n| summarize Connections = count() by DeviceName, InitiatingProcessFileName\n| where Connections > 200\n| order by Connections desc\n``` |

---

## 3. DeviceFileEvents

| Field | Value |
|-------|-------|
| Purpose | File creation, modification, deletion, rename on endpoints |
| Source | Defender for Endpoint connector |
| Key Fields | Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine |
| Typical Attack Coverage | Ransomware encryption (mass writes/renames), droppers writing executables, script-based downloaders, staging for exfiltration (large archives), suspicious binaries in user-writable paths |
| MITRE | T1486 (Data Encrypted for Impact), T1074 (Data Staged), T1105 (Ingress Tool Transfer) |
| Common Pivots | From SHA1 to DeviceProcessEvents for execution; from FolderPath to DeviceProcessEvents (who executed from that path); from InitiatingProcessFileName to DeviceNetworkEvents for C2 |
| KQL Starter | ```kql\nDeviceFileEvents\n| where Timestamp >= ago(1d)\n| where ActionType in (\"FileCreated\",\"FileModified\",\"FileRenamed\")\n| summarize FileOps = count(), DistinctExt = dcount(tostring(split(FileName, \".\")[-1])) by DeviceName, bin(Timestamp, 5m)\n| where FileOps > 1000 and DistinctExt > 20\n| order by FileOps desc\n``` |

---

## 4. DeviceRegistryEvents

| Field | Value |
|-------|-------|
| Purpose | Registry changes from endpoints |
| Source | Defender for Endpoint connector |
| Key Fields | Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, AccountName |
| Typical Attack Coverage | Persistence via Run/RunOnce keys, service configuration (`HKLM\\SYSTEM\\CurrentControlSet\\Services`), IFEO, COM hijack, LSA provider injection, enabling RDP, security policy tampering |
| MITRE | T1112 (Modify Registry), T1547 (Boot or Logon Autostart Execution), T1543 (Create or Modify System Process), T1556 (Modify Authentication Process) |
| Common Pivots | RegistryKey → known persistence paths; RegistryValueData → path → DeviceFileEvents + DeviceProcessEvents; InitiatingProcessFileName → suspicious processes writing registry |
| KQL Starter | ```kql\nDeviceRegistryEvents\n| where Timestamp >= ago(7d)\n| where RegistryKey has \"\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\"\n| project Timestamp, DeviceName, InitiatingProcessFileName, AccountName, RegistryKey, RegistryValueName, RegistryValueData\n``` |

---

## 5. DeviceLogonEvents

| Field | Value |
|-------|-------|
| Purpose | Logon events on endpoints (local, RDP, network, service) |
| Source | Defender for Endpoint connector |
| Key Fields | Timestamp, DeviceName, AccountName, AccountDomain, LogonType, RemoteIP, IsLocalAdmin, LogonId |
| Typical Attack Coverage | RDP brute-force, lateral movement, suspicious admin logons, service account interactive use |
| MITRE | T1021.001 (RDP), T1021.002 (SMB/Windows Admin Shares), T1078 (Valid Accounts) |
| Common Pivots | AccountName → SecurityEvent and SigninLogs; RemoteIP → pivoting hosts; DeviceName → DeviceProcessEvents after logon |
| KQL Starter | ```kql\nDeviceLogonEvents\n| where Timestamp >= ago(1d)\n| where LogonType == 10\n| summarize Count = count() by AccountName, RemoteIP, DeviceName\n| where Count > 20\n| order by Count desc\n``` |

---

## 6. DeviceInfo

| Field | Value |
|-------|-------|
| Purpose | Device inventory and metadata (OS, role, onboarding) |
| Source | Defender for Endpoint |
| Key Fields | DeviceName, OSPlatform, OSVersion, OnboardingStatus, IsAzureADJoined, AADDeviceId, LoggedOnUsers, Tags |
| Typical Attack Coverage | Not a detection table itself, but crucial for scoping (e.g. which OSes are affected, which machines are DCs, which are servers, etc.) |
| MITRE | Pre-ATT&CK style scoping and asset mapping |
| Common Pivots | DeviceName → all other Device* tables; Tags → identify critical assets (e.g. DCs, DB servers) |
| KQL Starter | ```kql\nDeviceInfo\n| summarize Count = count() by OSPlatform, OSVersion\n| order by Count desc\n``` |

---

## 7. DeviceEvents

| Field | Value |
|-------|-------|
| Purpose | Miscellaneous endpoint events: AV detections, exploit guard, network protection, scheduled task ops, etc. |
| Source | Defender for Endpoint |
| Key Fields | Timestamp, DeviceName, ActionType, AdditionalFields |
| Typical Attack Coverage | AV detection events, exploit/ASR block events, scheduled task creation, tampering events |
| MITRE | Depends on ActionType; often T1053 (tasks), T1203 (exploitation), T1562 (defense evasion) |
| Common Pivots | Filter on ActionType, then pivot to DeviceProcessEvents / DeviceFileEvents / DeviceNetworkEvents around the same time |
| KQL Starter | ```kql\nDeviceEvents\n| where Timestamp >= ago(7d)\n| where ActionType has \"Antivirus\"\n| summarize Detections = count() by DeviceName\n| order by Detections desc\n``` |

---

## 8. SecurityEvent

| Field | Value |
|-------|-------|
| Purpose | Classic Windows Security logs from servers/DCs/endpoints via agent/AMA |
| Source | Windows Security Log connector |
| Key Fields | EventID, TimeGenerated, Computer, Account, TargetUserName, TargetDomainName, LogonType, IpAddress, ProcessName, ServiceName |
| Typical Attack Coverage | Kerberoasting (4769), AS-REP roasting patterns (4768), brute-force (4625), logon success (4624), new services (7045), group changes, account lockouts, log clearing (1102) |
| MITRE | T1558 (Steal or Forge Kerberos Tickets), T1110 (Brute Force), T1543 (Create or Modify System Process), T1078 (Valid Accounts) |
| Common Pivots | Computer → Device* tables in MDE; IpAddress → DeviceNetworkEvents / CommonSecurityLog; Account → SigninLogs |
| KQL Starter – Kerberoasting Example | ```kql\nSecurityEvent\n| where TimeGenerated >= ago(7d)\n| where EventID == 4769\n| where ServiceName !has \"$\"\n| summarize TicketReqs = count() by IpAddress, Account, ServiceName\n| where TicketReqs > 20\n| order by TicketReqs desc\n``` |

---

## 9. Syslog

| Field | Value |
|-------|-------|
| Purpose | Generic Syslog ingestion (Linux servers, network devices, security tools) |
| Source | Syslog connector / AMA |
| Key Fields | TimeGenerated, Computer, Facility, SeverityLevel, SyslogMessage |
| Typical Attack Coverage | SSH logons, sudo activity, Linux auth failures, firewall logs (if sent via Syslog), IDS alerts, app-specific logs |
| MITRE | T1078, T1110 (for auth), varies heavily by device type |
| Common Pivots | SyslogMessage → extract IPs/users and pivot to SigninLogs, DeviceNetworkEvents, SecurityEvent |
| KQL Starter | ```kql\nSyslog\n| where TimeGenerated >= ago(1d)\n| where SyslogMessage has_any (\"failed password\",\"authentication failure\")\n``` |

---

*(You can add more endpoint-related tables here if your environment has custom or connector-specific host logs.)*
