# 🛰️ Ultimate SOC Table Guide – Microsoft 365 Defender & Sentinel
### L2–L3 Threat Hunting & Incident Response Reference
Hybrid Professional + Hacker Aesthetic • Endpoint • Identity • Email • Cloud • Alerts

---

## 📘 Contents

1. Investigation Flowchart (Any Intrusion)
2. Unified MITRE ATT&CK Coverage Matrix
3. MDE Endpoint Telemetry Tables (L2–L3)
4. Identity & Email Tables (Defender for Office 365 / AAD)
5. Cloud App & Shadow IT Tables (MCAS / App Governance)
6. Alerts & Incidents Tables (Sentinel + MDE)
7. Cross-Table Pivot Guide
8. Advanced KQL Hunting Library

---

## 1. Investigation Flowchart (Any Intrusion)

```ascii
+--------------------------------------------------------------+
|                    INCIDENT INVESTIGATION                    |
+--------------------------------------------------------------+
        |
        v
+------------------+
| 1. Alert Trigger |
+------------------+
        |
        v
+---------------------------+
| 2. Identify Affected Host |
+---------------------------+
        |
        v
+-----------------------------+
| 3. Pull Process Timeline    |
|    (DeviceProcessEvents)    |
+-----------------------------+
        |
        v
+-----------------------------+
| 4. Pivot to Network Traffic |
|    (DeviceNetworkEvents)    |
+-----------------------------+
        |
        v
+-----------------------------+
| 5. Look for File Drops      |
|    (DeviceFileEvents)       |
+-----------------------------+
        |
        v
+-----------------------------+
| 6. Persistence Check        |
|    (DeviceRegistryEvents)   |
+-----------------------------+
        |
        v
+-----------------------------+
| 7. DLL / Module Loads       |
|    (DeviceImageLoadEvents)  |
+-----------------------------+
        |
        v
+--------------------------------------------+
| 8. Identity Behaviour (AAD / LogonEvents)  |
+--------------------------------------------+
        |
        v
+--------------------------------------------+
| 9. Cloud App / SaaS Pivot (MCAS/MDE Cloud) |
+--------------------------------------------+
        |
        v
+------------------------+
| 10. Kill Chain Summary |
+------------------------+
```

---

## 2. Unified Sentinel + MDE + MCAS MITRE ATT&CK Matrix

```markdown
| Tactic → / Source ↓ | MDE Endpoint                    | Sentinel              | MCAS / CloudApps                    |
|---------------------|---------------------------------|-----------------------|-------------------------------------|
| Reconnaissance      | DeviceInfo, DeviceNetworkInfo   | SecurityAlert         | CloudAppEvents                      |
| Resource Dev.       | DeviceProcessEvents (tooling)   | SecurityIncident      | ShadowITDiscoveryEvents             |
| Initial Access      | DeviceNetworkEvents             | SecurityAlert         | CloudAppSecurityAlerts              |
| Execution           | DeviceProcessEvents, ImageLoads | Analytics Rules       | MCAS Activity Policies             |
| Persistence         | RegistryEvents, FileEvents      | AMA / Custom Logs     | AppGovernancePolicyEvents          |
| Priv Esc            | ProcessEvents, RegistryEvents   | UEBA                  | OAuth Abuse / App Governance       |
| Defense Evasion     | DeviceEvents (ASR/AV)           | Sentinel Rules        | CloudAppEvents (hidden exfil)      |
| Credential Access   | LogonEvents, RegistryEvents     | Identity Logs         | OAuth Token Theft                  |
| Discovery           | ProcessEvents, NetworkEvents    | Identity / AAD        | CloudAppEvents                     |
| Lateral Movement    | LogonEvents, NetworkEvents      | SecurityIncident      | Conditional Access                 |
| Collection          | FileEvents                      | Sentinel              | CloudAppFileEvents                 |
| Exfiltration        | NetworkEvents                   | Sentinel              | CloudAppFileEvents, MCAS Alerts    |
| C2                  | NetworkEvents                   | Analytics Rules       | SaaS Anomalies                     |
| Impact              | DeviceEvents, FileEvents        | SecurityAlert         | MCAS Alerts                        |
```

---

## 3. MDE Endpoint Telemetry Tables (L2–L3)

### 3.1 DeviceInfo — Endpoint Identity & Metadata

**Purpose:** Device identity, OS details, join status, tags.  
**Key Fields:** `DeviceName`, `OSPlatform`, `OSVersion`, `OnboardingStatus`, `IsAzureADJoined`, `AADDeviceId`, `Tags`.  
**Coverage:** Recon, asset criticality, unmanaged/high-risk hosts.

**Compact KQL**
```kql
DeviceInfo
| summarize count() by OSPlatform, OnboardingStatus
```

**L2–L3 Notes**
- Use tags to find DCs, Jump Hosts, Tier-0 assets.
- Identify unmanaged / not-onboarded machines from other sources vs DeviceInfo.

---

### 3.2 DeviceProcessEvents — Process Creation

**Purpose:** Process start events (core execution table).  
**Key Fields:** `Timestamp`, `DeviceName`, `FileName`, `ProcessCommandLine`, `InitiatingProcessFileName`, `FolderPath`, `AccountName`, `ProcessId`, `SHA1`.  
**Coverage:** LOLBins, malware, loaders, script engines, ransomware stages.  
**MITRE:** T1059, T1218, T1106, T1569.002, T1053.005.

**Compact KQL**
```kql
DeviceProcessEvents
| where FileName in ("powershell.exe","cmd.exe","wscript.exe","mshta.exe","rundll32.exe")
```

**L2–L3 Hunt – Full Timeline for One Host**
```kql
let targetHost = "<DEVICE_NAME>";
DeviceProcessEvents
| where DeviceName =~ targetHost
| order by Timestamp asc
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, ProcessCommandLine
```

**L2–L3 Hunt – Suspicious LOLBin Abuse**
```kql
DeviceProcessEvents
| where FileName in ("mshta.exe","regsvr32.exe","installutil.exe","rundll32.exe")
| where ProcessCommandLine has_any ("http","https",".js",".vbs",".hta")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

---

### 3.3 DeviceNetworkEvents — Process-Level Network Connections

**Purpose:** Every outbound network connection tied to a process.  
**Key Fields:** `Timestamp`, `DeviceName`, `InitiatingProcessFileName`, `InitiatingProcessCommandLine`, `RemoteIP`, `RemotePort`, `RemoteUrl`, `Protocol`.  
**Coverage:** C2, scanning, lateral movement (SMB/RDP/WinRM), exfiltration.  
**MITRE:** T1041, T1071, T1105, T1021.001/002, T1046.

**Compact KQL**
```kql
DeviceNetworkEvents
| where isnotempty(RemoteUrl)
```

**L2–L3 Hunt – Suspicious PowerShell / CMD C2**
```kql
DeviceNetworkEvents
| where Timestamp >= ago(24h)
| where InitiatingProcessFileName has_any ("powershell","cmd","wscript","cscript")
| where RemotePort in (80,443)
| where RemoteUrl !contains "microsoft" and RemoteUrl !contains "windowsupdate"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
```

**L2–L3 Hunt – Internal Lateral Movement**
```kql
DeviceNetworkEvents
| where Timestamp >= ago(7d)
| where RemoteIP startswith "10." or RemoteIP startswith "192.168."
| where RemotePort in (445,135,139,3389,5985,5986)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
```

---

### 3.4 DeviceFileEvents — File Creation & Modification

**Purpose:** File create/modify/delete events.  
**Key Fields:** `Timestamp`, `DeviceName`, `ActionType`, `FileName`, `FolderPath`, `SHA1`, `SHA256`, `InitiatingProcessFileName`.  
**Coverage:** Droppers, payload staging, ransomware encryption, exfil staging.  
**MITRE:** T1486, T1105, T1074.

**Compact KQL**
```kql
DeviceFileEvents
| where ActionType == "FileCreated"
```

**L2–L3 Hunt – User-Path Payload Drops**
```kql
DeviceFileEvents
| where Timestamp >= ago(7d)
| where ActionType == "FileCreated"
| where FolderPath has_any ("\Users\","\Desktop\","\Downloads\","AppData","Temp")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
```

**L2–L3 Hunt – Ransomware-Like Mass Changes**
```kql
DeviceFileEvents
| where Timestamp >= ago(1d)
| summarize Changes = count() by DeviceName, bin(Timestamp, 5m)
| where Changes > 500
| order by Changes desc
```

---

### 3.5 DeviceRegistryEvents — Registry Persistence & Tampering

**Purpose:** Registry set/create/delete operations.  
**Key Fields:** `Timestamp`, `DeviceName`, `RegistryKey`, `RegistryValueName`, `RegistryValueData`, `InitiatingProcessFileName`, `AccountName`.  
**Coverage:** Run keys, IFEO, COM hijack, RDP enabling, LSA protection tampering.  
**MITRE:** T1112, T1547, T1543, T1556.

**Compact KQL**
```kql
DeviceRegistryEvents
| where RegistryKey has "Run"
```

**L2–L3 Hunt – Classic Run Key Persistence**
```kql
DeviceRegistryEvents
| where Timestamp >= ago(7d)
| where RegistryKey has "\Run"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp desc
```

**L2–L3 Hunt – RDP Enablement**
```kql
DeviceRegistryEvents
| where Timestamp >= ago(7d)
| where RegistryKey has "System\CurrentControlSet\Control\Terminal Server"
| where RegistryValueName == "fDenyTSConnections" and RegistryValueData == "0"
```

---

### 3.6 DeviceImageLoadEvents — DLL Load Events (Sideloading & Injection)

**Purpose:** Tracks DLLs and modules loaded by processes.  
**Key Fields:** `Timestamp`, `DeviceName`, `FileName`, `FolderPath`, `SHA1`, `InitiatingProcessFileName`.  
**Coverage:** DLL search order hijacking, unsigned modules, sideloaded payloads.  
**MITRE:** T1574.002, T1055.

**Compact KQL**
```kql
DeviceImageLoadEvents
| where FolderPath has "AppData"
```

**L2–L3 Hunt – Suspicious DLLs in User Paths**
```kql
DeviceImageLoadEvents
| where Timestamp >= ago(7d)
| where FolderPath has_any ("AppData","Temp","\Users\")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath
```

---

### 3.7 DeviceLogonEvents — Logons & Lateral Movement

**Purpose:** Local & remote logon attempts.  
**Key Fields:** `Timestamp`, `DeviceName`, `AccountName`, `AccountDomain`, `LogonType`, `RemoteIP`.  
**Coverage:** RDP brute force, lateral movement, service account misuse.  
**MITRE:** T1021.001, T1021.002, T1078.

**Compact KQL**
```kql
DeviceLogonEvents
| where LogonType == 10
```

**L2–L3 Hunt – RDP Brute-Force / Spray**
```kql
DeviceLogonEvents
| where Timestamp >= ago(3d)
| where LogonType == 10
| summarize Attempts = count() by AccountName, RemoteIP, DeviceName
| where Attempts > 5
| order by Attempts desc
```

---

### 3.8 DeviceEvents — Defender Engine Activity (AV, ASR, Exploit Guard)

**Purpose:** AV detections, ASR blocks, Network Protection, Exploit Guard.  
**Key Fields:** `Timestamp`, `DeviceName`, `ActionType`, `AdditionalFields`.  
**Coverage:** Exploits, script-blocks, malware detection, tampering.  
**MITRE:** T1203, T1562.

**Compact KQL**
```kql
DeviceEvents
| where ActionType has "Block"
```

**L2–L3 Hunt – ASR/Exploit Guard Around an Intrusion**
```kql
DeviceEvents
| where Timestamp >= ago(3d)
| where ActionType has_any ("ASR","ExploitGuard","NetworkProtection")
| project Timestamp, DeviceName, ActionType, AdditionalFields
| order by Timestamp desc
```

---

### 3.9 DeviceNetworkInfo — Network Interfaces & IPs

**Purpose:** Device IPs, NIC configuration.  
**Key Fields:** `DeviceName`, `IPAddress`, `MacAddress`, `NetworkAdapterStatus`.  
**Coverage:** Recon, dual-homed hosts, pivot points.  
**MITRE:** TA0043 (Recon).

**Compact KQL**
```kql
DeviceNetworkInfo
| summarize IPs = make_set(IPAddress) by DeviceName
```

---

### 3.10 DeviceFileCertificateInfo — Code Signing Intelligence

**Purpose:** Mapping binaries to code signing certs.  
**Key Fields:** `FileName`, `SHA1`, `Publisher`, `Issuer`, `ValidFrom`, `ValidTo`, `CertificateThumbprint`.  
**Coverage:** Malicious signed binaries, fake cert issuers, expired cert abuse.  
**MITRE:** T1553.002.

**Compact KQL**
```kql
DeviceFileCertificateInfo
| where Issuer !contains "Microsoft"
```

---

### 3.11 DeviceTvmSoftwareVulnerabilities — Vulnerable Software / CVEs

**Purpose:** Threat & Vulnerability Management (TVM) – CVEs per device/software.  
**Key Fields:** `CveId`, `Severity`, `SoftwareName`, `DeviceId`.  
**Coverage:** Pre-attack risk, exploit paths.  
**MITRE:** Initial Access / Recon.

**Compact KQL**
```kql
DeviceTvmSoftwareVulnerabilities
| where Severity in ("High","Critical")
```

---

### 3.12 DeviceTvmSecureConfigurationAssessment — Hardening Gaps

**Purpose:** Secure configuration misconfigurations.  
**Key Fields:** `ConfigurationId`, `BenchmarkId`, `CurrentValue`, `DeviceId`.  
**Coverage:** Hardening issues, misconfigs leveraged by attackers.  
**MITRE:** Defense Evasion, Initial Access.

**Compact KQL**
```kql
DeviceTvmSecureConfigurationAssessment
| where CurrentValue == "NonCompliant"
```

---

## 4. Identity & Email Tables (Defender for Office 365 / AAD)

> Availability depends on licensing and integration with Defender for Office 365, AAD, and Defender XDR.

---

### 4.1 EmailEvents

| Field | Value |
|-------|-------|
| Purpose | High-level metadata for each email processed by Defender for Office 365. |
| Key Fields | `Timestamp`, `RecipientEmailAddress`, `SenderFromAddress`, `Subject`, `ThreatTypes`, `DeliveryAction`, `NetworkMessageId` |
| Coverage | Phishing, malware, BEC clues. |
| MITRE | T1566, T1204 |
| Compact KQL | `EmailEvents | where ThreatTypes != "" or DeliveryAction in ("Blocked","Replaced")` |

**L2–L3 Hunt – High-Risk Mailboxes**
```kql
EmailEvents
| where Timestamp >= ago(7d)
| where ThreatTypes != "" or DeliveryAction in ("Blocked","Replaced","Quarantined")
| summarize Alerts = count(), Threats = make_set(ThreatTypes) by RecipientEmailAddress
| order by Alerts desc
```

---

### 4.2 EmailUrlInfo

| Field | Value |
|-------|-------|
| Purpose | URLs extracted from email content. |
| Key Fields | `Timestamp`, `NetworkMessageId`, `Url`, `ThreatTypes` |
| Coverage | Phishing links, credential harvesting, malware staging. |
| MITRE | T1566, T1189 |
| Compact KQL | `EmailUrlInfo | where ThreatTypes != "" or Url has_any ("login","secure","verify")` |

**L2–L3 Hunt – Email URLs → Endpoint Clicks**
```kql
let suspiciousUrls =
    EmailUrlInfo
    | where Timestamp >= ago(7d)
    | where ThreatTypes != ""
        or Url has_any ("login","secure","verify","password","sso")
    | distinct Url;
DeviceNetworkEvents
| where Timestamp >= ago(7d)
| where isnotempty(RemoteUrl)
| where RemoteUrl in (suspiciousUrls)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
```

---

### 4.3 EmailAttachmentInfo

| Field | Value |
|-------|-------|
| Purpose | Attachments present in email messages. |
| Key Fields | `Timestamp`, `NetworkMessageId`, `FileName`, `FileType`, `SHA256`, `ThreatTypes` |
| Coverage | Malicious documents, archives, scripts, ISO/VHD, droppers. |
| MITRE | T1566, T1204, T1203 |
| Compact KQL | `EmailAttachmentInfo | where ThreatTypes != "" or FileType in ("exe","dll","iso","js","vbs","docm","xlsm")` |

**L2–L3 Hunt – High-Risk Attachment Types**
```kql
EmailAttachmentInfo
| where Timestamp >= ago(7d)
| where ThreatTypes != ""
   or FileType in ("exe","dll","iso","vhd","js","vbs","hta","docm","xlsm","zip","rar","7z")
| project Timestamp, NetworkMessageId, FileName, FileType, SHA256, ThreatTypes
| order by Timestamp desc
```

**L2–L3 Hunt – Follow Attachment Hash to Endpoints**
```kql
let riskyHashes =
    EmailAttachmentInfo
    | where Timestamp >= ago(14d)
    | where ThreatTypes != ""
        or FileType in ("exe","dll","iso","vhd","js","vbs","hta","docm","xlsm","zip","rar")
    | distinct SHA256;
DeviceFileEvents
| where Timestamp >= ago(14d)
| where SHA256 in (riskyHashes)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName
```

---

## 5. Cloud App & Shadow IT Tables (MCAS / App Governance)

### 5.1 CloudAppEvents

**Purpose:** Records SaaS activity (logins, file actions, admin changes).  
**Key Fields:** `Timestamp`, `AccountObjectId`, `UserAgent`, `SourceIPAddress`, `AppName`, `ActivityType`, `PolicyName`, `Severity`.  
**Coverage:** Shadow IT, risky cloud usage, suspicious sessions, exfil to unsanctioned SaaS.  
**MITRE:** T1530, T1041, T1133.

**Compact KQL**
```kql
CloudAppEvents
| where Timestamp >= ago(7d)
| summarize Events = count() by AppName, ActivityType
```

---

### 5.2 CloudAppFileEvents

**Purpose:** File actions in SaaS (upload, download, share).  
**Key Fields:** `ActionType`, `FileName`, `FileType`, `FileURL`, `AppName`, `AccountObjectId`.  
**Coverage:** Cloud exfiltration, data exposure, sensitive file movement.  
**MITRE:** T1530, T1041.

**Compact KQL**
```kql
CloudAppFileEvents
| where Timestamp >= ago(7d)
| summarize Events = count() by AppName, ActionType
```

---

### 5.3 AppGovernancePolicyEvents & AppGovernanceAlertEvents

**Purpose:** Monitoring and alerts for OAuth app behaviour.  
**Key Fields:** `AppId`, `AppDisplayName`, `PolicyName`, `RiskScore`.  
**Coverage:** OAuth app abuse, exfil via third-party apps.  
**MITRE:** T1528, T1550, T1098.003.

**Compact KQL**
```kql
AppGovernanceAlertEvents
| summarize Alerts = count() by AppDisplayName, Severity
```

---

### 5.4 ShadowITDiscoveryEvents

**Purpose:** Unsanctioned SaaS identified via endpoint traffic.  
**Coverage:** Shadow IT, risky SaaS usage.  
**Compact KQL**
```kql
ShadowITDiscoveryEvents
| summarize MB = sum(TrafficVolume) by AppName
| top 20 by MB
```

---

## 6. Alerts & Incidents Tables (Sentinel + MDE)

### 6.1 AlertInfo (M365 Defender Alert Metadata)

**Purpose:** Alert metadata from Defender (including MDE).  
**Key Fields:** `AlertId`, `Title`, `Category`, `DetectionSource`, `ServiceSource`, `Severity`, `StartTime`.  
**Coverage:** All threats MDE/Microsoft 365 Defender detects.  

**Compact KQL**
```kql
AlertInfo
| where StartTime >= ago(2d)
| summarize count() by ServiceSource, Category, Severity
```

---

### 6.2 AlertEvidence (Entities Behind the Alert)

**Purpose:** Devices, accounts, files, IPs, URLs tied to an AlertId.  
**Key Fields:** `AlertId`, `EntityType`, `DeviceId`, `DeviceName`, `AccountName`, `FileName`, `Sha1`, `RemoteUrl`, `IPAddress`.  

**L2–L3 Pivot – Alert → Endpoint Telemetry**
```kql
let targetAlertId = "<ALERT_ID>";
let devices =
    AlertEvidence
    | where AlertId == targetAlertId and isnotempty(DeviceId)
    | distinct DeviceId;
DeviceProcessEvents
| where DeviceId in (devices)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

---

### 6.3 SecurityAlert (Sentinel Unified Alerts)

**Purpose:** Sentinel’s unified alert view across sources.  
**Key Fields:** `SystemAlertId`, `ProductName`, `AlertName`, `Severity`, `CompromisedEntity`.  

**Compact KQL**
```kql
SecurityAlert
| where TimeGenerated >= ago(1d)
| summarize count() by ProductName, Severity
```

---

### 6.4 SecurityIncident (Sentinel Incidents)

**Purpose:** Correlated group of alerts representing a campaign/incident.  
**Key Fields:** `IncidentNumber`, `Title`, `Severity`, `Status`, `Owner`.  

**Compact KQL**
```kql
SecurityIncident
| where Status != "Closed"
| project IncidentNumber, Title, Severity, Status, Owner
```

---

## 7. Cross-Table Pivot Guide

```markdown
| Start Point         | Pivot To                      | Purpose                            |
|---------------------|------------------------------|------------------------------------|
| AlertInfo           | AlertEvidence                | Get entities                       |
| AlertEvidence (IP)  | DeviceNetworkEvents          | Find C2 / lateral pivot            |
| AlertEvidence (File)| DeviceFileEvents/Process     | Find payload & executing process   |
| DeviceProcessEvents | DeviceNetworkEvents          | Map C2 & exfil                     |
| DeviceNetworkEvents | DeviceProcessEvents          | Identify beaconing malware         |
| DeviceFileEvents    | DeviceProcessEvents          | Identify dropper                   |
| RegistryEvents      | ProcessEvents                | Source of persistence              |
| EmailAttachmentInfo | DeviceFileEvents             | Attachments executed on endpoints  |
| EmailUrlInfo        | DeviceNetworkEvents          | Users who clicked phishing links   |
| CloudAppEvents      | AAD Sign-in Logs             | Correlate cloud with identity      |
```

---

## 8. Advanced KQL Hunting Library (Core Blocks)

### Process Timeline

```kql
DeviceProcessEvents
| where DeviceName == "<DEVICE>"
| order by Timestamp asc
```

### Suspicious Outbound C2

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName has_any ("powershell","cmd","wscript")
| where RemotePort in (80,443)
| where RemoteUrl !contains "microsoft" and RemoteUrl !contains "windowsupdate"
```

### Ransomware Burst Detection

```kql
DeviceFileEvents
| where Timestamp >= ago(1d)
| summarize Changes = count() by DeviceName, bin(Timestamp, 5m)
| where Changes > 500
```

### Persistence – Run Keys

```kql
DeviceRegistryEvents
| where RegistryKey has "\Run"
```

### Phishing to Endpoint Click

```kql
let suspiciousUrls =
    EmailUrlInfo
    | where Timestamp >= ago(7d)
    | where ThreatTypes != "" 
        or Url has_any ("login","secure","verify","password","reset","update")
    | distinct Url;
DeviceNetworkEvents
| where Timestamp >= ago(7d)
| where RemoteUrl in (suspiciousUrls)
```

---

# ✔ End of Ultimate SOC Table Guide
