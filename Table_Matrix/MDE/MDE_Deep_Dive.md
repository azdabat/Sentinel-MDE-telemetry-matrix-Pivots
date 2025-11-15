# 🧩 MDE Endpoint & Cloud Telemetry Deep Dive  
### **Complete L2–L3 Detection Engineering Reference**  
Microsoft Defender for Endpoint • Microsoft Sentinel • Defender for Cloud Apps (MCAS)  
Hybrid Professional + Hacker Aesthetic

---

# 📘 Contents  
1. Intrusion Investigation Flowchart  
2. Unified MITRE ATT&CK Matrix  
3. MDE Endpoint Telemetry (All Major Tables)  
4. MCAS / Cloud App Telemetry  
5. Cross-Table Pivot Guide  
6. Advanced Hunting / KQL Library  

---

# 🧭 1. Intrusion Investigation Flowchart (L2–L3 Workflow)

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

# 🎯 2. Unified Sentinel + MDE + MCAS MITRE ATT&CK Matrix

```markdown
| Tactic → / Source ↓ | MDE Endpoint | Sentinel | MCAS / CloudApps |
|---------------------|--------------|----------|------------------|
| **Reconnaissance** | DeviceInfo, DeviceNetworkInfo | SecurityAlert | CloudAppEvents |
| **Resource Dev.** | DeviceProcessEvents (tooling) | SecurityIncident | ShadowITDiscoveryEvents |
| **Initial Access** | DeviceNetworkEvents | SecurityAlert | CloudAppSecurityAlerts |
| **Execution** | DeviceProcessEvents, DeviceImageLoadEvents | Analytics Rules | MCAS Activity Policies |
| **Persistence** | DeviceRegistryEvents, FileEvents | AMA Logs | AppGovernancePolicyEvents |
| **Privilege Escalation** | ProcessEvents, RegistryEvents | UEBA | OAuth Abuse / App Governance |
| **Defense Evasion** | DeviceEvents (ASR/AV) | Sentinel Rules | CloudAppEvents (hidden exfil) |
| **Credential Access** | LogonEvents, RegistryEvents | Identity Logs | OAuth Token Theft |
| **Discovery** | ProcessEvents, NetworkEvents | Identity / AAD | CloudAppEvents |
| **Lateral Movement** | LogonEvents, NetworkEvents | SecurityIncident | Conditional Access |
| **Collection** | FileEvents | Sentinel | CloudAppFileEvents |
| **Exfiltration** | NetworkEvents | Sentinel | CloudAppFileEvents, MCAS Alerts |
| **C2** | NetworkEvents | Analytics Rules | SaaS Anomalies |
| **Impact** | DeviceEvents, FileEvents | SecurityAlert | MCAS Alerts |
```

---

# 🖥️ 3. COMPLETE MDE ENDPOINT TELEMETRY TABLES (L2–L3)

## DeviceInfo
Purpose: metadata  
KQL:
```kql
DeviceInfo | summarize count() by OSPlatform
```

## DeviceProcessEvents
```kql
DeviceProcessEvents | where FileName in ("powershell.exe","cmd.exe")
```

## DeviceNetworkEvents
```kql
DeviceNetworkEvents | where isnotempty(RemoteUrl)
```

## DeviceFileEvents
```kql
DeviceFileEvents | where ActionType=="FileCreated"
```

## DeviceRegistryEvents
```kql
DeviceRegistryEvents | where RegistryKey has "Run"
```

## DeviceImageLoadEvents
```kql
DeviceImageLoadEvents | where FolderPath has "AppData"
```

## DeviceLogonEvents
```kql
DeviceLogonEvents | where LogonType == 10
```

## DeviceEvents
```kql
DeviceEvents | where ActionType has "Block"
```

## DeviceNetworkInfo
```kql
DeviceNetworkInfo | summarize by DeviceName, IPAddress
```

## DeviceFileCertificateInfo
```kql
DeviceFileCertificateInfo | where Issuer !contains "Microsoft"
```

## TVM Tables
```kql
DeviceTvmSoftwareVulnerabilities | where Severity=="High"
```

---

# ☁️ 4. Cloud Telemetry

## CloudAppEvents
```kql
CloudAppEvents | summarize count() by AppName
```

## CloudAppFileEvents
```kql
CloudAppFileEvents | summarize count() by ActionType
```

## AppGovernancePolicyEvents
```kql
AppGovernancePolicyEvents | summarize count() by PolicyName
```

## AppGovernanceAlertEvents
```kql
AppGovernanceAlertEvents | summarize count() by AppDisplayName
```

## ShadowITDiscoveryEvents
```kql
ShadowITDiscoveryEvents | top 20 by TrafficVolume
```

## CloudAppSecurityAlerts
```kql
CloudAppSecurityAlerts | summarize count() by AppName
```

---

# 🧲 5. CROSS-TABLE PIVOT GUIDE

```markdown
| Start | Pivot | Why |
|-------|-------|-----|
| Process → Network | Identify C2 | Find beaconing |
| Network → Process | Identify malware | Find injector |
| File → Process | Identify dropper | Link payload |
| Registry → Process | Persistence actor | Track changes |
| ImageLoad → Process | DLL sideloading | Hijack detection |
| Logon → Network | Lateral movement | Identify host pivot |
| Cloud → AAD | Identity compromise | Account takeover |
```

---

# 🧨 6. ADVANCED HUNTING / KQL LIBRARY

## Timeline reconstruction
```kql
DeviceProcessEvents
| where DeviceName == "<DEVICE>"
| order by Timestamp asc
```

## C2 traffic
```kql
DeviceNetworkEvents
| where InitiatingProcessFileName has_any ("powershell","cmd","wscript")
| where RemoteUrl !contains "microsoft"
```

## Payload drop hunt
```kql
DeviceFileEvents
| where FolderPath has_any ("Users","AppData","Downloads","Temp")
```

## Persistence
```kql
DeviceRegistryEvents
| where RegistryKey has "\Run"
```

## Sideloaded DLLs
```kql
DeviceImageLoadEvents
| where FolderPath has_any ("Temp","AppData")
```

---

# ✔ END OF FILE
