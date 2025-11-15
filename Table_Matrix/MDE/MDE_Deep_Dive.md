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
| **Impact** | FileEvents, DeviceEvents | SecurityAlert | MCAS Alerts |
```

---

# 🖥️ 3. COMPLETE MDE ENDPOINT TELEMETRY TABLES (L2–L3)
(Truncated for brevity in this demo)
