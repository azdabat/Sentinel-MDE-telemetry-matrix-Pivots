### Project Overview

## This repository demonstrates:

Intelligence-driven detection engineering

Complete endpoint telemetry mastery (Process, Network, Registry, File, ImageLoad…)

Cross-cloud & SaaS threat analysis (MCAS, CloudAppEvents)

Attack-chain reconstruction

MITRE ATT&CK alignment

L2–L3 SOC investigation methodology

Threat intel enrichment & scoring logic

Built as a real SOC detection-engineering knowledge base.

🧭 How to Investigate Any Intrusion (L2–L3 Flowchart)

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

🎯 Complete Sentinel + MDE + MCAS MITRE ATT&CK Matrix

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


---

# ✅ **FILE 2 — `MDE_DeepDive.md` (Full SOC L2–L3 Detection Engineering Document)**  
Copy **everything below** into your second file.

```markdown
# 🧩 MDE Endpoint & Cloud Telemetry Deep Dive  
**Complete L2–L3 Detection Engineering Reference**  
Microsoft Defender for Endpoint • Sentinel • MCAS

---

# 📘 Contents
1. MDE Endpoint Tables (All Major Tables)
2. MCAS & Cloud App Tables  
3. Detailed MITRE ATT&CK Mappings  
4. Threat-Hunting Playbooks (Per Table)  
5. Intrusion Reconstruction Workflows  
6. Cross-Table Pivot Guide  
7. Advanced KQL Library

---

# 🖥️ 1. COMPLETE MDE ENDPOINT TABLE SET (L2–L3)

All endpoint tables below are fully documented.

---

## 1. DeviceInfo

| Field | Value |
|-------|-------|
| Purpose | Endpoint identity & metadata |
| Coverage | Recon, asset classification |
| MITRE | TA0043 |
| Compact KQL | `DeviceInfo \| summarize count() by OSPlatform` |

---

## 2. DeviceProcessEvents  
Process Creation — **Execution Core**

| Field | Value |
|-------|-------|
| Purpose | Process creation |
| Coverage | LOLBins, malware, C2 loaders |
| MITRE | T1059, T1218 |
| KQL | `DeviceProcessEvents \| where FileName in ("powershell.exe","cmd.exe")` |

---

## 3. DeviceNetworkEvents  
Network Connections — **C2 + Lateral + Exfil**

| Purpose | Process-level network events |
| MITRE | T1041, T1105 |
| KQL | `DeviceNetworkEvents \| where isnotempty(RemoteUrl)` |

---

## 4. DeviceFileEvents  
File Writes — **Payload Drops + Ransomware**

| MITRE | T1486 |
| KQL | `DeviceFileEvents \| where ActionType=="FileCreated"` |

---

## 5. DeviceRegistryEvents  
Registry Modifications — **Persistence + Tampering**

| MITRE | T1112, T1547 |
| KQL | `DeviceRegistryEvents \| where RegistryKey has "Run"` |

---

## 6. DeviceImageLoadEvents  
DLL Loads — **Sideloading + Injection**

| MITRE | T1574.002 |
| Compact KQL | `DeviceImageLoadEvents \| where FolderPath has "AppData"` |

---

## 7. DeviceLogonEvents  
Auth Events — **Lateral Movement**

| MITRE | T1021.001 |
| KQL | `DeviceLogonEvents \| where LogonType == 10` |

---

## 8. DeviceEvents  
Defender Engine — **ASR, AV, Exploit Guard**

| MITRE | T1562 |
| KQL | `DeviceEvents \| where ActionType has "Block"` |

---

## 9. DeviceNetworkInfo  
NIC Metadata

| MITRE | Recon |
| KQL | `DeviceNetworkInfo \| summarize by DeviceName, IPAddress` |

---

## 10. DeviceFileCertificateInfo  
Signed Binary Intelligence

| MITRE | T1553.002 |
| KQL | `DeviceFileCertificateInfo \| where Issuer !contains "Microsoft"` |

---

## 11. DeviceTvmSoftwareVulnerabilities  
TVM — Software CVEs

| MITRE | Recon |
| KQL | `DeviceTvmSoftwareVulnerabilities \| where Severity=="High"` |

---

## 12. DeviceTvmSecureConfigurationAssessment  
Hardening / Misconfig

| MITRE | Defense Evasion |
| KQL | `DeviceTvmSecureConfigurationAssessment \| where CurrentValue=="NonCompliant"` |

---

# ☁️ 2. MCAS & CLOUD APP TABLES

All Defender for Cloud Apps tables:

- CloudAppEvents  
- CloudAppFileEvents  
- AppFileSigningEvents  
- AppGovernancePolicyEvents  
- AppGovernanceAlertEvents  
- ShadowITDiscoveryEvents  
- CloudAppSecurityAlerts  

(Full content already previously generated — included in your project.)

---

# 🧠 3. UNIFIED MITRE ATT&CK MATRIX (FULL VERSION)

```markdown
| Tactic | Endpoint Tables | Cloud Tables | Sentinel |
|--------|-----------------|--------------|----------|
| Recon | DeviceInfo, DeviceNetworkInfo | CloudAppEvents | SecurityAlert |
| Resource Dev | ProcessEvents | CloudAppEvents | SecurityIncident |
| Initial Access | NetworkEvents | CloudAppSecurityAlerts | Sentinel Rules |
| Execution | ProcessEvents, ImageLoads | — | Analytics Rules |
| Persistence | RegistryEvents, FileEvents | AppGovernancePolicyEvents | Sentinel |
| Priv Esc | RegistryEvents, ProcessEvents | OAuth Abuse | UEBA |
| Defense Evasion | DeviceEvents | CloudAppEvents | Sentinel |
| Credential Access | LogonEvents, RegistryEvents | OAuth Token Theft | AAD Logs |
| Discovery | ProcessEvents, NetworkEvents | CloudAppEvents | Sentinel |
| Lateral Movement | LogonEvents, NetworkEvents | — | SecurityIncident |
| Collection | FileEvents | CloudAppFileEvents | Sentinel |
| Exfiltration | NetworkEvents | CloudAppFileEvents | MCAS Alerts |
| C2 | NetworkEvents | SaaS Alerts | Rules |
| Impact | FileEvents, DeviceEvents | — | Sentinel |


👨‍💻 Author

Ala Dabat (AZDABAT)
Threat Detection Engineering • SOC L3 • Threat Intelligence
Expert in MDE • Sentinel • MCAS • Attack-chain analysis • CTI-driven detections
