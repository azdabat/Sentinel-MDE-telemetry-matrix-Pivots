# ☁️ Microsoft Defender for Cloud Apps (MCAS) — Cloud App & Shadow IT Tables  
**Scope:**  
These tables appear in **Sentinel** when Defender for Cloud Apps / App Governance is enabled and logs are connected.  
They support high-fidelity detection of **Shadow IT, cloud exfiltration, OAuth abuse, suspicious SaaS activity, and app governance policy violations**.

--- 

# 1. CloudAppEvents — Cloud App Usage & Risky Activity

| Field | Value |
|-------|-------|
| **Purpose** | Records user activity across SaaS applications (Teams, SharePoint, Box, Dropbox, GDrive, 3rd-party SaaS). |
| **Key Fields** | `Timestamp`, `UserAgent`, `SourceIPAddress`, `AccountObjectId`, `AppName`, `ActivityType`, `PolicyName`, `Severity` |
| **Typical Coverage** | Shadow IT, risky SaaS behaviour, exfiltration to unsanctioned cloud storage, anomalous access patterns. |
| **MITRE** | T1530 (Data from Cloud Storage), T1041 (Web Exfil), T1133 (External Services) |
| **Important L2–L3 Pivots** | • `AccountObjectId → SigninLogs` • `SourceIPAddress → DeviceNetworkEvents` • `AppName → sanctioned app list` |
| **KQL (Compact)** | `CloudAppEvents \| where Timestamp >= ago(7d) \| summarize count() by AppName, ActivityType` |

---

# 2. CloudAppFileEvents — File Upload/Download & Sharing

| Field | Value |
|-------|-------|
| **Purpose** | Tracks uploads, downloads, sharing actions across SaaS apps (Box, Drive, SharePoint, Dropbox). |
| **Key Fields** | `Timestamp`, `AccountObjectId`, `ActionType`, `FileName`, `FileType`, `FileURL`, `AppName`, `SensitivityLabel`, `SharePointItemId` |
| **Typical Coverage** | Data exfiltration, data exposure, suspicious data movement, sensitive file uploads to unsanctioned cloud apps. |
| **MITRE** | T1530, T1041 (Exfiltration over Web), T1081 (Data from Info Repositories) |
| **Important L2–L3 Pivots** | • `FileURL → CloudAppEvents` • `AccountObjectId → AAD SigninLogs` • Compare against DLP alerts |
| **KQL (Compact)** | `CloudAppFileEvents \| where Timestamp >= ago(7d) \| summarize count() by AppName, ActionType` |

---

# 3. AppFileSigningEvents — OAuth App File Activity (App Governance)

| Field | Value |
|-------|-------|
| **Purpose** | Identifies OAuth apps interacting with files: reading, modifying or exporting tenant data (OneDrive, SharePoint). |
| **Key Fields** | `AppId`, `AppDisplayName`, `FileName`, `FileURL`, `OperationName`, `ResourceType`, `UserId` |
| **Typical Coverage** | OAuth consent abuse, rogue apps extracting files, over-privileged third-party apps. |
| **MITRE** | T1528 (Steal Application Access Token), T1550.001 (Token Impersonation), T1098.003 (Add Service Principal Credentials) |
| **L2–L3 Pivots** | • `AppId → AzureADServicePrincipal` • `UserId → AAD SigninLogs` |
| **KQL (Compact)** | `AppFileSigningEvents \| summarize count() by AppDisplayName, OperationName` |

---

# 4. AppGovernancePolicyEvents — Policy Matches in MCAS/App Governance

| Field | Value |
|-------|-------|
| **Purpose** | Tracks when app governance policies are triggered (risky behavior by OAuth apps). |
| **Key Fields** | `Timestamp`, `PolicyId`, `PolicyName`, `AppId`, `AppDisplayName`, `RiskScore`, `MatchedCondition` |
| **Typical Coverage** | Rogue OAuth behavior, anomalous app activity, large-volume data exposure, privilege escalation via app identity. |
| **MITRE** | T1098 (Account Manipulation), T1528, T1552.005 (Cloud Credentials) |
| **L2–L3 Pivots** | • Cross-reference with `AppGovernanceAlertEvents` • `AppId → AzureADServicePrincipal` |
| **KQL (Compact)** | `AppGovernancePolicyEvents \| summarize count() by PolicyName, AppDisplayName` |

---

# 5. AppGovernanceAlertEvents — Alerts Triggered by App Governance

| Field | Value |
|-------|-------|
| **Purpose** | Alerts for suspicious OAuth app behavior: mass file downloads, mailbox access, token abuse. |
| **Key Fields** | `AlertId`, `Severity`, `Category`, `AppId`, `AppDisplayName`, `UserId`, `Activity`, `Impact` |
| **Typical Coverage** | OAuth token misuse, malicious third-party SaaS, rogue enterprise apps. |
| **MITRE** | T1528, T1550, T1098.003 |
| **L2–L3 Pivots** | • `AlertId → AlertInfo/AlertEvidence` • `AppId → AzureAD App Registration` |
| **KQL (Compact)** | `AppGovernanceAlertEvents \| summarize count() by AppDisplayName, Severity` |

---

# 6. ShadowITDiscoveryEvents — SaaS Discovery From Endpoint Logs

| Field | Value |
|-------|-------|
| **Purpose** | Tracks endpoints accessing cloud apps outside sanctioned list (“Shadow IT”). |
| **Key Fields** | `DeviceId`, `DeviceName`, `AppName`, `TrafficVolume`, `Category`, `UserPrincipalName`, `IPAddress` |
| **Typical Coverage** | Unapproved SaaS usage, high-risk cloud activity, exfiltration via personal accounts. |
| **MITRE** | T1133 (External Services), T1041 |
| **L2–L3 Pivots** | • `AppName → sanctioned/unsanctioned list` • `DeviceId → DeviceNetworkEvents` |
| **KQL (Compact)** | `ShadowITDiscoveryEvents \| summarize MB = sum(TrafficVolume) by AppName \| top 20 by MB` |

---

# 7. CloudAppSecurityAlerts — MCAS Security Alerts (High-Fidelity)

| Field | Value |
|-------|-------|
| **Source** | MCAS alert feed → Sentinel `SecurityAlert` table OR `CloudAppSecurity` connector. |
| **Purpose** | Alerts for impossible travel, session hijacking, OAuth abuse, unusual download patterns, DLP violations. |
| **Key Fields** | `AlertId`, `Title`, `Severity`, `Description`, `AccountObjectId`, `AppName`, `SourceIPAddress`, `ActivityType` |
| **Typical Coverage** | Compromised cloud identity, cloud exfiltration, session token theft, app misuse. |
| **MITRE** | T1530, T1041, T1550 (Token Theft), T1528 |
| **L2–L3 Pivots** | • Join → `SecurityAlert` • `AccountObjectId → SigninLogs` • `SourceIPAddress → threat intel lookup` |
| **KQL (Compact)** | `CloudAppSecurityAlerts \| summarize count() by AppName, Severity` |

---

# 🧱 L2–L3 Investigation Patterns (Cloud App Edition)

These are **actual** analyst playbook blocks for MCAS/SaaS investigations.

---

### 🔍 Pattern 1 — “Show me risky SaaS apps by activity volume”
```kql
CloudAppEvents
| where Timestamp >= ago(48h)
| summarize Events=count() by AppName, ActivityType
| top 20 by Events
