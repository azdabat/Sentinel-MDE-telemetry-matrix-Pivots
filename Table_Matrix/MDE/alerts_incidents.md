# ⚠️ Microsoft Defender — Alerts & Incident Tables (Sentinel + MDE)

This section documents how **Microsoft Defender for Endpoint (MDE)** alerts surface into **Microsoft Sentinel**, and how to use the core alert/incident tables at **L2–L3 investigation level**.

> **Scope:**  
> - **MDE Advanced Hunting / M365D schema:** `AlertInfo`, `AlertEvidence`  
> - **Sentinel-native incident & alert views:** `SecurityAlert`, `SecurityIncident`  
> - Assumes the **Microsoft 365 Defender / MDE connectors** are enabled in Sentinel.

---

## 1. `AlertInfo` — MDE Alert Metadata (Unified Defender Schema)

| Field | Value |
|-------|-------|
| **Source** | Microsoft Defender (Advanced Hunting schema – available in Sentinel when M365D connector is enabled). |
| **Purpose** | Root alert record: *what* fired, *where*, *how severe*, *which product* raised it. |
| **Key Fields** | `AlertId`, `Title`, `Description`, `Category`, `DetectionSource`, `ServiceSource`, `Severity`, `StartTime`, `EndTime` |
| **Typical Uses (L2–L3)** | Alert triage at scale, find noisy detections, map detection coverage by product, surface blind spots (e.g. few Identity alerts vs Endpoint). |
| **MITRE** | Mapped indirectly via `Category` / `Title` / JSON properties; not as granular as Device* tables. |
| **Quick KQL (Triage)** | `AlertInfo \| where StartTime >= ago(24h) \| summarize count() by ServiceSource, Category, Severity` |

---

## 2. `AlertEvidence` — Entities Behind the Alert

| Field | Value |
|-------|-------|
| **Source** | Microsoft Defender (Advanced Hunting schema – flows with MDE → Sentinel). |
| **Purpose** | Breaks down each alert into **entities**: devices, users, processes, files, IPs, URLs, registry keys, mailboxes. |
| **Key Fields** | `AlertId`, `EntityType`, `DeviceId`, `DeviceName`, `AccountName`, `AccountSid`, `FileName`, `Sha1`, `RemoteUrl`, `IPAddress`, `RegistryKey`, `RegistryValueName` |
| **Typical Uses (L2–L3)** | Take an alert and pivot to **DeviceProcessEvents/Network/Registry/File** to reconstruct the attack chain; enumerate all impacted devices and accounts. |
| **MITRE** | Inherits ATT&CK mapping from the parent alert, but entity types help you tie to specific tactics (e.g. process → Execution, registry → Persistence). |
| **Quick KQL (Entities View)** | `AlertEvidence \| where AlertId == "<ALERT_ID>" \| project EntityType, DeviceName, AccountName, FileName, RemoteUrl, IPAddress` |

---

## 3. `SecurityAlert` — Sentinel’s Unified Alert View

| Field | Value |
|-------|-------|
| **Source** | Sentinel-native table; each row = one alert from a connected product (MDE, AAD, O365, custom analytics, etc.). |
| **Purpose** | Normalised alert view for all connectors (MDE, Azure AD, MCAS, custom rules). Good for **cross-product hunting**. |
| **Key Fields** | `SystemAlertId`, `ProductName`, `ProviderName`, `Severity`, `CompromisedEntity`, `StartTime`, `EndTime`, `ExtendedProperties` (JSON) |
| **Typical Uses (L2–L3)** | Cross-correlation: “Which other products also fired on this host/user/IP around the same time?”, finding alert clusters across multiple data sources. |
| **MITRE** | Depends on the analytic/connector; some store ATT&CK tags in `ExtendedProperties`. |
| **Quick KQL (Cross-Product Triage)** | `SecurityAlert \| where TimeGenerated >= ago(24h) \| summarize count() by ProductName, Severity` |

---

## 4. `SecurityIncident` — Sentinel Incident Container

| Field | Value |
|-------|-------|
| **Source** | Sentinel’s incident engine (Fusion, analytics rules, playbooks). |
| **Purpose** | Groups related alerts (from `SecurityAlert`) into a **single incident** representing a broader attack or campaign. |
| **Key Fields** | `IncidentId`, `Title`, `Description`, `Severity`, `Status`, `Owner`, `Classification`, `Label`, `FirstActivityTime`, `LastActivityTime` |
| **Typical Uses (L2–L3)** | Track **full kill-chain**, hand-off to IR, measure MTTR/MTTD, group multi-device or multi-user activity into a single case. |
| **MITRE** | Not directly stored, but incident often aggregates multiple alerts that each have ATT&CK context. |
| **Quick KQL (Open Incidents)** | `SecurityIncident \| where Status != "Closed" \| project IncidentNumber, Title, Severity, Status, Owner` |

---

## 5. Putting It Together — Core L2–L3 Investigation Patterns

Below are **realistic starting patterns** for defenders. Keep these as “playbook building blocks” in your README.

---

### 🔎 Pattern 1 — “Show me all MDE alerts in Sentinel by product & severity (last 24h)”

```kql
AlertInfo
| where StartTime >= ago(24h)
| summarize Alerts = count() by ServiceSource, DetectionSource, Severity
| order by Alerts desc
