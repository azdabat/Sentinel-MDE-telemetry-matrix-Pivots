# 🚨 Microsoft Defender — Alerts & Incident Tables (L2–L3 SOC Edition)

This section provides **practical, high-value pivots** for analysts handling real intrusions — not basic summaries.  
All KQL fits cleanly in the cells.

---

# 1. AlertInfo (High-Level Alert Metadata)

| Field | Value |
|-------|-------|
| Purpose | Root alert container: severity, category, source service, timestamps. Used for triage and cross-tenant visibility. |
| Key Fields | AlertId, Title, Category, Severity, ServiceSource, DetectionSource, StartTime, EndTime |
| Analyst Use Cases | Triage, prioritisation, filtering false positives, identifying detection gaps. |
| L2–L3 Pivot | Group by DetectionSource to identify weak telemetry paths. |
| KQL Starter (Advanced) | `AlertInfo | where StartTime >= ago(3d) | summarize count() by DetectionSource, ServiceSource, Severity` |

---

# 2. AlertEvidence (Entities Linked to the Alert)

| Field | Value |
|-------|-------|
| Purpose | All IoCs associated with an alert: files, users, processes, IPs, URLs, registry paths, cloud apps. |
| Key Fields | AlertId, EntityType, DeviceName, AccountName, FileName, Sha1, RemoteUrl, IPAddress |
| Analyst Use Cases | Entity extraction → pivot into DeviceProcessEvents, NetworkEvents, CloudAppEvents. |
| L2–L3 Pivot | Build an entity graph from one alert and follow all related processes across devices. |
| KQL Starter (Advanced) | `AlertEvidence | where AlertId == "<ID>" | project EntityType, DeviceName, AccountName, FileName, RemoteUrl, IPAddress` |

---

# 3. AlertEvents (Alert Timeline Events)

| Field | Value |
|-------|-------|
| Purpose | Timeline events generated *within* the alert: process, file, network, registry, identity behaviours. |
| Key Fields | AlertId, Timestamp, EventType, DeviceId, Detail | 
| Analyst Use Cases | Build an intra-alert timeline without querying every Device* table manually. |
| L2–L3 Pivot | Reconstruct the full attack chain inside a single alert. |
| KQL Starter (Advanced) | `AlertEvents | where AlertId == "<ID>" | project Timestamp, EventType, DeviceId, Detail` |

---

# 4. IncidentInfo (Incident-Level Container)

| Field | Value |
|-------|-------|
| Purpose | Groups related alerts across devices/users into a single incident (Kill Chain view). |
| Key Fields | IncidentId, Title, Status, Severity, Category, InvestigationState |
| Analyst Use Cases | Track multi-stage intrusions, prioritise IR workflows, identify lateral movement chains. |
| L2–L3 Pivot | Query all alerts inside the same incident → enumerate affected entities. |
| KQL Starter (Advanced) | `IncidentInfo | where Status != "Resolved" | project IncidentId, Title, Severity, Category` |

---

# 5. IncidentAlerts (Alerts Belonging to Each Incident)

| Field | Value |
|-------|-------|
| Purpose | Connects incidents to their underlying alerts. |
| Key Fields | IncidentId, AlertId, Severity, Category |
| Analyst Use Cases | Identify patterns across related alerts (same device, same user, same malware family). |
| L2–L3 Pivot | Pull all correlated alerts → pivot deeper via AlertEvidence. |
| KQL Starter (Advanced) | `IncidentAlerts | where IncidentId == "<INCIDENT_ID>" | project IncidentId, AlertId, Category, Severity` |

---

# 6. AlertRelatedUser (All Users Associated with the Alert)

| Field | Value |
|-------|-------|
| Purpose | User entities involved in an alert (sign-in anomalies, token manipulation, persistence abuse). |
| Key Fields | AlertId, UserName, AccountObjectId, Role |
| Analyst Use Cases | Identify compromised accounts, privilege escalation, cloud identity abuse (OAuth). |
| L2–L3 Pivot | Join with AAD SigninLogs → full identity-based timeline. |
| KQL Starter (Advanced) | `AlertRelatedUser | where AlertId == "<ID>" | project UserName, AccountObjectId` |

---

# 7. AlertRelatedService (Cloud App / Service Identity)

| Field | Value |
|-------|-------|
| Purpose | Identifies cloud services and apps involved (AzureAD, M365, EXO, Cloud App Security). |
| Key Fields | AlertId, ServiceSource, AppId, AppName |
| Analyst Use Cases | Detect malicious OAuth apps, service principal misuse, token-reuse patterns. |
| L2–L3 Pivot | Cross-reference with AuditLogs → “Add Service Principal Credentials”, consent events. |
| KQL Starter (Advanced) | `AlertRelatedService | where AlertId == "<ID>" | project AppName, ServiceSource` |

---

# 8. AlertRelatedDevice (Devices Linked to the Alert)

| Field | Value |
|-------|-------|
| Purpose | All endpoints involved: workstation, server, DC, jump host, cloud VM, hybrid join. |
| Key Fields | AlertId, DeviceId, DeviceName, OSPlatform |
| Analyst Use Cases | Device enumeration, spotting lateral movement, infected fleet analysis. |
| L2–L3 Pivot | Join DeviceId → DeviceProcessEvents for chain reconstruction. |
| KQL Starter (Advanced) | `AlertRelatedDevice | where AlertId=="<ID>" | project DeviceName, DeviceId, OSPlatform` |

---

# 9. AlertRelatedIP (IP-level Indicators)

| Field | Value |
|-------|-------|
| Purpose | IP addresses involved in alert: internal lateral movement, external C2, VPN exit nodes. |
| Key Fields | AlertId, IPAddress, Location |
| Analyst Use Cases | Identify pivot hosts, suspicious internal subnets, cloud infra → pivot to NetworkEvents. |
| L2–L3 Pivot | Cross-reference IP → DeviceNetworkEvents → find initiating process. |
| KQL Starter (Advanced) | `AlertRelatedIP | where AlertId=="<ID>" | project IPAddress, Location` |

---

# 10. AlertRelatedURL (Malicious URLs and C2 Endpoints)

| Field | Value |
|-------|-------|
| Purpose | Captures suspicious URLs detected by SmartScreen, Defender, Cloud App Security, Office 365. |
| Key Fields | AlertId, Url, UrlCategory |
| Analyst Use Cases | Phishing, C2, staging servers, payload hosting. |
| L2–L3 Pivot | Join → UrlClickEvents (Defender for Office) OR DeviceNetworkEvents (if endpoint-based). |
| KQL Starter (Advanced) | `AlertRelatedURL | where AlertId=="<ID>" | project Url` |
