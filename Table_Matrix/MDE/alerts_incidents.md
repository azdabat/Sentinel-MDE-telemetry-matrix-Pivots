# 🚨 MDE Alerts & Incidents

---

## 1. AlertInfo

| Field | Value |
|-------|-------|
| Purpose | High-level information about alerts raised in Defender (Endpoint, Identity, Office, Cloud Apps) |
| Key Fields | AlertId, Title, Category, Severity, ServiceSource, DetectionSource, StartTime, EndTime |
| Typical Attack Coverage | All – depends on alert rules; used for triage and reporting |
| MITRE | Often mapped in Category/Description fields; multi-technique |
| KQL Starter | ```kql\nAlertInfo\n| where StartTime >= ago(7d)\n| summarize Count = count() by ServiceSource, Category, Severity\n| order by Count desc\n``` |

---

## 2. AlertEvidence

| Field | Value |
|-------|-------|
| Purpose | Detailed entities attached to each alert (devices, users, files, IPs, URLs, processes) |
| Key Fields | AlertId, EntityType, DeviceId, DeviceName, AccountName, FileName, Sha1, RemoteUrl, IPAddress |
| Typical Attack Coverage | Surfaces all IoCs and entities per alert for pivoting into Device* and other tables |
| MITRE | Inherited from upstream alert logic |
| KQL Starter | ```kql\nlet targetAlertId = \"<ALERT_ID>\";\nAlertEvidence\n| where AlertId == targetAlertId\n| project AlertId, EntityType, DeviceName, AccountName, FileName, Sha1, RemoteUrl, IPAddress\n``` |
