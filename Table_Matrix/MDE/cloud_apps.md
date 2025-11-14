# ☁️ MDE Cloud Apps / Shadow IT Tables (If Available)

---

## 1. CloudAppEvents

| Field | Value |
|-------|-------|
| Purpose | Events from Defender for Cloud Apps (MCAS) – cloud app usage, policy matches, anomalies |
| Key Fields | Timestamp, UserAgent, SourceIPAddress, AccountObjectId, AppName, ActivityType, PolicyName, Severity |
| Typical Attack Coverage | Shadow IT, unsanctioned app usage, risky cloud app behaviour, exfiltration to unsanctioned services |
| MITRE | T1530 (Data from Cloud Storage), T1041, T1133 (External Services) |
| Common Pivots | AccountObjectId → SigninLogs; SourceIPAddress → DeviceNetworkEvents; AppName → sanctioned/unsanctioned app lists |
| KQL Starter | ```kql\nCloudAppEvents\n| where Timestamp >= ago(7d)\n| summarize Count = count() by AppName, ActivityType\n| order by Count desc\n``` |
