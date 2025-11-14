# ☁️ Sentinel Cloud / SaaS Telemetry

---

## 1. OfficeActivity

| Field | Value |
|-------|-------|
| Purpose | Unified Microsoft 365 audit logs (Exchange, SharePoint, OneDrive, Teams, etc.) |
| Source | Microsoft 365 (M365) unified audit pipeline |
| Key Fields | TimeGenerated, RecordType, OfficeWorkload, Operation, UserId, ObjectId (mailbox/file/site), Parameters |
| Typical Attack Coverage | BEC and mailbox rule abuse (Exchange), mass file downloads or sync (SharePoint/OneDrive), mailbox exports, suspicious sharing, Teams data abuse |
| MITRE | T1114 (Email Collection), T1530 (Data from Cloud Storage), T1112 (for mailbox rules via server-side changes) |
| Common Pivots | UserId → SigninLogs and DeviceLogonEvents; ObjectId → mailbox or site; external destinations in Parameters → exfil destinations |
| KQL Starter – Malicious Inbox Rules | ```kql\nOfficeActivity\n| where TimeGenerated >= ago(7d)\n| where OfficeWorkload == \"Exchange\" and Operation in (\"New-InboxRule\",\"Set-InboxRule\")\n| project TimeGenerated, UserId, Operation, ObjectId, Parameters\n``` |

---

## 2. AzureActivity

| Field | Value |
|-------|-------|
| Purpose | Azure control-plane events (resource create/update/delete, role assignments, policy changes) |
| Source | Azure Monitor / Azure Activity connector |
| Key Fields | TimeGenerated, OperationName, Caller, ResourceId, Category, Status, SubscriptionId |
| Typical Attack Coverage | Rogue VM creation, NSG / firewall rule changes, role assignment escalations, Key Vault and Storage configuration changes |
| MITRE | T1098 (Account Manipulation), T1548 (Abuse Elevation Control Mechanism), T1529 (System Shutdown/Restart) when destructive operations occur |
| Common Pivots | Caller → SigninLogs; ResourceId → service-specific logs (e.g. KeyVaultDataPlane, SQLSecurityAudit); SubscriptionId → environment separation |
| KQL Starter – Role Assignment Ops | ```kql\nAzureActivity\n| where TimeGenerated >= ago(7d)\n| where Category == \"Administrative\" and OperationName has \"role assignment\"\n| project TimeGenerated, Caller, OperationName, ResourceId, Status\n| order by TimeGenerated desc\n``` |

---

## 3. AzureDiagnostics (Service-Specific)

| Field | Value |
|-------|-------|
| Purpose | Diagnostic logs from specific services (Key Vault, Storage, SQL DB, AKS, App Service, etc.) |
| Source | AzureDiagnostics (multi-service schema) |
| Key Fields | TimeGenerated, ResourceId, Category, OperationName, ResultType, CallerIpAddress, identity fields depending on service |
| Typical Attack Coverage | Key Vault secret access or purge, SQL admin logins and failed logins, Storage access anomalies, AKS control-plane events |
| MITRE | Depends on service; often T1530 (Data from Cloud Storage), T1555 (Credentials from Password Stores), T1078 (Valid Accounts) |
| Common Pivots | ResourceId → AzureActivity; CallerIpAddress / identity → SigninLogs; OperationName / Category → service-specific detection |
| KQL Starter – Key Vault Access Example | ```kql\nAzureDiagnostics\n| where TimeGenerated >= ago(7d)\n| where ResourceId has \"Microsoft.KeyVault/vaults\"\n| project TimeGenerated, ResourceId, OperationName, ResultType, CallerIpAddress\n``` |
