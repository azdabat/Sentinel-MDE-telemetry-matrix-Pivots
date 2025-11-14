# 🧪 Sentinel Specialty & Niche Tables

These vary heavily per environment. A few common ones:

---

## 1. SecurityAlert

| Field | Value |
|-------|-------|
| Purpose | Alerts raised by security solutions integrated with Sentinel |
| Key Fields | TimeGenerated, AlertName, AlertSeverity, AlertType, CompromisedEntity, VendorName, ProductName |
| Typical Attack Coverage | Aggregate view of all integrated security products (AV, EDR, firewall, CASB, DLP, etc.) |
| MITRE | Depends on upstream product; often multi-technique |
| Common Pivots | CompromisedEntity → Device* tables, SigninLogs; AlertType → deeper investigation in product-specific logs |
| KQL Starter | ```kql\nSecurityAlert\n| where TimeGenerated >= ago(7d)\n| summarize Count = count() by VendorName, ProductName, AlertSeverity\n``` |

---

## 2. SecurityIncident

| Field | Value |
|-------|-------|
| Purpose | Sentinel incidents (grouping alerts) |
| Key Fields | TimeGenerated, IncidentNumber, Title, Severity, Status, Owner, Classification, Tactics, Techniques |
| Typical Attack Coverage | Incident-level view across multiple alerts and entities |
| MITRE | Tactics/Techniques field often contain ATT&CK mapping |
| Common Pivots | IncidentNumber → linked alerts and entities; Tactics → MITRE-based reporting |
| KQL Starter | ```kql\nSecurityIncident\n| summarize Count = count() by Severity, Status\n``` |

---

## 3. KeyVaultDataPlane

| Field | Value |
|-------|-------|
| Purpose | Operations against Azure Key Vault (secret/key reads, deletes, backups, etc.) |
| Key Fields | TimeGenerated, ResourceId, OperationName, ResultType, CallerIPAddress, Identity |
| Typical Attack Coverage | Secret theft, key exfiltration, destructive operations (purge) |
| MITRE | T1555 (Credentials from Password Stores), T1530 (Data from Cloud Storage) |
| Common Pivots | ResourceId → AzureActivity; CallerIPAddress → SigninLogs; Identity → AuditLogs (for role/config changes) |
| KQL Starter | ```kql\nKeyVaultDataPlane\n| where TimeGenerated >= ago(7d)\n| where OperationName has_any (\"SecretGet\",\"KeyGet\",\"CertificateGet\")\n``` |
