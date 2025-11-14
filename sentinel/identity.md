# 👤 Sentinel Identity & Authentication Tables

---

## 1. SigninLogs

| Field | Value |
|-------|-------|
| Purpose | Azure AD / Entra ID sign-in events (interactive sign-ins to apps and portals) |
| Source | Azure AD / Entra ID Sign-in connector |
| Key Fields | TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, AppDisplayName, ClientAppUsed, AuthenticationRequirement, ConditionalAccessStatus, RiskDetail |
| Typical Attack Coverage | Password spray, account takeover, MFA fatigue, impossible travel, legacy protocol abuse |
| MITRE | T1110 (Brute Force), T1078 (Valid Accounts), T1556.006 (MFA), T1098 (Account Manipulation, indirectly through patterns) |
| Common Pivots | UserPrincipalName → AuditLogs, OfficeActivity, DeviceLogonEvents; IPAddress → DeviceNetworkEvents/CommonSecurityLog; AppDisplayName → app inventory/safe list |
| KQL Starter – Password Spray | ```kql\nSigninLogs\n| where TimeGenerated >= ago(1d)\n| where ResultType != 0\n| summarize Failures = count() by IPAddress, UserPrincipalName\n| where Failures > 15\n| order by Failures desc\n``` |

---

## 2. AADNonInteractiveUserSignInLogs

| Field | Value |
|-------|-------|
| Purpose | Non-interactive sign-ins (background / service access) for users |
| Source | Azure AD |
| Key Fields | UserPrincipalName, IPAddress, AppDisplayName, ResultType, ClientAppUsed |
| Typical Attack Coverage | Abuse of refresh tokens, service tokens, non-interactive login patterns with stolen tokens |
| MITRE | T1550.001 (Use of Stolen Tokens), T1078 |
| Common Pivots | UserPrincipalName → SigninLogs + AuditLogs; AppDisplayName → OAuth app analysis |
| KQL Starter | ```kql\nAADNonInteractiveUserSignInLogs\n| where TimeGenerated >= ago(7d)\n| where ResultType == 0\n| summarize SuccessCount = count() by UserPrincipalName, AppDisplayName, IPAddress\n``` |

---

## 3. AADServicePrincipalSignInLogs

| Field | Value |
|-------|-------|
| Purpose | Sign-ins by service principals (applications) |
| Source | Azure AD |
| Key Fields | ServicePrincipalName, ServicePrincipalId, IPAddress, AppDisplayName, ResourceDisplayName, ResultType |
| Typical Attack Coverage | Compromised service principal abuse, over-privileged app activity, backdoor access via app credentials |
| MITRE | T1098.001 (Additional Cloud Credentials), T1550.001 |
| Common Pivots | ServicePrincipalId → AuditLogs (creation, credential updates); IPAddress → CommonSecurityLog; ResourceDisplayName → specific APIs used |
| KQL Starter | ```kql\nAADServicePrincipalSignInLogs\n| where TimeGenerated >= ago(7d)\n| where ResultType == 0\n| summarize SuccessCount = count() by ServicePrincipalName, AppDisplayName, IPAddress\n``` |

---

## 4. AADManagedIdentitySignInLogs

| Field | Value |
|-------|-------|
| Purpose | Managed identity sign-ins (used by Azure resources) |
| Source | Azure AD |
| Key Fields | ManagedIdentityResourceId, IPAddress, ResultType, AppDisplayName, ResourceId |
| Typical Attack Coverage | Abuse of managed identities (e.g. lateral cloud movement), misconfigured identities |
| MITRE | T1078 (Valid Accounts), T1098 |
| Common Pivots | ManagedIdentityResourceId → AzureActivity; ResourceId → AzureDiagnostics for the resource |
| KQL Starter | ```kql\nAADManagedIdentitySignInLogs\n| where TimeGenerated >= ago(7d)\n| where ResultType != 0\n``` |

---

## 5. AuditLogs (Azure AD Audit)

| Field | Value |
|-------|-------|
| Purpose | Azure AD directory and application audit trail (config changes) |
| Source | Azure AD / Entra ID |
| Key Fields | TimeGenerated, OperationName, InitiatedBy, TargetResources, Category, Result |
| Typical Attack Coverage | OAuth consent abuse, service principal credential addition, app registration, group membership changes, privileged role assignments |
| MITRE | T1098 (Account Manipulation), T1098.001 (Additional Cloud Credentials), T1548 (Abuse Elevation Control Mechanism) |
| Common Pivots | InitiatedBy.user.userPrincipalName → SigninLogs; TargetResources[].displayName / id → app/svc principal details |
| KQL Starter – OAuth Consent Operations | ```kql\nAuditLogs\n| where TimeGenerated >= ago(30d)\n| where OperationName in (\n    \"Consent to application\",\n    \"Add delegated permission grant\",\n    \"Add app role assignment grant\",\n    \"Add service principal credentials\"\n)\n| extend Initiator = tostring(InitiatedBy.user.userPrincipalName), AppName = tostring(TargetResources[0].displayName)\n| project TimeGenerated, OperationName, Initiator, AppName, Result\n| order by TimeGenerated desc\n``` |

---

## 6. IdentityInfo / IdentityLogonEvents (if present)

| Field | Value |
|-------|-------|
| Purpose | UEBA and identity enrichment data for users (roles, groups, risk, baseline behaviour) |
| Source | Defender for Identity / UEBA integration |
| Key Fields | AccountName, UPN, Groups, RiskLevel, IsAdmin, LastSeen, Baseline stats |
| Typical Attack Coverage | Supporting data for anomaly detection, privileged user context |
| MITRE | Not direct; supports many techniques as context |
| Common Pivots | AccountName / UPN → SigninLogs, AuditLogs, DeviceLogonEvents, OfficeActivity |
| KQL Starter | ```kql\nIdentityInfo\n| summarize count() by IsAdmin, RiskLevel\n``` |
