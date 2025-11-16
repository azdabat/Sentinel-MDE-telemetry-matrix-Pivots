# 🧪 KQL Examples

These are generic starter queries you can adapt into hunts or detections.

### 📚 Additional Materials  
**Complete rule sets are available here:**  
👉 https://github.com/azdabat/Threat-Hunting-Rules
---

## 1. Suspicious PowerShell with Encoded or Download Behaviour

```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any ("-enc", "FromBase64String", "IEX", "DownloadString", "Invoke-WebRequest")
| project Timestamp, DeviceName, AccountName, ParentProcessName, FileName, ProcessCommandLine#

2. RDP Brute Force / High Volume RDP Logons
DeviceLogonEvents
| where Timestamp >= ago(1d)
| where LogonType == 10
| summarize Attempts = count() by AccountName, RemoteIP, DeviceName
| where Attempts > 20
| order by Attempts desc

3. Kerberoasting Pattern (on DCs)
SecurityEvent
| where TimeGenerated >= ago(7d)
| where EventID == 4769
| where ServiceName !has "$"
| summarize TicketReqs = count() by IpAddress, Account, ServiceName
| where TicketReqs > 20
| order by TicketReqs desc

4. MFA Fatigue / Push Bombing (Entra ID)
SigninLogs
| where TimeGenerated >= ago(1d)
| where AuthenticationRequirement == "multiFactorAuthentication"
| summarize Attempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 10m)
| where Attempts > 10
| order by Attempts desc

5. OAuth Consent Abuse
AuditLogs
| where TimeGenerated >= ago(30d)
| where OperationName in (
    "Consent to application",
    "Add delegated permission grant",
    "Add app role assignment grant",
    "Add service principal credentials"
)
| extend Initiator = tostring(InitiatedBy.user.userPrincipalName),
         AppName = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, Initiator, AppName, Result
| order by TimeGenerated desc

6. Malicious Inbox Rules (BEC)
OfficeActivity
| where TimeGenerated >= ago(7d)
| where OfficeWorkload == "Exchange"
| where Operation in ("New-InboxRule","Set-InboxRule")
| where Parameters has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
| project TimeGenerated, UserId, Operation, ObjectId, Parameters

7. Potential Ransomware Behaviour (Mass File Encryption)
DeviceFileEvents
| where Timestamp >= ago(1d)
| where ActionType in ("FileModified","FileRenamed")
| summarize FileOps = count(), DistinctExt = dcount(tostring(split(FileName, ".")[-1])) by DeviceName, bin(Timestamp, 5m)
| where FileOps > 1000 and DistinctExt > 20
| order by FileOps desc

8. Suspicious Webshell-Like Behaviour (IIS / Web Server)
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where ParentProcessName in~ ("w3wp.exe","tomcat.exe","java.exe")
| where FileName in~ ("cmd.exe","powershell.exe","bash")
| project Timestamp, DeviceName, ParentProcessName, FileName, ProcessCommandLine, AccountName
| order by Timestamp desc

SEE: THREATH-HUNTING Section for ready to use complete rules.
