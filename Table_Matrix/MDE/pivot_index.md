# 🔍 Pivot Index – “Which Table Do I Use for X?”

This is the **quick lookup sheet** for analysts.

| Question / Goal | Primary Tables | Follow-Up Pivots |
|-----------------|----------------|------------------|
| What process ran this binary and from where? | DeviceProcessEvents | DeviceFileEvents, DeviceNetworkEvents, DeviceRegistryEvents |
| Did this process talk to the internet or internal hosts? | DeviceNetworkEvents | ThreatIntelligenceIndicator, CommonSecurityLog, ASimNetworkSession |
| Did this binary get dropped anywhere else? | DeviceFileEvents | DeviceProcessEvents (for the dropping process), DeviceInfo (to list affected devices) |
| Is there persistence on this host? | DeviceRegistryEvents, DeviceFileEvents (autoruns), SecurityEvent (7045) | DeviceProcessEvents (processes linked to persistence) |
| Who logged into this host? | DeviceLogonEvents, SecurityEvent (4624/4625) | SigninLogs (cloud), IdentityInfo |
| Are there abnormal RDP patterns? | DeviceLogonEvents (LogonType 10), SecurityEvent (4624/4625) | DeviceNetworkEvents (port 3389) |
| Account X – where is it authenticating? | SigninLogs, DeviceLogonEvents, SecurityEvent | DeviceProcessEvents (post-logon execution) |
| Which cloud apps did this user access? | SigninLogs (AppDisplayName), CloudAppEvents | OfficeActivity (if M365), AzureActivity |
| Are there suspicious mailbox rules? | OfficeActivity | SigninLogs (who/where), EmailEvents |
| Is data being exfiltrated to cloud storage? | OfficeActivity (SharePoint/OneDrive), CloudAppEvents, DeviceNetworkEvents | ASimWebSession, CommonSecurityLog |
| Have any dangerous Azure role changes occurred? | AzureActivity, AuditLogs | SigninLogs (caller), KeyVaultDataPlane, AzureDiagnostics |
| Are we hitting known bad IPs/domains/hashes? | ThreatIntelligenceIndicator joined with DeviceNetworkEvents, CommonSecurityLog, DeviceFileEvents, DeviceProcessEvents | SecurityAlert / SecurityIncident |
| Which devices see the most AV detections? | DeviceEvents (Antivirus), SecurityAlert | DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents |

Use this as your **first-stop “where do I look?”** guide during triage and hunting.
