# LOLBin KQL Examples

These examples assume **Defender for Endpoint** data via:

- `DeviceProcessEvents`
- `DeviceNetworkEvents`
- `DeviceFileEvents`
- `DeviceRegistryEvents`
- and Sentinel equivalents.

---

## 1. Abnormal PowerShell Parents

```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName =~ "powershell.exe"
| extend Parent = tostring(ParentProcessName)
| where Parent !in~ ("explorer.exe","services.exe","cmd.exe","powershell.exe")
| project Timestamp, DeviceName, AccountName, ParentProcessName, FileName, ProcessCommandLine

2. Office → LOLBin (Word launching PowerShell, WScript, CMD, MSHTA)
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName in~ ("powershell.exe","wscript.exe","cscript.exe","cmd.exe","mshta.exe")
| where ParentProcessName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| project Timestamp, DeviceName, AccountName, ParentProcessName, FileName, ProcessCommandLine

3. MSHTA from Browser or Office (HTML Smuggling)
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName =~ "mshta.exe"
| where ParentProcessName in~ ("chrome.exe","msedge.exe","firefox.exe","winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| project Timestamp, DeviceName, AccountName, ParentProcessName, FileName, ProcessCommandLine

4. Certutil Download / Decode Usage
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-urlcache","-split","-decode","http","https")
| project Timestamp, DeviceName, AccountName, ParentProcessName, FileName, ProcessCommandLine

5. Schtasks from Odd Parents
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName =~ "schtasks.exe"
| where ParentProcessName in~ ("winword.exe","excel.exe","outlook.exe","wscript.exe","cscript.exe","mshta.exe")
| project Timestamp, DeviceName, AccountName, ParentProcessName, ProcessCommandLine

6. Service Creation via sc.exe (Non-Admin Tools)
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName =~ "sc.exe"
| where ProcessCommandLine has "create"
| where ParentProcessName !in~ ("services.exe","explorer.exe","cmd.exe")
| project Timestamp, DeviceName, AccountName, ParentProcessName, ProcessCommandLine


Use the LOLBin matrix to tune allowed parents per environment and convert these into analytics rules.
