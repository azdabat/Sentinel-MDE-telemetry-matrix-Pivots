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


---

## 📄 `matrices/process_baselines/parent_child_matrix.md`

```markdown
# 🧬 Parent–Child Baseline Matrix (Normal Behaviour)

This matrix describes **what SHOULD launch what** in a typical Windows environment.

---

| Child Process | Allowed / Typical Parents | Notes |
|---------------|---------------------------|-------|
| powershell.exe | explorer.exe, powershell.exe, services.exe, svchost.exe (management tools), system management suites | Admin tasks, scripts, configuration management |
| cmd.exe | explorer.exe, services.exe, taskmgr.exe, legitimate management tools | Shell usage, troubleshooting, scripts |
| wscript.exe | explorer.exe, scheduled tasks, admin script runners | Logon scripts, admin automations |
| cscript.exe | explorer.exe, scheduled tasks, admin script runners | Scripted admin tasks, GPO scripts |
| mshta.exe | explorer.exe, control.exe, trusted installer processes | MSI/HTA-based installers, legacy management scripts |
| rundll32.exe | explorer.exe, services.exe, svchost.exe, trusted application processes | Control panel applets, DLL-based components |
| regsvr32.exe | explorer.exe, msiexec.exe, trusted setup executables | DLL registration during install/updates |
| reg.exe | explorer.exe, services.exe, trusted admin tools | Registry export/import, config changes |
| schtasks.exe | explorer.exe, services.exe, trusted admin shells | Scheduled maintenance, backups, inventory tasks |
| sc.exe | services.exe, explorer.exe, trusted admin shells | Service management, driver operations |
| certutil.exe | explorer.exe, mmc.exe, certsrv tools | Certificate management, PKI operations |
| bitsadmin.exe | explorer.exe, system management tools | Legacy admin download jobs, rarely used legitimately now |
| msiexec.exe | explorer.exe, system installers, software deployment platforms | MSI installs and upgrades |
| installutil.exe | msiexec.exe, developer tools, build servers | Installing .NET custom installers, dev builds |
| regedit.exe | explorer.exe, mmc.exe | Manual registry editing by admins |
| msbuild.exe | devenv.exe, Visual Studio tools, build agents | Building .NET / C# projects |
| wmic.exe | explorer.exe, admin shells, system management tools | Remote management, inventory, queries |
| psexec.exe | admin shells on jump boxes, management scripts | Remote administration in tightly controlled contexts |
| rdpclip.exe | rdpinit.exe, rdp session processes | Clipboard integration for RDP sessions |
| dllhost.exe | explorer.exe, system processes, COM subsystem | Normal COM object hosting for Windows components |

