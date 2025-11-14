# 🧪 KQL Examples

These are generic starter queries you can adapt into hunts or detections.

---

## 1. Suspicious PowerShell with Encoded or Download Behaviour

```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any ("-enc", "FromBase64String", "IEX", "DownloadString", "Invoke-WebRequest")
| project Timestamp, DeviceName, AccountName, ParentProcessName, FileName, ProcessCommandLine
