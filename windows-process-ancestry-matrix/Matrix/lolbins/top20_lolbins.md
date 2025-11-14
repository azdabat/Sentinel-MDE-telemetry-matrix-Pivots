# Top 20 Windows LOLBins – Ancestry Matrix

These are the **20 most commonly abused Windows LOLBins** with their:

- Typical legitimate parents
- Suspicious parents
- Clearly malicious patterns
- Attack roles

---

| LOLBin | Typical Legitimate Parents | Suspicious Parents | Clearly Malicious Parents | Common Malicious Uses |
|--------|----------------------------|--------------------|---------------------------|------------------------|
| powershell.exe | explorer.exe, svchost.exe (management tools), powershell.exe (self) | winword.exe, excel.exe, outlook.exe, wscript.exe | office app spawning multiple instances, unknown exe from temp, script interpreter spawning it | Download and execute payloads, obfuscated scripts, C2, recon, lateral movement |
| cmd.exe | explorer.exe, services.exe, taskmgr.exe | winword.exe, excel.exe, outlook.exe, browser processes | wscript.exe, mshta.exe, rundll32.exe, regsvr32.exe | Shell for malware, script dropper, running encoded or staged commands |
| wscript.exe | explorer.exe, admin tools, legitimate scripts | office apps, browsers, outlook.exe | mshta.exe, powershell.exe, cmd.exe as parent, unknown temp exe | VBS/JScript droppers, fileless malware, C2 stagers |
| cscript.exe | explorer.exe, scheduled tasks, admin tools | office apps, remote shells | wscript.exe, mshta.exe, unknown exe from user temp | Script-based persistence, recon, living-off-the-land tooling |
| mshta.exe | explorer.exe, control.exe, legitimate installers | office apps, browsers, outlook.exe, wscript.exe | mshta.exe child of mshta.exe, powershell.exe or cmd.exe as parent | HTML smuggling, inline script execution, downloading and running payloads |
| rundll32.exe | explorer.exe, services.exe, svchost.exe, legitimate installers | browsers, office apps, script hosts | rundll32.exe executing from unusual path, unknown exe in user dir spawning rundll32.exe | DLL sideloading, executing arbitrary exports, LOLBin C2 stagers |
| regsvr32.exe | explorer.exe, msiexec.exe, legitimate installers | script hosts, unknown temp exe | regsvr32.exe registering DLLs from user-writeable paths or web shares | DLL registration and COM hijack, LOLBin execution via /s and remote locations |
| reg.exe | explorer.exe, services.exe, admin tools | office apps, script hosts | unknown exe in user cache, rundll32.exe, wscript.exe | Registry-based persistence and tampering, disabling security features |
| schtasks.exe | explorer.exe, services.exe, management tools | office apps, script hosts | unknown exe in temp, powershell.exe, cmd.exe | Scheduled task persistence, repeated execution of malware or scripts |
| sc.exe | services.exe, explorer.exe, management consoles | cmd.exe from unknown parent, script hosts | unknown temp exe, powershell.exe, mshta.exe | Service creation for persistence, running malicious services, driver abuse |
| certutil.exe | explorer.exe, admin tools, mmc.exe | script hosts, powershell.exe, cmd.exe | office apps, browser processes, unknown exe | Downloading payloads, base64 decode, data exfil encoding |
| bitsadmin.exe | explorer.exe, admin tools | script hosts, office apps | unknown temp exe, powershell.exe, cmd.exe | Background downloads of payloads, staging malware silently |
| msiexec.exe | explorer.exe, installers, management tools | script hosts, browsers | unknown exe, powershell.exe | Installing malicious MSI packages, side-loading DLLs |
| installutil.exe | msiexec.exe, admin tools | script hosts | unknown exe launching with suspicious parameters | .NET assembly execution, fileless payloads via custom installers |
| regedit.exe | explorer.exe, admin consoles | script hosts | unknown exe, office apps | Manual or semi-automated registry tampering for persistence or disabling security |
| msbuild.exe | devenv.exe, visual studio tooling | script hosts, office apps | unknown exe or browser processes | XAML inline tasks for executing C# payloads, LOLBin code runner |
| wmic.exe | explorer.exe, admin tools, svchost.exe | office apps, script hosts | unknown temp exe, rundll32.exe | Remote command exec, recon, lateral movement via WMI |
| psexesvc.exe (PsExec) | services.exe | almost any other process spawning psexec.exe | psexec.exe launched by script hosts or unknown exe | Lateral movement via SMB and service creation |
| rdpclip.exe | rdpinit.exe (RDP session) | very rare from others | abnormal parents | Clipboard abuse and data staging over RDP (context only, not usually a hunting table key) |
| dllhost.exe | explorer.exe, system processes | office apps, browsers | unknown temp exe, script hosts | COM object hijack abuse, shellcode hosting via DLL surrogates |

Use this matrix to design “who should launch what” rules per LOLBin.

