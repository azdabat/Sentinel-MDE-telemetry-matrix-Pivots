# ⚠️ Suspicious Parent–Child Combinations

Combinations that are not always malicious, but **highly suspicious** and worth triage.

---

| Child Process | Suspicious Parent Process | Why Suspicious |
|---------------|--------------------------|----------------|
| powershell.exe | winword.exe, excel.exe, powerpnt.exe, outlook.exe | Macro malware, phishing payload execution |
| powershell.exe | wscript.exe, cscript.exe, mshta.exe | Multi-stage script/lolbin chaining, obfuscation |
| powershell.exe | browser processes (chrome.exe, msedge.exe, iexplore.exe, firefox.exe) | Exploit or HTML smuggling handing straight to PowerShell |
| cmd.exe | winword.exe, excel.exe, outlook.exe | Macro-driven shell for running scripts and payloads |
| cmd.exe | wscript.exe, cscript.exe, mshta.exe | Script/lolbin pivot into raw shell |
| mshta.exe | office apps, browsers, outlook.exe | HTML smuggling, remote HTA payloads |
| wscript.exe | office apps, browsers, unknown temp executables | Script-based malware, droppers |
| rundll32.exe | office apps, browsers, unknown temp executables | Abusing rundll32 as LOLBin for shellcode/DLL |
| regsvr32.exe | script hosts, unknown temp executables | Rogue DLL registration, COM hijack |
| reg.exe | office apps, script hosts | Registry tampering driven by phishing payloads |
| schtasks.exe | office apps, script hosts | Persistence from user-delivered malware |
| sc.exe | office apps, script hosts, unknown executables | Service-based persistence from non-admin tooling |
| certutil.exe | powershell.exe, cmd.exe, script hosts | Chained download/encode usage |
| bitsadmin.exe | powershell.exe, cmd.exe, script hosts | Hidden downloader for payloads |
| msiexec.exe | browser or office as parent | Drive-by or phishing triggered MSI |
| installutil.exe | script hosts, unknown binaries | .NET payload delivery beyond dev/build servers |
| wmic.exe | office apps, browsers, script hosts | Recon/lateral movement triggered by phishing payload |
| dllhost.exe | script hosts, unknown user path executables | COM hijack shellcode or payload host |
| psexec.exe | unknown user binary from temp path | Lateral malware spread instead of legit admin use |
