# Advanced Suspicious Parent–Child Combinations
This matrix explains *why* combinations are suspicious, the **MITRE techniques**, **attacker intent**, **analyst pivots**, and **triage priorities**.

It is designed for SOC L2/L3, DFIR, and Threat Hunters.

---

| Child Process | Suspicious Parent | MITRE Techniques | Why Suspicious (Attacker Intent) | Severity | Key Analyst Pivots |
|---------------|------------------|------------------|----------------------------------|---------|--------------------|
| **powershell.exe** | winword.exe, excel.exe, outlook.exe, powerpnt.exe | T1566.001 (Phishing), T1059.001 (PowerShell), T1204 | Classic macro → PowerShell stager. Usually followed by download cradle or payload decode. | 🔥 High | Check ProcessCommandLine for `-enc`, `IEX`, `http`. Join with DeviceNetworkEvents. Look for PowerShell → rundll32 chain. |
| **powershell.exe** | wscript.exe, cscript.exe, mshta.exe | T1059.005, T1218.005, T1059.001 | Script-host → PowerShell indicates multi-stage loader. Used heavily by Emotet, QakBot, Bumblebee, Cobalt Strike loaders. | 🔥 High | Extract parent script, look for base64 obfuscation. Pivot into file writes in `%AppData%` or `%Temp%`. |
| **powershell.exe** | chrome.exe, msedge.exe, firefox.exe, iexplore.exe | T1204, T1218.005, T1059.001 | HTML smuggling or browser exploit handing execution to PowerShell. Often in malicious `.hta`, `.html`, JS smuggling attacks. | 🔥 High | Look at RemoteUrl. Join with OfficeActivity for initial vector. |
| **cmd.exe** | winword.exe, excel.exe, outlook.exe | T1566.001, T1059.003 | Macro abuse: first stage shell to run batch files or LOLBins. Very common QakBot/Dridex pattern. | 🔥 High | Inspect dropped files. Check for `cmd /c powershell`, auto-pivot to child process. |
| **cmd.exe** | wscript.exe, cscript.exe, mshta.exe | T1059.003, T1059.005 | Script → cmd chaining is part of a staged loader. Attackers use this to obfuscate process tree. | ⚠️ Medium–High | Look at task scheduler commands, registry edits, or payload unpacking. |
| **mshta.exe** | browsers, winword.exe, outlook.exe | T1218.005, T1204 | HTML smuggling, malicious remote HTA, JS/VBS stager. Heavily used in spearphishing + drive-by. | 🔥 High | Extract the URL from command line. Join with TI indicators. |
| **wscript.exe** | office apps, browser, unknown binaries in AppData/Temp | T1059.005, T1204 | Phishing attachment launches script → payload. Common in downloader families. | 🔥 High | Extract `.vbs`, `.js`, `.jse`, `.vbe` bodies. Decode obfuscated JS. |
| **rundll32.exe** | office apps, browsers, temp executables | T1218.011, T1055 | Malicious DLL execution or shellcode runner. APTs and loaders love this. | 🔥 High | Parse export method in the command line. Pivot into DeviceFileEvents for DLL. |
| **regsvr32.exe** | script hosts, temp files | T1218.010, T1547 | Rogue DLL registration or “Squiblydoo” technique. Used for remote COM execution. | 🔥 High | Check registry writes, COM objects, presence of `.sct` files. |
| **reg.exe** | office apps, script hosts | T1112, T1547 | Malware modifying Run keys, disabling AV, tampering authentication. | ⚠️ Medium–High | Pivot into registry values and compare before/after. Look for persistence. |
| **schtasks.exe** | office apps, scripts, temp binaries | T1053.005 | Malware setting persistence tasks post-infection. | 🔥 High | Check `/create` arguments. Look for dropped binaries in `%AppData%`. |
| **sc.exe** | office apps, wscript, unknown userland binaries | T1543.003, T1569.002 | Malicious service creation. Indicator of ransomware staging or lateral movement. | 🔥 Critical | Inspect service binPath. Check for network propagation signs. |
| **certutil.exe** | powershell, cmd, script hosts | T1105, T1140, T1041 | Download cradle or base64 decode of payloads. Malware uses this LOLOLOL. | ⚠️ Medium–High | Look for `.b64`, `.txt`, `.dat` → `.exe` chains. Check DeviceFileEvents. |
| **bitsadmin.exe** | powershell, cmd, scripts | T1105, T1071.001 | Stealthy downloader. Used by APT32, APT29, FIN groups. | ⚠️ Medium | Pivot to network connections, inspect remote URLs. |
| **msiexec.exe** | browsers, Office | T1218.007 | Malicious MSI installation. Used in drive-by or phishing deployments. | 🔥 High | Dump MSI, check embedded DLLs. |
| **installutil.exe** | scripts, unknown binaries | T1218.004 | Executes .NET payloads using signed Microsoft InstallUtil. | 🔥 High | Extract .NET assembly, inspect installer class. |
| **wmic.exe** | office, browser, script hosts | T1047 | Recon or remote execution triggered by phishing payload. | ⚠️ Medium | Review executed WMI query (process creation, remote host). |
| **dllhost.exe** | script hosts, unknown EXEs | T1055, T1547.009 | COM surrogates abused for in-memory shellcode. | 🔥 High | Trace parent, inspect memory usage and anomalous modules. |
| **psexec.exe** | unknown userland executables | T1021.002, T1569.002 | Lateral movement attempt from compromised station. Classic ransomware spread. | 🔥 Critical | Check ADMIN$ writes, service creation patterns, share access. |

