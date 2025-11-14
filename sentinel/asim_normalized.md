#  Sentinel ASIM Normalized Tables

ASIM (Advanced Security Information Model) normalizes data from many products into consistent schemas.

---

## 1. ASimNetworkSession

| Field | Value |
|-------|-------|
| Purpose | Normalized network session/tcp/udp logs from various sources |
| Key Fields | TimeGenerated, SrcIpAddr, DstIpAddr, SrcPortNumber, DstPortNumber, NetworkProtocol, Dvc, DvcAction |
| Typical Attack Coverage | General C2 analysis, scanning, lateral movement, exfil, port abuse |
| MITRE | T1041, T1046, T1105 |
| Common Pivots | SrcIpAddr / DstIpAddr → DeviceNetworkEvents, CommonSecurityLog; Dvc → vendor device details |
| KQL Starter | ```kql\nASimNetworkSession\n| where TimeGenerated >= ago(1d)\n| summarize Count = count() by SrcIpAddr, DstIpAddr, DstPortNumber\n| order by Count desc\n``` |

---

## 2. ASimDnsActivity

| Field | Value |
|-------|-------|
| Purpose | Normalized DNS query logs from multiple systems/providers |
| Key Fields | TimeGenerated, SrcIpAddr, QueryName, QueryType, ResponseCode, Dvc |
| Typical Attack Coverage | DNS-based C2 (DGA domains, beaconing), data exfil via DNS, suspicious domain usage |
| MITRE | T1071.004 (DNS), T1568 (DGA) |
| Common Pivots | QueryName → TI; SrcIpAddr → DeviceNetworkEvents / DeviceInfo |
| KQL Starter | ```kql\nASimDnsActivity\n| where TimeGenerated >= ago(1d)\n| summarize Queries = count() by QueryName\n| where Queries > 500\n| order by Queries desc\n``` |

---

## 3. ASimWebSession

| Field | Value |
|-------|-------|
| Purpose | Normalized HTTP/Web proxy sessions |
| Key Fields | TimeGenerated, SrcIpAddr, DstIpAddr, Url, HttpStatusCode, HttpMethod, DvcAction |
| Typical Attack Coverage | HTTP-based C2, data exfil via web, suspicious uploads/downloads |
| MITRE | T1071.001 (Web Protocols), T1041 |
| Common Pivots | Url → TI; SrcIpAddr → DeviceNetworkEvents; Dvc → proxy device |
| KQL Starter | ```kql\nASimWebSession\n| where TimeGenerated >= ago(1d)\n| where Url has_any (\".onion\",\"pastebin\",\"mega.nz\")\n``` |

---

## 4. ASimProcessEvent

| Field | Value |
|-------|-------|
| Purpose | Normalized process activity from endpoints |
| Key Fields | TimeGenerated, Dvc, TargetProcessName, TargetProcessCommandLine, ActorProcessName, ActorUsername |
| Typical Attack Coverage | Process LOLBin abuse, malware execution, parent-child relationships |
| MITRE | T1059, T1218 |
| Common Pivots | TargetProcessName → specific binary; ActorUsername → identity tables |
| KQL Starter | ```kql\nASimProcessEvent\n| where TimeGenerated >= ago(7d)\n| where TargetProcessName =~ \"powershell.exe\"\n``` |
