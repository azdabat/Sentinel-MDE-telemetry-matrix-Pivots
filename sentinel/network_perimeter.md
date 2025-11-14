# 🌐 Sentinel Network & Perimeter Telemetry

---

## 1. CommonSecurityLog

| Field | Value |
|-------|-------|
| Purpose | CEF-formatted logs from firewalls, VPN, proxies, WAF, IDS/IPS and other security devices |
| Source | CEF over Syslog / AMA |
| Key Fields | TimeGenerated, DeviceVendor, DeviceProduct, SourceIP, DestinationIP, SourcePort, DestinationPort, Protocol, RequestURL, DeviceAction, Message |
| Typical Attack Coverage | Perimeter scanning, inbound exploit attempts (web attacks, brute force), outbound C2 / exfiltration, VPN logins, WAF blocks |
| MITRE | T1190 (Exploit Public-Facing Application), T1041 (Exfiltration over C2), T1133 (External Remote Services) |
| Common Pivots | SourceIP → host or client; DestinationIP → C2/external services; RequestURL → URL + TI; DeviceAction → allowed/blocked context |
| KQL Starter – Rare Outbound Destinations | ```kql\nCommonSecurityLog\n| where TimeGenerated >= ago(1d)\n| where DeviceAction == \"Allow\"\n| summarize Count = count() by DestinationIP\n| where Count < 10\n| order by Count asc\n``` |

---

## 2. AzureFirewall (AzureDiagnostics subset)

| Field | Value |
|-------|-------|
| Purpose | Azure Firewall application and network rules logging |
| Source | AzureFirewall log categories via AzureDiagnostics |
| Key Fields | TimeGenerated, SourceIp, DestinationIp, DestinationPort, Protocol, Action, RuleName, Fqdn, ThreatIntel |
| Typical Attack Coverage | Outbound C2 and exfil, blocked/allowed suspicious domains/IPs, lateral movement between VNets, scanning attempts |
| MITRE | T1041, T1105, T1046 |
| Common Pivots | SourceIp → VM / host mapping; DestinationIp/Fqdn → TI; RuleName → policy context |
| KQL Starter | ```kql\nAzureDiagnostics\n| where Category == \"AzureFirewallNetworkRule\"\n| project TimeGenerated, SourceIp, DestinationIp, DestinationPort, Action, RuleName\n``` |

---

## 3. WAF / Application Gateway

| Field | Value |
|-------|-------|
| Purpose | Web Application Firewall (WAF) logs (requests, blocking decisions) |
| Source | Application Gateway / WAF logs via AzureDiagnostics or CEF |
| Key Fields | TimeGenerated, ClientIP_s, RequestUri_s, HttpStatus_d, Action_s, RuleSetType_s, RuleName_s |
| Typical Attack Coverage | OWASP-style web attacks (SQLi, XSS, path traversal), bot activity, scanners, brute-force on web login forms |
| MITRE | T1190 (Exploit Public-Facing Application) |
| Common Pivots | ClientIP_s → SigninLogs and CommonSecurityLog; RequestUri_s → app-specific detection; Action_s → blocked vs allowed |
| KQL Starter | ```kql\nAzureDiagnostics\n| where Category == \"ApplicationGatewayFirewallLog\"\n| project TimeGenerated, ClientIP_s, RequestUri_s, Action_s, RuleName_s\n``` |
