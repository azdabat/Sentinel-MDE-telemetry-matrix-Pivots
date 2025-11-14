# 📊 Sentinel & MDE Telemetry Matrix  
### Comprehensive SOC Telemetry, Pivoting & Detection Reference

This repository is a **SOC telemetry bible** for: (Beginners-Intermediate) 

- **Microsoft Sentinel** (Log Analytics + connected data sources)
- **Microsoft Defender for Endpoint (MDE) / Defender XDR** hunting tables

It contains **GitHub-ready tables** with:

- Table purpose and source  
- Key investigative fields  
- Typical attack coverage  
- MITRE ATT&CK mapping (where applicable)  
- Pivot strategies (which tables to join / query next)  
- Starter KQL examples

Designed for:

- SOC Analysts (L1–L3)  
- Threat Hunters  
- Detection Engineers  
- Incident Responders  

---

## 📁 Repository Structure

| Path | Description |
|------|-------------|
| `matrices/sentinel/index.md` | Index of all Sentinel telemetry groups |
| `matrices/sentinel/endpoint.md` | Sentinel endpoint / host tables (Device* + SecurityEvent + Syslog, etc.) |
| `matrices/sentinel/identity.md` | Sentinel identity / auth tables (SigninLogs, AuditLogs, etc.) |
| `matrices/sentinel/cloud_saas.md` | M365 / SaaS telemetry in Sentinel |
| `matrices/sentinel/network_perimeter.md` | Firewalls, WAF, VPN, proxies, NVA logs |
| `matrices/sentinel/asim_normalized.md` | ASIM normalized tables (network, dns, process, web, etc.) |
| `matrices/sentinel/specialty.md` | Azure resource, Key Vault, Storage, SQL, IoT and niche logs |
| `matrices/mde/index.md` | Index of all MDE / Defender XDR tables |
| `matrices/mde/core_endpoint.md` | Core MDE endpoint tables (Device*, DeviceInfo, etc.) |
| `matrices/mde/alerts_incidents.md` | MDE / XDR alerts, evidence and incident entities |
| `matrices/mde/identity_email.md` | Defender for Identity and Defender for Office (email) tables |
| `matrices/mde/cloud_apps.md` | Defender for Cloud Apps / App governance tables (if available) |
| `matrices/mitre-mapping.md` | MITRE ATT&CK mapping for all major tables |
| `matrices/pivot_index.md` | “What table should I use for X?” quick pivot guide |
| `kql/examples.md` | General KQL examples you can adapt into hunts and analytics |

---

## 🎯 How to Use This Repo

| Use Case | How to Use This Repo |
|----------|----------------------|
| Quick triage | Start with `matrices/pivot_index.md` to pick your tables |
| Build a new analytic rule | Look up relevant tables in Sentinel + MDE matrices, note key fields and MITRE mapping, then adapt KQL from `kql/examples.md` |
| Threat hunting | Use per-table “Attack Coverage” and “KQL Starter” rows as entry points for hunts |
| Interview prep | Treat each `*.md` as a printable/learnable sheet: tables, fields, threats, pivots |
| Documentation / onboarding | Link analysts to this repo as part of your SOC runbook |

---

## 👤 Author

**Alstrum (Ala Dabat)**  
Senior Cyber Security Analyst – Detection Engineering, Threat Hunting & IR  
This repo is part of a wider professional reference set for SOC and CTI work.
