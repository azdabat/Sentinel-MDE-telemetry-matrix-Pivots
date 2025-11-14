#  Sentinel & MDE Telemetry Matrix  
### Comprehensive SOC Telemetry, Pivoting & Detection Reference

This repository provides a complete, GitHub-ready reference for every major telemetry source used in:
- Microsoft Sentinel
- Microsoft Defender for Endpoint (MDE)

It includes:
- Wide GitHub-friendly tables  
- Pivoting logic  
- Key investigative fields  
- MITRE mappings  
- KQL examples  

Designed for:
- SOC Analysts  
- Threat Hunters  
- Detection Engineers  
- Incident Responders  

---

# 📁 Repository Structure

| Path | Description |
|------|-------------|
| `matrices/sentinel_tables.md` | All Sentinel tables with fields, use-cases, pivots, KQL |
| `matrices/mde_tables.md` | Full MDE advanced hunting table matrix |
| `matrices/mitre-mapping.md` | MITRE ATT&CK mappings for all telemetry sources |
| `matrices/pivot_index.md` | “Which table do I use for X?” quick-pivot reference |
| `kql/examples.md` | General KQL example queries |

---

# 🧭 How to Use This Repo

| Purpose | How |
|---------|-----|
| Triage Alerts | Use `pivot_index.md` |
| Build Detections | Check “Attack Coverage” per table |
| Threat Hunting | Start from KQL examples in each section |
| MITRE Alignment | Use `mitre-mapping.md` |
| SOC Training | Treat as your telemetry encyclopedia |

---

# 👤 Author

**Alstrum (Ala Dabat)**  
Senior Cyber Security Analyst — IR, Detection Engineering, Threat Hunting

