# 📊 Sentinel & MDE Telemetry Matrix  
### Comprehensive SOC Telemetry, Pivoting & Detection Reference

This repository provides a **complete, analyst-friendly, GitHub-ready reference** for every major telemetry source used in:
- **Microsoft Sentinel**
- **Microsoft Defender for Endpoint (MDE)**

It includes clean, wide, GitHub-safe tables for:
- Table purpose & log type  
- Key fields for investigations  
- Attack types each table detects  
- Pivot strategies (what to look at next)  
- MITRE ATT&CK mappings  
- KQL examples for threat hunting & detection engineering  

All content is optimised for:
- SOC Analysts (L1–L3)
- Threat Hunters
- DFIR Analysts
- Detection Engineers
- Red/Blue/Purple Teams

---

# 📁 Repository Structure

| Path | Description |
|------|-------------|
| `matrices/sentinel_tables.md` | All Sentinel tables, fields, use-cases, pivots, KQL |
| `matrices/mde_tables.md` | Full MDE advanced hunting table matrix |
| `matrices/mitre-mapping.md` | MITRE ATT&CK mappings for all tables |
| `matrices/pivot_index.md` | A global pivot index: “Which table do I use for X?” |
| `kql/examples.md` | General-purpose KQL examples |

---

# 🎯 Purpose of This Project

This repository acts as a **SOC telemetry bible**.  
It is designed to eliminate the guesswork in IR, threat hunting, and detection engineering by providing:

### ✔ Clear understanding of what each table captures  
### ✔ The exact fields that matter during investigations  
### ✔ Which attacks map to which tables  
### ✔ How to pivot between tables efficiently  
### ✔ MITRE technique alignment for each table  
### ✔ Clean starter KQL for real-world use  

---

# 🧭 How to Use This Repo

| Task | How to Use |
|------|------------|
| **Triage Alerts** | Use `pivot_index.md` to choose the correct table quickly |
| **Build Detections** | Start with the “Attack coverage” column inside each table |
| **Threat Hunting** | Use KQL examples + table pivots to expand findings |
| **MITRE Mapping** | See `mitre-mapping.md` for quick ATT&CK alignment |
| **Training Analysts** | Treat this repo as an in-house telemetry encyclopedia |

---

# 🔗 Related Repositories (Recommended)

- **Process & LOLBin Ancestry Matrix**  
- **Attack Technique → KQL Detection Matrix**  
(These will be built in your next two repos.)

---

# 👤 Author

**Alstrum (Ala Dabat)**  
Senior Cyber Security Analyst — Detection Engineering, IR, Threat Hunting  
This repository is part of a professional-grade SOC reference toolkit.

