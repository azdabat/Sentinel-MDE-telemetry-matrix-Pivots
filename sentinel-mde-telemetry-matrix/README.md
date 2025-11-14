#  Zero-Day Sentinel & MDE Telemetry Matrix

**Author:** Alstrum (Ala Dabat)  
**Project:** Zero-Day – Advanced Detection & Threat Hunting

![Zero-Day Telemetry Banner](assets/banner.png)

> Know your tables. Know your pivots. Build better detections.

This repository is a **SOC reference** for:

- Microsoft Sentinel core tables (endpoint, identity, cloud, network)
- Microsoft Defender for Endpoint (MDE) hunting tables
- Their **purpose**, **key fields**, **common attacks detected**, and **pivot ideas**

Designed for:

- SOC analysts (L1–L3)
- Threat hunters
- Detection engineers and IR

---

## 📂 Contents

- [`matrices/sentinel_tables.md`](matrices/sentinel_tables.md)  
  **What:** Sentinel-side table matrix – DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, SecurityEvent, SigninLogs, AuditLogs, OfficeActivity, AzureActivity, CommonSecurityLog, ThreatIntelligenceIndicator.  
  **Why:** Helps analysts know “which table do I query for X?” and “how do I pivot from this event?”

- [`matrices/mde_tables.md`](matrices/mde_tables.md)  
  **What:** MDE advanced hunting table matrix – DeviceInfo, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceEvents, AlertInfo, AlertEvidence.  
  **Why:** Shows how to move from alerts → entities → raw telemetry for investigation.

---

## 🧬 How to Use

1. **During triage:** Start with AlertInfo/AlertEvidence → identify entities.
2. **During hunting:** Pick an attack type (e.g. Kerberoasting, OAuth abuse, RDP brute) and see which tables are best for it.
3. **During detection engineering:** Use “Key Fields” + “Pivots” sections to design efficient KQL.

---

## 🔗 Related Repos

- Process & LOLBin Ancestry Matrix (parent-child baselining)
- Attack Technique → KQL Playbook

---

## 👤 About

Part of the **Zero-Day** project by **Alstrum (Ala Dabat)**.  
Built as a practical, field-driven reference for real SOC work.
