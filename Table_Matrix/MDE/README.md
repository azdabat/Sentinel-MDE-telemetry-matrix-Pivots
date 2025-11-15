# 🛡️ AZDABAT — Threat Detection Engineering & Cyber Defence  
**Hybrid Professional + Hacker Aesthetic | SOC L2–L3 | Threat Intelligence | Detection Engineering**

```ascii
       _       _           _         _   
   ___| | ___ | |__   __ _| |_ _   _| |_ 
  / _ \ |/ _ \| '_ \ / _` | __| | | | __|
 |  __/ | (_) | |_) | (_| | |_| |_| | |_ 
  \___|_|\___/|_.__/ \__,_|\__|\__,_|\__|
     THREAT  INTELLIGENCE  LABS
---
---
Welcome to my Threat Detection Engineering, SOC L2–L3 research, and Microsoft Defender / Sentinel portfolio.
This repository contains:

Full MDE endpoint telemetry mapping

Full MCAS (Cloud App Security) mapping

Complete Sentinel + MDE + MCAS MITRE ATT&CK Matrix

Advanced threat-hunting playbooks

An actionable intrusion investigation flowchart

My end-to-end detection engineering methodology

Project Overview

This repository demonstrates:

Intelligence-driven detection engineering

Complete endpoint telemetry mastery (Process, Network, Registry, File, ImageLoad…)

Cross-cloud & SaaS threat analysis (MCAS, CloudAppEvents)

Attack-chain reconstruction

MITRE ATT&CK alignment

L2–L3 SOC investigation methodology

Threat intel enrichment & scoring logic

🧭 How to Investigate Any Intrusion (L2–L3 Flowchart)

+--------------------------------------------------------------+
|                    INCIDENT INVESTIGATION                    |
+--------------------------------------------------------------+
        |
        v
+------------------+
| 1. Alert Trigger |
+------------------+
        |
        v
+---------------------------+
| 2. Identify Affected Host |
+---------------------------+
        |
        v
+-----------------------------+
| 3. Pull Process Timeline    |
|    (DeviceProcessEvents)    |
+-----------------------------+
        |
        v
+-----------------------------+
| 4. Pivot to Network Traffic |
|    (DeviceNetworkEvents)    |
+-----------------------------+
        |
        v
+-----------------------------+
| 5. Look for File Drops      |
|    (DeviceFileEvents)       |
+-----------------------------+
        |
        v
+-----------------------------+
| 6. Persistence Check        |
|    (DeviceRegistryEvents)   |
+-----------------------------+
        |
        v
+-----------------------------+
| 7. DLL / Module Loads       |
|    (DeviceImageLoadEvents)  |
+-----------------------------+
        |
        v
+--------------------------------------------+
| 8. Identity Behaviour (AAD / LogonEvents)  |
+--------------------------------------------+
        |
        v
+--------------------------------------------+
| 9. Cloud App / SaaS Pivot (MCAS/MDE Cloud) |
+--------------------------------------------+
        |
        v
+------------------------+
| 10. Kill Chain Summary |
+------------------------+


