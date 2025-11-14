# Windows Process Ancestry Matrix  
### Parent–Child Baselines, LOLBins, and Attack Chains

This repository is a **Windows process ancestry bible**. It focuses on:

- The **top 20 abused LOLBins** and how they should vs should not be launched
- **Normal vs suspicious vs clearly malicious parent–child chains**
- Persistence paths (registry, services, tasks, autostarts)
- Attack chains explained as **process trees**
- KQL hunting and detection templates

It is designed for:

- SOC analysts and incident responders
- Threat hunters
- Detection engineers writing KQL / Sigma rules

Use it as a **reference** when designing rules like:

- “Alert when mshta.exe is launched by outlook.exe”
- “Alert when certutil.exe writes an EXE then that EXE connects out”
- “Alert when schtasks.exe is launched by Office or a browser”

---

##  Structure

| Path | Description |
|------|-------------|
| `matrices/lolbins/top20_lolbins.md` | Top 20 LOLBins – legit parents, suspicious parents, malicious usage, examples |
| `matrices/lolbins/lolbin_mitre_mapping.md` | LOLBins mapped to MITRE ATT&CK techniques |
| `matrices/lolbins/lolbin_kql_examples.md` | KQL hunting examples for each LOLBin |
| `matrices/process_baselines/parent_child_matrix.md` | “What should launch what” baseline for common processes |
| `matrices/process_baselines/suspicious_parent_matrix.md` | Suspicious but contextual parent → child combinations |
| `matrices/process_baselines/malicious_parent_matrix.md` | High-confidence malicious parent → child combinations |
| `matrices/process_baselines/commandline_patterns.md` | High-risk command-line patterns by process |
| `matrices/process_baselines/process_attack_mapping.md` | Process-level mapping to attack types (ransomware, C2, discovery, etc.) |
| `matrices/persistence/registry_persistence.md` | Registry-based persistence keys and process patterns |
| `matrices/persistence/service_persistence.md` | Malicious services and service binary hijack patterns |
| `matrices/persistence/scheduled_tasks.md` | Task-based persistence techniques |
| `matrices/persistence/autostart_locations.md` | Common Windows autostart locations and abuse patterns |
| `matrices/ancestry_visuals/ancestry_flowcharts.md` | Conceptual flowcharts for common attack chains |
| `matrices/ancestry_visuals/ascii_attack_chains.md` | ASCII process trees for reference in terminals/docs |
| `kql/lolbins.md` | LOLBin-focused KQL patterns |
| `kql/parent_child.md` | Parent–child detection templates and baselines |
| `kql/detection_examples.md` | More complete detection queries using all of the above |

---

##  Philosophy

The entire repo is built around one core idea:

> “The right binary launched by the wrong parent is nearly always suspicious.”

This gives you:

- An easy way to design rules: **parent + child + context**
- A way to explain detections in interviews and incident reports
- A standard reference matrix that can be reused across environments

---
