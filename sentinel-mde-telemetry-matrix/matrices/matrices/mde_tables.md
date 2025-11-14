# 📘 MDE Table Matrix

## 1. DeviceInfo

| Field | Value |
|-------|-------|
| Purpose | Device inventory |
| Attack Coverage | Identifying DCs, servers, high-value targets |
| MITRE | Pre-attack mapping |
| KQL | ```DeviceInfo | summarize count() by OSPlatform``` |

---

## 2. DeviceProcessEvents  
*(same intensive detail as above)*

| Purpose | Process telemetry |
| Key Fields | FileName, CommandLine, Parent, SHA1 |
| MITRE | T1059, T1218, T1053 |
| KQL | ```DeviceProcessEvents | take 50``` |

---

## 3. DeviceNetworkEvents

| Purpose | Network flows |
| MITRE | T1041, T1105 |
| KQL | ```DeviceNetworkEvents | take 50``` |

---

## 4. DeviceFileEvents

| Purpose | File writes/reads |
| MITRE | T1486, T1074 |
| KQL | ```DeviceFileEvents | take 50``` |

---

## 5. DeviceRegistryEvents

| Purpose | Registry writes |
| MITRE | T1112, T1547 |
| KQL | ```DeviceRegistryEvents | take 50``` |

---

## 6. DeviceLogonEvents

| Purpose | Logons |
| MITRE | T1021.001 |
| KQL | ```DeviceLogonEvents | take 50``` |

---

## 7. DeviceEvents

| Purpose | Misc events |
| MITRE | T1203, T1562 |
| KQL | ```DeviceEvents | take 50``` |

---

## 8. AlertInfo & AlertEvidence

| Purpose | Alert metadata + entities |
| MITRE | All techniques |
| KQL | ```AlertEvidence | take 50``` |

