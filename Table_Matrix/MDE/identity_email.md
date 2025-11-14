# 👤📧 MDE Identity & Email Tables (If Available)

> Note: Availability of these tables depends on licensing and integration (Defender for Office 365, Defender for Identity, Defender for Cloud Apps, Defender XDR unified portal).

---

## 1. EmailEvents

| Field | Value |
|-------|-------|
| Purpose | Summary of email messages seen by Defender for Office 365 |
| Key Fields | Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, ThreatTypes, DeliveryAction, NetworkMessageId |
| Typical Attack Coverage | Phishing, malware in email, business email compromise indicators |
| MITRE | T1566 (Phishing), T1204 (User Execution) |
| Common Pivots | NetworkMessageId → EmailUrlInfo and EmailAttachmentInfo; RecipientEmailAddress → OfficeActivity and SigninLogs |
| KQL Starter | ```kql\nEmailEvents\n| where Timestamp >= ago(7d)\n| where ThreatTypes != \"\" or DeliveryAction in (\"Blocked\",\"Replaced\")\n``` |

---

## 2. EmailUrlInfo

| Field | Value |
|-------|-------|
| Purpose | URLs found in email messages |
| Key Fields | Timestamp, NetworkMessageId, Url, ThreatTypes, DetectionMethods |
| Typical Attack Coverage | Malicious URLs, credential harvesting sites, malware delivery via links |
| MITRE | T1566, T1204, T1189 (Drive-by) |
| Common Pivots | Url → TI; NetworkMessageId → EmailEvents; Url → DeviceNetworkEvents for click-through |
| KQL Starter | ```kql\nEmailUrlInfo\n| where Timestamp >= ago(7d)\n| where ThreatTypes != \"\" or Url has_any (\"login\",\"update\",\"secure\")\n``` |

---

## 3. EmailAttachmentInfo

| Field | Value |
|-------|-------|
| Purpose | Attachments in email messages |
| Key Fields | Timestamp, NetworkMessageId, FileName, FileType, SHA256, ThreatTypes |
| Typical Attack Coverage | Malicious attachments (macro docs, ISO/VHD, executables, archives) |
| MITRE | T1566, T1204 |
| Common Pivots | SHA256 → DeviceFileEvents and DeviceProcessEvents; NetworkMessageId → EmailEvents |
| KQL Starter | ```kql\nEmailAttachmentInfo\n| where Timestamp >= ago(7d)\n| where ThreatTypes != \"\" or FileType in (\"exe\",\"dll\",\"iso\",\"js\",\"vbs\",\"docm\",\"xlsm\")\n``` |
