# 📘 Microsoft Defender for Endpoint / Defender XDR – Index

This folder documents **MDE / Defender XDR** hunting tables by category.

---

## 🖥 Core Endpoint Tables

File: `core_endpoint.md`

Includes:

- DeviceInfo  
- DeviceProcessEvents  
- DeviceNetworkEvents  
- DeviceFileEvents  
- DeviceRegistryEvents  
- DeviceLogonEvents  
- DeviceEvents  

---

## 🚨 Alerts & Incidents

File: `alerts_incidents.md`

Includes:

- AlertInfo  
- AlertEvidence  
- potentially IncidentInfo / IncidentEntities (if exposed in your tenant)  

---

## 👤 Identity & Email

File: `identity_email.md`

Includes (where available in your environment):

- EmailEvents  
- EmailUrlInfo  
- EmailAttachmentInfo  
- EmailPostDeliveryEvents  
- Identity tables where surfaced through Defender XDR  

---

## ☁️ Cloud Apps / Shadow IT

File: `cloud_apps.md`

Includes:

- CloudAppEvents (Defender for Cloud Apps / MCAS)  
- App governance related tables (if available)  
