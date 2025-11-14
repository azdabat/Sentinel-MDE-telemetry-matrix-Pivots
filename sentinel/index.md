# 📘 Sentinel Telemetry – Index

This folder documents major **Microsoft Sentinel** tables by category:

---

## 🖥 Endpoint / Host Telemetry

File: `endpoint.md`

Includes (examples):

- DeviceProcessEvents  
- DeviceNetworkEvents  
- DeviceFileEvents  
- DeviceRegistryEvents  
- DeviceLogonEvents  
- DeviceInfo  
- DeviceEvents  
- SecurityEvent (Windows Security logs)  
- Syslog (Linux/Unix and network devices)  

---

## 👤 Identity & Authentication

File: `identity.md`

Includes:

- SigninLogs  
- AADManagedIdentitySignInLogs  
- AADServicePrincipalSignInLogs  
- AADNonInteractiveUserSignInLogs  
- AuditLogs (Azure AD Audit)  
- IdentityInfo / IdentityLogonEvents (UEBA, if present)  

---

## ☁️ Cloud / SaaS (M365, Azure)

File: `cloud_saas.md`

Includes:

- OfficeActivity (Exchange, SharePoint, OneDrive, Teams)  
- AzureActivity (resource operations)  
- AzureDiagnostics (service-specific logs)  

---

## 🌐 Network & Perimeter

File: `network_perimeter.md`

Includes:

- CommonSecurityLog (CEF: firewalls, WAF, VPN, proxy, IPS)  
- AzureFirewall logs  
- Azure WAF / Application Gateway logs  
- NVA / 3rd party appliances (via CEF/Syslog)  

---

## 🧱 ASIM Normalized Tables

File: `asim_normalized.md`

Includes:

- ASimNetworkSession (NetworkSession logs)  
- ASimDnsActivity (DNS)  
- ASimWebSession (Web proxy / HTTP)  
- ASimProcessEvent (Process activity)  
- ASimAuthentication (Auth)  
- ASimFileEvent, ASimRegistryEvent, etc.  

---

## 🧪 Specialty & Niche Tables

File: `specialty.md`

Includes:

- KeyVaultDataPlane  
- AzureDiagnostics (SQL, Storage, AKS, etc.)  
- SecurityAlert / SecurityIncident  
- Custom tables specific to your environment  

Use these matrices to map **“what telemetry do I have”** to **“what detection can I build.”**
