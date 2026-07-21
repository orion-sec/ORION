# ORION IOC Coverage Roadmap

**Project:** ORION Security Investigation Platform

**Document Version:** 1.0

**Last Updated:** Day 18

**Owner:** Onwenmadu Samuel Chukwuka

---

# Purpose

This document defines the long-term Indicator of Compromise (IOC) coverage strategy for ORION.

The goal is to ensure that ORION develops into a complete investigation platform capable of supporting Security Operations Centre (SOC), Incident Response (IR), Threat Hunting, Detection Engineering, Digital Forensics, Cloud Security, Identity Security, and Business Email Compromise investigations.

Rather than focusing only on extracting indicators, ORION is designed to understand, enrich, correlate, assess and respond to security events using a modular investigation pipeline.

This roadmap serves as the engineering reference for current capabilities and future IOC expansion.

---

# IOC Maturity Levels

| Level | Meaning |
|--------|---------|
| Planned | Capability has not yet been implemented |
| Foundation | Basic extraction or identification implemented |
| Developing | Enrichment or analysis has begun |
| Mature | Extraction, enrichment, correlation and reporting complete |
| Advanced | External intelligence, automation and AI-assisted reasoning integrated |

---

# Current IOC Coverage Matrix

| IOC Category | Extraction | Enrichment | Correlation | Reporting | Status |
|--------------|------------|------------|-------------|-----------|--------|
| URLs | ✅ | ✅ | ✅ | ✅ | Mature |
| Domains | ✅ | ✅ | ✅ | ✅ | Mature |
| IP Addresses | ✅ | ✅ | ✅ | ✅ | Mature |
| Email Addresses | ✅ | ⚠ Planned | ⚠ Planned | ✅ | Foundation |
| Identity Entities | ✅ | ⚠ Planned | ⚠ Planned | ✅ | Foundation |
| MD5 Hashes | ✅ | ❌ | ❌ | ✅ | Foundation |
| SHA1 Hashes | ✅ | ❌ | ❌ | ✅ | Foundation |
| SHA256 Hashes | ✅ | ❌ | ❌ | ✅ | Foundation |
| File Names | ❌ | ❌ | ❌ | ❌ | Planned |
| File Extensions | ⚠ Basic | ❌ | ❌ | ❌ | Foundation |
| Processes | ❌ | ❌ | ❌ | ❌ | Planned |
| Command Lines | ❌ | ❌ | ❌ | ❌ | Planned |
| Registry Keys | ❌ | ❌ | ❌ | ❌ | Planned |
| Services | ❌ | ❌ | ❌ | ❌ | Planned |
| Scheduled Tasks | ❌ | ❌ | ❌ | ❌ | Planned |
| Email Headers | ❌ | ❌ | ❌ | ❌ | Planned |
| OAuth Applications | ❌ | ❌ | ❌ | ❌ | Planned |
| Azure Applications | ❌ | ❌ | ❌ | ❌ | Planned |
| Browser Extensions | ❌ | ❌ | ❌ | ❌ | Planned |
| Certificates | ❌ | ❌ | ❌ | ❌ | Planned |
| Cloud Resources | ❌ | ❌ | ❌ | ❌ | Planned |

---

# IOC Coverage Details

---

## URLs

### Current Capabilities

- IOC Extraction
- URL Parsing
- URL Risk Scoring
- Behaviour Detection
- Threat Correlation
- MITRE Mapping
- Contextual Risk Integration
- Response Playbooks

### Future Enhancements

- VirusTotal
- URLScan.io
- Google Safe Browsing
- WHOIS
- Passive DNS
- Domain Age
- Redirect Chain Analysis
- URL Reputation APIs

---

## Domains

### Current Capabilities

- Domain Extraction
- Reputation Classification
- Suspicious Keyword Detection
- IOC Correlation

### Future Enhancements

- WHOIS
- Passive DNS
- Registrar Intelligence
- Domain Age
- DNS History
- DNS Record Analysis
- Newly Registered Domain Detection
- Typosquatting Detection

---

## IP Addresses

### Current Capabilities

- IOC Extraction
- Threat Intelligence
- IOC Correlation
- Investigation Assessment

### Future Enhancements

- VirusTotal
- AbuseIPDB
- ASN Lookup
- Country
- ISP
- Hosting Provider
- VPN Detection
- TOR Detection
- Reverse DNS
- Historical Reputation

---

## Email Addresses

### Current Capabilities

- Email Extraction
- Identity Association

### Future Enhancements

- Display Name Analysis
- Executive Impersonation Detection
- Tenant Validation
- SPF
- DKIM
- DMARC
- BEC Risk Assessment
- External Relationship Analysis

---

## Identity Entities

### Current Capabilities

- Primary User Identification
- Email Association
- Identity Object Generation

### Future Enhancements

- Microsoft Graph Integration
- Display Name
- Department
- Manager
- Job Title
- Office Location
- Risk Level
- Privileged Role Detection
- VIP Identification
- Account Type Classification
- Last Sign-in
- User Risk
- Device Ownership

---

## File Hashes

### Current Capabilities

- MD5 Extraction
- SHA1 Extraction
- SHA256 Extraction

### Future Enhancements

- VirusTotal
- Malware Bazaar
- ThreatFox
- Malware Family
- Campaign Correlation
- Threat Actor Attribution
- Sandbox Reports
- YARA Rules
- Sigma Rules
- MITRE ATT&CK Mapping

---

## File Names

### Planned Features

- Executable Detection
- Double Extension Detection
- Suspicious Filename Detection
- Office Documents
- ISO Images
- Scripts
- Macro-enabled Documents
- Archive Inspection

---

## Processes

### Planned Features

- LOLBins Detection
- PowerShell Analysis
- Command Prompt
- Rundll32
- Regsvr32
- WMIC
- MSHTA
- Process Trees
- Parent/Child Relationships

---

## Command Lines

### Planned Features

- Encoded PowerShell
- Base64 Detection
- Certutil
- Bitsadmin
- Curl
- Invoke-WebRequest
- Download Cradles
- Obfuscation Detection

---

## Registry

### Planned Features

- Run Keys
- RunOnce
- Winlogon
- IFEO
- Services
- Registry Persistence

---

## Services

### Planned Features

- Malicious Service Detection
- Service Persistence
- Service Creation
- Service Modification

---

## Scheduled Tasks

### Planned Features

- Persistence Detection
- Hidden Tasks
- Malicious Task Creation

---

## Email Headers

### Planned Features

- Return Path
- Message ID
- SPF Validation
- DKIM Validation
- DMARC Validation
- Relay Chain Analysis
- Sender Infrastructure
- BEC Investigation

---

## OAuth Applications

### Planned Features

- Consent Analysis
- Dangerous Permissions
- Tenant-wide Consent
- Rogue Applications

---

## Azure Applications

### Planned Features

- Enterprise Applications
- Service Principals
- Secret Expiration
- Certificate Analysis

---

## Browser Extensions

### Planned Features

- Malicious Extensions
- Browser Persistence
- Credential Theft Extensions

---

## Certificates

### Planned Features

- TLS Certificate Analysis
- Self-signed Detection
- Expiration
- Issuer Validation

---

## Cloud Resources

### Planned Features

- Azure
- AWS
- Google Cloud
- Storage Accounts
- Key Vault
- IAM Roles
- Security Groups

---

# Investigation Coverage Matrix

| Investigation Type | Primary IOC Categories |
|--------------------|------------------------|
| Phishing | URLs, Domains, Email Addresses, Identity |
| Credential Phishing | URLs, Domains, Identity, Authentication |
| Business Email Compromise | Email Headers, Identity, Domains, OAuth |
| Malware | Hashes, Files, Processes, Command Lines |
| Ransomware | Processes, Services, Registry, Scheduled Tasks, Hashes |
| Insider Threat | Identity, Devices, Authentication, Cloud |
| Cloud Compromise | Identity, OAuth, Azure Applications, IP Addresses |
| Endpoint Intrusion | Processes, Registry, Services, Command Lines |
| Web Attack | URLs, Domains, IP Addresses |
| Command and Control | Domains, IP Addresses, URLs |
| Lateral Movement | Identity, Authentication, Processes |
| Persistence | Registry, Services, Scheduled Tasks |
| Data Exfiltration | Identity, Cloud Resources, Network Indicators |

---

# Engineering Principles

ORION follows several design principles when implementing IOC support:

- Preserve original evidence whenever possible.
- Separate identity intelligence from infrastructure intelligence.
- Treat IOC extraction, enrichment and correlation as independent modules.
- Design stable data models before integrating external data sources.
- Ensure every IOC category can evolve independently without affecting downstream components.
- Support explainable security decisions by providing evidence for every assessment.

---

# Future Vision

The long-term objective is for ORION to become a modular investigation platform capable of automatically extracting, enriching, correlating, assessing and responding to security incidents across identity, endpoint, cloud, email and network environments.

Future integrations include:

- Microsoft Graph
- Microsoft Defender XDR
- CrowdStrike Falcon
- Google SecOps
- ServiceNow
- VirusTotal
- AbuseIPDB
- URLScan.io
- Shodan
- GreyNoise
- MISP
- OpenCTI

---

# Version History

| Version | Day | Summary |
|----------|-----|---------|
| 1.0 | Day 18 | Initial IOC Coverage Roadmap created |