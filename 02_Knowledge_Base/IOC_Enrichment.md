# IOC Enrichment

## Definition

IOC (Indicator of Compromise) enrichment is the process of automatically adding useful security context to extracted indicators before an analyst begins an investigation.

Instead of displaying only raw indicators, enrichment provides additional information that helps analysts make faster and more informed decisions.

---

# Why IOC Enrichment Is Important

Raw IOCs provide very little context.

Example:

IP Address

8.8.8.8

Without enrichment an analyst still needs to determine:

- Is the IP public?
- Is it private?
- Is it internal?
- Is it reserved?
- Is it loopback?
- Is it suspicious?

Enrichment answers many of these questions automatically.

---

# Types of IOC Enrichment

## IP Address Enrichment

Typical enrichment includes:

- IP version
- Private/Public
- Global
- Loopback
- Reserved
- Country
- ASN
- ISP
- Reputation
- Threat Intelligence

---

## Domain Enrichment

Typical enrichment includes:

- WHOIS
- Domain age
- Registrar
- DNS records
- Reputation
- Newly registered domains

---

## URL Enrichment

Typical enrichment includes:

- URL reputation
- Redirect chain
- Malware hosting
- Phishing classification

---

## File Hash Enrichment

Typical enrichment includes:

- Malware family
- Detection rate
- First seen
- Last seen
- Threat actor association

---

## Email Enrichment

Typical enrichment includes:

- SPF
- DKIM
- DMARC
- Domain reputation
- Known phishing campaigns

---

# ORION Day 8 Implementation

The first version of ORION enrichment focuses on IP addresses.

Current capabilities include:

- IP Version
- Private Address Detection
- Global Address Detection
- Loopback Detection
- Multicast Detection
- Reserved Address Detection

This enrichment is performed automatically after IOC extraction and before the final investigation report is generated.

---

# SOC Use Case

A SOC analyst receives an alert containing:

Source IP:
8.8.8.8

Instead of manually researching the address, ORION automatically enriches it and provides immediate context.

This reduces investigation time and helps analysts prioritise incidents more efficiently.

---

# Future Enhancements

Future versions of ORION will integrate with:

- VirusTotal
- AbuseIPDB
- GreyNoise
- Cisco Talos
- Shodan
- Microsoft Defender Threat Intelligence
- Recorded Future

These integrations will transform ORION into an intelligent investigation assistant capable of providing reputation, threat intelligence and response recommendations automatically.