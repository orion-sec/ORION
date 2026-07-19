# Behavioural Evidence Analysis & Response Playbook Engine

## Purpose

This document explains how ORION now combines behavioural evidence with technical indicators to improve attack pattern detection and automatically generate structured response playbooks.

The Behavioural Evidence Engine represents ORION's transition from IOC-centric analysis towards contextual investigation reasoning.

---

## Behavioural Evidence Analysis

Implemented in:

`11_Modules/attack_patterns.py`

Behavioural Evidence Analysis evaluates investigation narrative for indicators that suggest user actions associated with common attack techniques.

Current behavioural indicators include:

- entered credentials
- submitted credentials
- entered password
- submitted password
- provided credentials
- credential harvesting
- login details entered

These indicators provide contextual evidence that cannot be derived from IOC reputation alone.

---

## Credential Phishing Detection

Current detection logic requires:

Credential Submission Behaviour

AND

(Suspicious URL OR Suspicious Domain)

This approach improves phishing detection while reducing dependence on URL reputation.

Example:

Investigation:

User received a phishing email containing:

https://login.example.com/reset

and entered credentials.

ORION identifies:

Attack Pattern

Credential Phishing

↓

MITRE ATT&CK

T1566.002

↓

Response Playbook

---

## Defensive Programming

ORION now supports investigations without IP-based threat intelligence.

If no Threat Correlation object exists, the engine automatically generates a safe default object.

Default values:

Verdict

Unknown

Confidence

Low

Sources

0

Reason

No IP-based threat intelligence correlation available.

This prevents runtime failures while maintaining investigation continuity.

---

## Response Playbook Engine

Implemented in:

`11_Modules/response_playbooks.py`

The Response Playbook Engine generates structured response actions based on detected attack patterns.

Unlike Investigation Recommendations, playbooks provide operational actions that analysts can perform during incident response.

---

## Current Playbooks

### Malware Delivery

Current response actions include:

- Identify affected endpoint
- Review EDR telemetry
- Isolate endpoint
- Block URL
- Block IP
- Block file hash
- Hunt for related indicators
- Collect forensic evidence
- Escalate to Incident Response

---

### Credential Phishing

Current response actions include:

- Identify affected users
- Review email telemetry
- Remove phishing messages
- Block sender
- Block URL
- Block domain
- Review sign-in activity
- Revoke sessions
- Reset passwords
- Review MFA
- Review inbox rules
- Review OAuth consent
- Hunt for related indicators
- Escalate to Incident Response

---

## Relationship Between Modules

Current investigation flow:

IOC Extraction

↓

Threat Intelligence

↓

Threat Correlation

↓

Behavioural Evidence Analysis

↓

Attack Pattern Detection

↓

MITRE ATT&CK Mapping

↓

Response Playbook Engine

↓

Investigation Assessment

↓

Priority Assessment

↓

Final Investigation Report

Each module performs a single responsibility while contributing to ORION's overall reasoning capability.

---

## Why Behaviour Matters

Many real-world attacks involve:

- Newly registered phishing domains
- Legitimate cloud-hosted phishing pages
- Unknown infrastructure
- Zero-day phishing campaigns

These attacks often have little or no threat intelligence.

Behavioural evidence enables ORION to identify suspicious activity even when technical reputation is unavailable.

---

## Future Enhancements

Future versions of ORION should expand behavioural analysis to include:

- MFA fatigue attacks
- Password spraying
- Impossible travel confirmation
- OAuth abuse
- Token theft
- Session hijacking
- Remote administration abuse
- Privilege escalation
- Lateral movement
- Data exfiltration
- Insider threat behaviour

These enhancements will further improve ORION's contextual reasoning and response capabilities while supporting more advanced incident response scenarios.