# ORION Knowledge Base
## Risk Scoring Engine

### Purpose

The Risk Scoring Engine is responsible for converting enriched investigation data into meaningful security decisions.

Instead of only collecting IOC information, ORION evaluates the security relevance of each indicator.

---

## Current Architecture

Investigation

↓

Extraction

↓

Enrichment

↓

Risk Scoring

↓

Reporting

---

## score.py

The score.py module contains the scoring logic for enriched IP addresses.

Current classifications include:

Private Address

Risk:
Low

Score:
10

Reason:
Private IP Address

---------------------------------

Loopback

Risk:
Informational

Score:
0

Reason:
Loopback Address

---------------------------------

Reserved Address

Risk:
Low

Score:
15

Reason:
Reserved Address

---------------------------------

Public Global Address

Risk:
Medium

Score:
50

Reason:
Public Global IP

---------------------------------

Unknown

Risk:
Unknown

Score:
25

Reason:
Unable to classify

---

## Design Philosophy

Scoring should never automatically declare an IOC malicious.

Instead, scoring estimates investigation priority based on currently available evidence.

Additional intelligence sources will later adjust the final score.

Examples include:

• VirusTotal

• AbuseIPDB

• GeoIP

• ASN Reputation

• Threat Intelligence Feeds

• Internal Threat Lists

---

## Future Improvements

Planned enhancements include:

- Country Risk Scoring

- ASN Reputation

- Tor Exit Node Detection

- Cloud Provider Identification

- Threat Intelligence Reputation

- Historical IOC Observations

- MITRE ATT&CK Mapping

- Overall Investigation Confidence Score

- Analyst Recommendation Engine

---

## Key Engineering Principle

Extraction answers:

"What exists?"

Enrichment answers:

"What do we know?"

Scoring answers:

"How important is this?"

These responsibilities should remain separate to keep the system modular, reusable, and easy to maintain.