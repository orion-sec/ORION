# Threat Intelligence API and Risk Scoring

## Overview

Threat intelligence enrichment adds external reputation context to security indicators such as IP addresses, domains, URLs and file hashes.

ORION currently integrates with AbuseIPDB for live IP reputation enrichment.

---

## Threat Intelligence Workflow

ORION processes IP threat intelligence using the following workflow:

IOC Extracted  
↓  
IP Enriched  
↓  
Threat Intelligence Lookup  
↓  
Result Normalised  
↓  
Risk Scoring  
↓  
SOC Decision  
↓  
Investigation Priority

---

## AbuseIPDB

AbuseIPDB provides reputation information about public IP addresses.

ORION currently extracts:

- IP address
- Threat intelligence source
- API availability status
- Reputation
- Confidence score
- Report count

---

## API Credential Security

API keys should never be hardcoded inside application source code.

ORION stores API credentials inside a `.env` file.

Python loads the environment variables using `python-dotenv`.

The `.env` file must be excluded from Git using `.gitignore`.

Example:

ABUSEIPDB_API_KEY=<API_KEY>

The real API key must never be committed to GitHub.

---

## Threat Intelligence Normalisation

External threat intelligence providers may return different data structures.

ORION converts provider data into a consistent internal format.

Example fields:

- ip
- source
- status
- reputation
- confidence
- reports

Normalisation allows the scoring and decision engines to consume threat intelligence without depending directly on the provider's raw API response.

---

## Graceful Degradation

Threat intelligence providers may become unavailable because of:

- Network failure
- API outage
- Invalid endpoint
- Authentication failure
- Rate limiting
- Timeout

ORION should not terminate the entire investigation when this occurs.

Instead, the threat intelligence module returns:

Status: Unavailable  
Reputation: Unknown  
Confidence: 0  
Reports: 0

The investigation continues using local enrichment and baseline scoring.

---

## Threat-Aware Risk Scoring

Threat intelligence can influence ORION's risk score.

Example decision logic:

High confidence malicious intelligence  
→ High Risk  
→ P1 investigation priority

Moderate threat confidence  
→ Elevated Risk  
→ Increased investigation priority

Clean intelligence  
→ Lower IOC risk  
→ Supporting activity should still be validated

Threat intelligence unavailable  
→ Use baseline public IP scoring  
→ Continue investigation

---

## Important SOC Principle

Threat intelligence is enrichment, not final evidence.

A clean IP reputation does not automatically mean the activity is legitimate.

Analysts should correlate threat intelligence with:

- Identity logs
- Sign-in activity
- MFA status
- EDR telemetry
- Historical activity
- User behaviour
- Host relationships
- Additional IOC activity

The final security decision should be based on correlated evidence.

---

## ORION Design Principle

ORION should never blindly trust a single threat intelligence provider.

Future versions should support multiple intelligence sources and compare results before producing a final IOC confidence assessment.

Potential integrations include:

- VirusTotal
- Additional IP reputation services
- Domain reputation intelligence
- URL reputation intelligence
- File hash intelligence

This will form ORION's multi-source threat intelligence enrichment layer.