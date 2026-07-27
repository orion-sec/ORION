# KB-023 — Threat Intelligence Enrichment and Reasoning Architecture

## Purpose

This article documents how ORION collects, normalizes, interprets, and uses external threat intelligence.

It captures the architectural lessons learned while enhancing the AbuseIPDB integration and validating the complete ORION V2 pipeline.

---

# Threat Intelligence in ORION

Threat intelligence is not only a reputation label.

A mature investigation platform must collect enough context to explain:

- What the infrastructure is
- Where it is located
- Who operates it
- How it is commonly used
- Whether it has been reported previously
- How recently it was reported
- Whether it is trusted, anonymous, or publicly routable
- What the evidence means for the investigation

ORION therefore separates threat intelligence into distinct responsibilities.

```text
External Provider
        ↓
Data Collection
        ↓
Normalization
        ↓
Threat Reasoning
        ↓
Contextual Risk
        ↓
Operational Decision
```

---

# Module Responsibilities

## `threat_intel.py`

Responsible for:

- Loading provider credentials securely
- Communicating with external APIs
- Applying request timeouts
- Handling unavailable services
- Parsing provider responses
- Normalizing provider-specific data
- Returning a consistent threat-intelligence object

It should not make final operational decisions.

---

## `threat_engine.py`

Responsible for:

- Interpreting normalized threat-intelligence evidence
- Correlating intelligence from one or more providers
- Evaluating suspicious and malicious indicators
- Producing an evidence-based verdict
- Explaining why the verdict was reached
- Supplying structured evidence to downstream risk stages

It should not perform external API communication.

---

## `context_risk.py`

Responsible for combining threat intelligence with investigation context, including:

- Business impact
- Identity context
- Asset importance
- Investigation evidence
- Threat reasoning
- Operational environment

Threat intelligence alone should not determine the final contextual risk.

---

## `operational_decision.py`

Responsible for converting contextual risk into an operational recommendation, such as:

- Close
- Monitor
- Investigate
- Escalate
- Contain
- Remediate

---

# AbuseIPDB Integration

ORION uses AbuseIPDB to enrich public IP addresses.

The API key is loaded from the environment:

```python
from dotenv import load_dotenv
import os

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
```

Secrets must never be:

- Hardcoded in source code
- Printed to the terminal
- Stored in Git
- Included in screenshots or documentation

---

# Normalized Threat Intelligence Object

ORION currently normalizes AbuseIPDB data into the following structure:

```python
{
    "ip": None,
    "source": "AbuseIPDB",
    "status": "Unavailable",
    "reputation": "Unknown",
    "confidence": 0,
    "reports": 0,
    "country_code": None,
    "country_name": None,
    "isp": None,
    "usage_type": None,
    "domain": None,
    "hostnames": [],
    "last_reported_at": None,
    "is_public": None,
    "ip_version": None,
    "is_whitelisted": None,
    "is_tor": None
}
```

The success and fallback responses use the same schema.

This prevents downstream modules from needing different logic for successful and failed lookups.

---

# Enrichment Fields

## Core Reputation

```text
reputation
confidence
reports
```

These fields describe the provider's assessment and report volume.

---

## Geographic Context

```text
country_code
country_name
```

These provide infrastructure location context.

Geography alone must not be treated as evidence of maliciousness.

---

## Infrastructure Ownership

```text
isp
domain
usage_type
hostnames
```

These fields help ORION identify whether an IP belongs to:

- Residential infrastructure
- Mobile infrastructure
- Hosting services
- Cloud providers
- Data centres
- Transit networks
- Corporate infrastructure

---

## Routing and Address Properties

```text
is_public
ip_version
```

These identify whether an address is publicly routable and whether it is IPv4 or IPv6.

Public status alone is not suspicious, but it is relevant when evaluating external exposure.

---

## Trust and Anonymity Indicators

```text
is_whitelisted
is_tor
```

A whitelisted result may reduce suspicion.

A Tor indicator may increase investigation priority, but it does not prove malicious activity.

---

## Reporting Recency

```text
last_reported_at
```

A recent report may be more operationally relevant than an old report.

Recency should be evaluated together with:

- Confidence score
- Number of reports
- Infrastructure type
- Investigation context

---

# Defensive API Handling

External APIs are unreliable by nature.

ORION must expect:

- Missing credentials
- Timeouts
- Rate limits
- HTTP errors
- Missing fields
- Invalid JSON
- Provider outages
- Changed response structures

The integration therefore uses defensive access patterns.

Preferred:

```python
payload = response.json()
data = payload.get("data", {})

confidence = data.get("abuseConfidenceScore", 0)
reports = data.get("totalReports", 0)
```

Avoid:

```python
data = response.json()["data"]
confidence = data["abuseConfidenceScore"]
```

Direct key access may raise a `KeyError` when an expected field is absent.

---

# Fallback Behaviour

When the API key is unavailable or the request fails, ORION returns a structured fallback object.

Example:

```python
{
    "source": "AbuseIPDB",
    "status": "Unavailable",
    "reputation": "Unknown"
}
```

This allows the pipeline to continue without pretending that threat intelligence was available.

A failed lookup must never be interpreted as a clean result.

---

# Collection Is Not Reasoning

Raw API fields are facts.

Examples:

```text
Country: China
Usage Type: Data Center/Web Hosting/Transit
Confidence: 0
Reports: 0
Whitelisted: False
Tor: False
```

These facts must not be converted into a verdict without analysis.

For example:

```text
Foreign country
        ≠
Malicious
```

```text
Cloud hosting provider
        ≠
Malicious
```

```text
No reports
        ≠
Trusted
```

Threat reasoning must evaluate the complete evidence set.

---

# Threat Reasoning Factors

The future Threat Intelligence Reasoning Engine should evaluate factors such as:

- Abuse confidence score
- Total reports
- Report recency
- Hosting or cloud infrastructure
- Residential infrastructure
- Tor usage
- Whitelisted status
- Public or private classification
- Provider agreement
- Provider disagreement
- Investigation behaviour
- Business context

---

# Evidence-Based Reasoning

A reasoning engine should produce structured evidence.

Example:

```python
{
    "verdict": "Suspicious",
    "confidence": "Medium",
    "score": 45,
    "evidence": [
        "IP belongs to a public cloud-hosting provider",
        "IP is not whitelisted",
        "The address was reported recently"
    ],
    "sources": 1
}
```

This is more valuable than returning only:

```python
{
    "verdict": "Suspicious"
}
```

The result must explain why the verdict was reached.

---

# Multi-Provider Architecture

Future providers may include:

- VirusTotal
- GreyNoise
- AlienVault OTX
- Microsoft Defender Threat Intelligence
- Cisco Talos
- CrowdStrike
- Darktrace
- Google SecOps

Each provider will return different data.

ORION should translate every provider response into a normalized internal structure before reasoning occurs.

```text
AbuseIPDB Response
        ↓
Provider Adapter
        ↓
ORION Threat Intelligence Schema

VirusTotal Response
        ↓
Provider Adapter
        ↓
ORION Threat Intelligence Schema
```

The rest of the pipeline should consume ORION's schema, not provider-specific JSON.

---

# Live Validation Result

The enriched AbuseIPDB integration was tested through the complete ORION V2 pipeline.

Validation result:

```text
Stages Executed: 12
Successful: 12
Failed: 0
Execution Status: SUCCESS
```

The test confirmed:

- Environment loading worked
- Authentication worked
- The API request succeeded
- The response was parsed
- Enrichment fields were normalized
- The Threat Intelligence stage received the data
- Downstream stages continued successfully
- No pipeline stages failed

---

# Architectural Principle

```text
Collection
        ↓
Normalization
        ↓
Reasoning
        ↓
Risk
        ↓
Decision
```

Each layer must have one clear responsibility.

This separation allows ORION to expand without tightly coupling providers, scoring logic, and operational actions.

---

# Engineering Lessons

- Verify whether a capability already exists before writing duplicate code.
- Validate existing integrations before enhancing them.
- External data must be normalized before downstream use.
- Success and fallback responses should share the same schema.
- Missing intelligence is not clean intelligence.
- Provider data must be treated as evidence, not truth.
- Geography alone must never determine maliciousness.
- API collection and threat reasoning should remain separate.
- Rich evidence enables explainable decisions.
- Modular architecture allows one stage to improve without breaking others.

---

# Next Engineering Objective

Transform `threat_engine.py` from a simple reputation counter into an evidence-based Threat Intelligence Reasoning Engine.

The first version should:

- Score normalized evidence
- Evaluate confidence and reports
- Interpret usage type
- Consider Tor and whitelist status
- Consider reporting recency
- Produce evidence statements
- Return a verdict, confidence level, score, source count, and explanation

---

## Summary

ORION has progressed from basic IP reputation lookup to structured threat-intelligence enrichment.

The next stage is to convert enriched facts into explainable security reasoning that can improve contextual risk assessment and operational decisions.