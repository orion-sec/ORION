# ORION Knowledge Base
## Entity Correlation and Environment Search Architecture

### Purpose

ORION's Entity Correlation and Environment Search architecture allows an investigation to expand beyond the evidence contained in the original security alert.

Instead of treating alerts as isolated objects, ORION extracts reusable security pivots and searches the wider environment for related activity.

---

## Core Principle

ORION separates:

1. Investigation evidence
2. Entity correlation
3. Environment searching

This prevents uncontrolled environment searches while allowing investigations to expand when relevant entities are discovered.

---

## Investigation Flow

Security Alert / Incident
        ↓
Evidence Collection
        ↓
Entity Extraction
        ↓
Entity Correlation
        ↓
Correlation Keys
        ↓
Environment Search
        ↓
Related Telemetry
        ↓
Blast-Radius Analysis
        ↓
Investigation Reasoning

---

## Correlation Keys

A correlation key represents an entity or indicator that can be used to search for related activity.

Supported pivots currently include:

| Entity Type | Example | Investigation Purpose |
|---|---|---|
| User | user@company.com | Identity activity |
| IP | 185.10.20.30 | Network/sign-in correlation |
| Device | HOST-001 | Endpoint correlation |
| File Hash | SHA-256 | Malware/file prevalence |
| Domain | malicious-example.com | Domain activity |
| URL | https://example.com/path | Web/phishing correlation |

---

## Entity Correlator

Component:

`correlation/entity_correlator.py`

Responsibility:

Extract and normalize investigation entities into correlation keys.

Conceptual output:

{
    "search_required": true,
    "correlation_keys": [
        {
            "type": "user",
            "value": "user@company.com"
        },
        {
            "type": "ip",
            "value": "185.10.20.30"
        }
    ]
}

The correlator determines WHAT should be searched.

It does not need to know HOW the underlying security platform performs that search.

---

## Environment Search Provider

Component:

`providers/environment_search_provider.py`

Responsibility:

Translate correlation pivots into telemetry searches.

Conceptually:

user
→ identity/sign-in search

ip
→ IP-related telemetry search

device
→ endpoint/device search

file_hash
→ Defender endpoint telemetry

domain
→ domain telemetry

url
→ URL telemetry

The provider therefore determines HOW the wider environment is searched.

---

## Why This Separation Matters

Without this architecture, investigation logic could become tightly coupled to individual Microsoft APIs and KQL queries.

Instead:

Correlation Layer
        ↓
Normalized Pivot
        ↓
Environment Search Provider
        ↓
Telemetry Platform

This makes future integrations easier.

For example:

Microsoft Sentinel
CrowdStrike
Google SecOps
Darktrace
Splunk

could eventually implement their own environment-search mechanisms while ORION continues using normalized investigation pivots.

---

## Investigation Isolation

Environment searching must be pivot-driven.

ORION should not automatically retrieve large quantities of unrelated tenant telemetry and attach it to an investigation.

The preferred model is:

Known Evidence
→ Extract Pivot
→ Search Pivot
→ Evaluate Related Activity
→ Expand Investigation

This reduces accidental cross-contamination between unrelated investigations.

---

## SOC Example

Assume Microsoft Sentinel creates an incident containing:

User:
finance.user@company.com

IP:
185.10.20.30

ORION extracts both entities.

The environment-search layer can then investigate:

Where else has this IP authenticated?

Which devices has this user accessed?

Does endpoint telemetry show suspicious activity associated with those devices?

Were malicious domains or URLs contacted?

Does the same file hash exist on other endpoints?

The investigation can therefore evolve from:

"One suspicious login"

into:

"Determine the complete identity, endpoint and IOC blast radius."

---

## Current Validation

The architecture has automated test coverage for:

- Entity correlation
- User routing
- IP routing
- Device routing
- File-hash routing
- Domain routing
- URL routing
- Pipeline correlation
- Pipeline environment searching
- Correlation → environment-search integration

Current validated test state:

36 passed
3 skipped

Ruff:

All checks passed.

---

## Architectural Direction

This capability forms the foundation for future:

- Blast-radius analysis
- IOC prevalence searching
- Automated threat hunting
- Cross-provider correlation
- Investigation graph construction
- Attack-path reconstruction
- MITRE ATT&CK correlation
- Risk scoring
- Automated containment recommendations
- Human-approved response actions

The long-term ORION investigation model therefore becomes:

DETECT
   ↓
COLLECT
   ↓
CORRELATE
   ↓
SEARCH
   ↓
EXPAND
   ↓
REASON
   ↓
DECIDE
   ↓
RESPOND