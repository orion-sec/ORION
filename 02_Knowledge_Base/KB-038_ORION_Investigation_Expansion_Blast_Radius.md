# KB-038 — ORION Investigation Expansion and Blast Radius Architecture

## Purpose

ORION investigation expansion determines whether entities discovered during an independent security investigation are associated with additional activity elsewhere in the monitored environment.

The objective is to move beyond alert-centric investigation toward environment-aware incident analysis.

## Architecture

Security Incident
        ↓
Entity Extraction
        ↓
Entity Correlation
        ↓
Environment Search
        ↓
Environment Evidence
        ↓
Investigation Expansion
        ↓
Blast Radius
        ↓
Evidence Reasoning
        ↓
Operational Decision

## Entity Correlation

ORION converts investigation artifacts into normalized correlation pivots.

Supported entities currently include:

- user
- ip
- device
- file_hash
- domain
- url

Example:

{
    "type": "file_hash",
    "value": "<SHA256>"
}

Provider-specific search logic can then consume these vendor-neutral pivots.

## Environment Search

Environment search looks for additional telemetry associated with the correlation entities.

Original alert evidence and environment-discovered evidence remain logically separated to preserve evidence provenance.

## Investigation Expansion

The investigation expansion layer converts related environment evidence into a normalized entity map.

Example:

{
    "users": [...],
    "ips": [...],
    "devices": [...],
    "file_hashes": [...],
    "domains": [...],
    "urls": [...]
}

It also determines:

- Whether expansion occurred
- Number of affected entities
- Related entities discovered

## Blast Radius

Blast-radius assessment summarizes the wider scope of the investigation.

Current outputs include:

- expanded
- affected_entity_count
- active_categories
- scope
- per-category counts

This allows downstream reasoning and response logic to distinguish isolated activity from activity involving multiple identities, systems, or indicators.

## Live Validation

The architecture was validated against live Microsoft Sentinel incidents.

A suspicious identity incident resulted in five related environment evidence records.

ORION expanded those records into:

- 1 user
- 2 IP addresses
- 1 device

Total affected entities:

4

Scope:

Multi-Entity

This demonstrated the complete path:

Sentinel
→ Entity Correlation
→ Environment Search
→ Investigation Expansion
→ Blast Radius

## Design Principle

ORION should not require an analyst to manually pivot between multiple security consoles for routine investigation enrichment.

Providers should retrieve the required telemetry and threat intelligence, normalize it into ORION evidence models, and make that evidence available to the reasoning and decision layers.

## Next Architecture Extension

VirusTotal threat-intelligence integration.

Target flow:

IOC Extraction
→ VirusTotal Provider
→ IOC Reputation
→ Normalized Threat Intelligence Evidence
→ Threat Correlation
→ Investigation Reasoning
→ Analyst Decision Support

This establishes the foundation for future enrichment from additional security platforms.