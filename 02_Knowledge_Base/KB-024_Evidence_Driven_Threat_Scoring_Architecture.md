# KB-024 — Evidence Driven Threat Scoring Architecture

---

# Purpose

This document describes the architectural evolution of ORION's Threat Intelligence engine from binary reputation checks to evidence-driven threat scoring.

---

# Previous Design

Initially, ORION classified threat intelligence using a simple reputation check.

Threat Feed
↓

Reputation

↓

Verdict

Only explicit "Malicious" classifications influenced the investigation.

This approach ignored valuable contextual intelligence such as infrastructure type, hosting providers, public exposure, and reporting history.

---

# New Architecture

The Threat Intelligence workflow now consists of four independent responsibilities.

Threat Intelligence

↓

Threat Enrichment

↓

Evidence Collection

↓

Threat Scoring

↓

Threat Correlation

↓

Investigation Verdict

Each responsibility has a single purpose.

---

# Threat Enrichment

Threat enrichment collects normalized intelligence from external providers.

Current provider:

- AbuseIPDB

Collected fields include:

- Reputation
- Abuse Confidence
- Reports
- Country
- ISP
- Usage Type
- Domain
- Hostnames
- Last Reported
- Public Status
- IP Version
- Whitelisted Status
- Tor Indicator

Future providers should normalize into the same structure.

---

# Evidence Collection

Evidence collection extracts meaningful investigative observations without making decisions.

Examples:

- Infrastructure hosted within a data centre.
- Publicly routable IP address.
- Recently reported malicious infrastructure.
- Tor exit node.
- Whitelisted infrastructure.

Evidence supports later reasoning stages while preserving analyst visibility.

---

# Threat Scoring

Threat scoring converts normalized intelligence into a numerical score.

Current scoring evaluates:

- Reputation
- Abuse Confidence
- Reports
- Infrastructure Type
- Public Exposure
- Tor Status
- Whitelisted Status

Scores are cumulative rather than binary.

---

# Threat Correlation

Threat Correlation no longer determines verdicts by counting malicious reputation responses.

Instead it evaluates:

- Total Threat Score
- Supporting Evidence
- Number of Intelligence Sources

This allows multiple intelligence providers to contribute independently.

---

# Benefits

This architecture provides several advantages.

- Better separation of responsibilities.
- Easier testing.
- Improved explainability.
- Reusable scoring engine.
- Easier future integrations.
- Vendor-neutral threat intelligence model.

---

# Future Expansion

Additional intelligence providers can integrate without redesigning ORION.

Examples include:

- VirusTotal
- GreyNoise
- Shodan
- Microsoft Threat Intelligence
- AlienVault OTX
- URLhaus
- Abuse.ch

Each provider should:

1. Normalize its response.
2. Generate evidence.
3. Produce a threat score.

The Threat Correlation engine remains unchanged.

---

# Engineering Principle

Threat intelligence should not be treated as a binary reputation lookup.

Threat intelligence should be evaluated as accumulated evidence contributing to an explainable investigation score.