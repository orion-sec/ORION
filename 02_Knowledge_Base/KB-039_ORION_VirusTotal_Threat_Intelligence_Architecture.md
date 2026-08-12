# KB — VirusTotal Threat Intelligence Architecture

## Purpose

VirusTotal provides external IOC reputation and detection intelligence to ORION.

## Architecture

Security Incident
→ IOC Extraction
→ Entity Correlation
→ Indicator Intelligence Stage
→ VirusTotalProvider
→ VirusTotalClient
→ VirusTotal API
→ VirusTotal Normalizer
→ IndicatorProfile
→ Investigation Aggregate

## Supported Indicators

- File Hash
- Domain
- URL
- IP Address

## Security Design

VirusTotal credentials are loaded from environment configuration.

Secrets must never be hardcoded or committed to source control.

`.env` remains excluded through `.gitignore`.

## Failure Handling

VirusTotal enrichment is designed to degrade gracefully.

An unavailable external intelligence source should produce structured unavailable/error evidence rather than unnecessarily destroying the entire investigation workflow.

## Testing Strategy

Unit/regression tests do not require live VirusTotal access.

Live VirusTotal execution is explicitly controlled through:

ORION_RUN_LIVE_VIRUSTOTAL=1

This prevents accidental VirusTotal API consumption during normal testing.

## Current Limitation

Indicator Intelligence exists as a separate evidence source but is not yet fully incorporated into ORION's cognitive confidence and contextual risk calculations.

Future architecture:

Indicator Intelligence
→ Evidence Reasoning
→ Cognitive Investigation
→ Contextual Risk
→ Operational Decision

## Validated Baseline

Day 41:

- Pipeline stages: 22
- Regression: 50 passed / 4 skipped
- Ruff: All checks passed
- Live Sentinel → VirusTotal enrichment: Successful