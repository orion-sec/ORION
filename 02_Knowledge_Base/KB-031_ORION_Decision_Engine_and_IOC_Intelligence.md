# ORION Knowledge Base

# Decision Engine v1.0

---

## Purpose

The Decision Engine converts cognitive investigation outputs into deterministic investigation outcomes.

Unlike rule-based automation, the engine combines:

- Investigation hypotheses
- Weighted confidence assessment
- Verified investigation context

before assigning a final disposition.

---

## Investigation Flow

Evidence

↓

Findings

↓

Questions

↓

Hypotheses

↓

Confidence Engine

↓

Decision Engine

↓

Investigation Outcome

↓

Incident Narrative

↓

IOC Intelligence

---

## Supported Investigation Outcomes

- True Positive
- False Positive
- Benign Positive
- Suspicious
- Authorized Security Testing
- Authorized Administrative Activity
- Policy Violation
- Misconfiguration
- Infrastructure Issue
- Business Risk
- Threat Hunt Candidate
- Needs Human Review
- Insufficient Evidence

---

## Confidence Signals

Current signals:

- Evidence Strength
- Identity Risk
- Threat Intelligence Risk
- Hypothesis Support
- Business Context Risk
- Historical Behaviour Risk
- Detection Quality

Signals are normalized between 0–100 before weighted calculation.

---

## Decision Context

The engine accepts deterministic investigation facts including:

- confirmed_malicious
- detection_incorrect
- activity_authorized
- policy_violation
- misconfiguration
- infrastructure_issue
- business_risk
- threat_hunt_candidate
- requires_human_review
- insufficient_evidence

This allows deterministic reasoning instead of threshold-only classification.

---

## Incident Narrative

Automatically generates:

- Executive Summary
- Analyst Verdict
- Severity
- Confidence
- Disposition
- Key Evidence

---

## IOC Intelligence Engine

Supports:

- URL
- IP Address
- Domain
- File Hash
- Email
- User
- Device

Outputs:

- Classification
- Risk Level
- Confidence
- Threat Family
- Intelligence Sources
- Related Entities
- MITRE ATT&CK Mapping
- Recommended Actions

---

## Design Principle

ORION separates:

Reasoning

from

Execution.

The Decision Engine determines:

"What should happen."

Future integrations determine:

"How it happens."

This allows safe human approval before automated remediation.

---

## Engineering Outcome

Decision Engine v1.0 is complete.

The platform is now prepared for real-world telemetry ingestion through Microsoft Graph and additional security APIs.