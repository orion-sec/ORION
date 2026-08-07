# Microsoft Entra Sign-In Evidence Reasoning in ORION

## Purpose

This knowledge-base article documents how ORION converts Microsoft Entra sign-in telemetry into structured investigation findings.

---

## Core Principle

Security telemetry should not directly determine an incident verdict.

ORION separates:

Telemetry → Evidence → Findings → Correlation → Decision

Each layer has a different responsibility.

---

## Telemetry

Telemetry is information received from an external security platform.

For Microsoft Entra ID this may include:

- User identity
- IP address
- Application
- Authentication result
- Risk level
- Conditional Access state
- Device information
- Location
- User agent
- Correlation ID

External telemetry should not become tightly coupled to ORION's reasoning engine.

---

## Evidence

External telemetry is normalized into ORION's internal evidence models.

Microsoft Entra authentication events are represented using:

SignInEvidence

This creates a stable security abstraction between Microsoft and ORION's investigation logic.

Provider/API changes therefore do not necessarily require changes throughout the reasoning architecture.

---

## Provider Responsibility

The SignInEvidenceProvider is responsible for retrieving authentication telemetry.

Providers should collect evidence.

Providers should not determine whether an incident is malicious.

This separation prevents collection logic from becoming mixed with investigation logic.

---

## Factory Responsibility

Factories convert provider-specific responses into ORION's internal models.

The SignInEvidence factory transforms Microsoft authentication records into SignInEvidence objects.

Factories therefore provide the normalization boundary between external telemetry and internal investigation evidence.

---

## Investigation Aggregate

Evidence is attached to the Investigation object.

The Investigation object acts as the shared state for the investigation lifecycle.

Instead of every investigation component independently querying external platforms, later stages operate against the accumulated investigation state.

This supports:

- Repeatable investigations
- Evidence correlation
- Testing
- Reporting
- Decision support
- Future automation

---

## Reasoner Responsibility

Reasoners interpret evidence.

The sign-in reasoner currently evaluates areas including:

### Authentication

Failed authentication attempts can produce Authentication findings.

### Identity Risk

Microsoft Entra risk information can produce Identity Risk findings.

### Conditional Access

Missing Conditional Access enforcement can produce Conditional Access findings.

### Device Trust

Authentication from an unmanaged device can produce Device Trust findings.

### Device Compliance

Authentication from a non-compliant device can produce Device Compliance findings.

---

## Findings Are Not Verdicts

A Finding represents an analyst-relevant observation.

For example:

Conditional Access was not applied.

This does NOT automatically mean:

The account is compromised.

A finding must be evaluated alongside other evidence.

This distinction is critical to reducing false positives.

---

## Why Correlation Matters

Consider these observations independently:

- Conditional Access not applied
- Login from new IP
- Unmanaged device
- High Entra risk
- Suspicious hosting-provider IP

Individually, some signals may have limited confidence.

Together they may represent a materially stronger indication of account compromise.

Therefore ORION's reasoning architecture should progressively move toward:

Evidence
    ↓
Findings
    ↓
Correlation
    ↓
Confidence Assessment
    ↓
Investigation Decision

---

## Typed Evidence and Legacy Evidence

ORION currently supports both:

1. Typed security evidence such as SignInEvidence.
2. Existing dictionary-based evidence such as Network and Infrastructure evidence.

The unified evidence reasoning layer determines the evidence type and routes it to the appropriate reasoner.

This allows ORION to evolve incrementally without breaking existing investigation capabilities.

---

## Design Rule

A useful architectural rule for future ORION development is:

**Providers collect.  
Factories normalize.  
Models represent.  
Reasoners interpret.  
Correlators connect.  
Decision engines decide.  
Playbooks respond.**

Maintaining these boundaries will help prevent the investigation pipeline from becoming tightly coupled as additional security platforms are integrated.

---

## Current Capability

As of Day 36, ORION has demonstrated the following live flow:

Microsoft Entra ID
→ Sign-In Provider
→ SignInEvidence
→ Investigation Aggregate
→ Evidence Reasoning
→ Sign-In Reasoner
→ Finding

This capability has been validated against live Microsoft Entra telemetry.

---

## Next Evolution

The next architectural requirement is cross-evidence correlation.

The correlation layer should determine whether multiple independent findings reinforce or contradict one another.

Future examples include:

Entra Risk + Threat Intelligence

IP Reputation + Hosting Infrastructure

Device Trust + Authentication Behaviour

Identity Privilege + Suspicious Authentication

Conditional Access + Device Compliance

The objective is not merely to generate more alerts.

The objective is to generate better-supported security conclusions.