# Operational Decision Architecture

## Purpose

Operational decisions should not be based solely on technical evidence.

A mature security platform separates:

- Technical Risk
- Business Context
- Operational Decisions

Each represents a distinct stage of the investigation lifecycle.

---

## Investigation Layers

### IOC Extraction

Answers:

What indicators exist?

Examples:

- IP Addresses
- URLs
- Hashes
- Domains
- Email Addresses

---

### Identity

Answers:

Who is involved?

Outputs:

- Primary User
- Email Addresses
- Identity Count

---

### Identity Enrichment

Answers:

Who is this person?

Outputs:

- Department
- Manager
- Role
- Job Title
- Country
- Office
- Privilege
- VIP Status
- Criticality
- Device Count

---

### Business Impact

Answers:

How important is the affected identity?

Evaluation factors:

- Privilege
- VIP Status
- Criticality
- Leadership
- Department
- Account Type
- Device Ownership

Outputs:

- Impact Score
- Impact Level
- Confidence
- Escalation Recommendation

---

### Contextual Risk

Answers:

How dangerous is the observed security activity?

Evaluation considers:

- Credential Theft
- Authentication Changes
- Inbox Rules
- Suspicious Sign-ins
- Sensitive Data Access

Outputs:

- Risk Score
- Severity
- Containment Recommendation
- Evidence

---

### Operational Decision

Answers:

Given both security evidence and business context...

What should the SOC do?

Inputs:

Contextual Risk

+

Business Impact

Outputs:

- Operational Decision
- Priority
- Automation Readiness
- Recommended Actions
- Decision Rationale

---

## Architectural Principle

Contextual Risk

≠

Business Impact

Technical severity and organisational importance must remain independent.

They are combined only when producing an operational decision.

---

## Single Responsibility Principle

Identity Engine

↓

Extracts identities.

Identity Enrichment

↓

Provides organisational context.

Business Impact

↓

Evaluates organisational importance.

Operational Decision

↓

Produces SOC recommendations.

Response Playbooks

↓

Describe how analysts should execute the decision.

Each module owns one responsibility.

---

## Benefits

This architecture provides:

- Explainable decision making
- Modular design
- Easier testing
- Enterprise scalability
- Future Microsoft Graph integration
- Future CMDB integration
- Future HR integration
- Future AI reasoning

---

## Future Evolution

Rule-Based Decision Engine

↓

Evidence Reasoning Engine

↓

Automation Engine

↓

Security Copilot

↓

Autonomous SOC

The rule-based layer provides predictable and auditable decisions.

The Evidence Reasoning Engine will later augment these recommendations using broader contextual evidence while preserving explainability.