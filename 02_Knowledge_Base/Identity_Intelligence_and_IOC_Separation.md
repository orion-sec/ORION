# ORION Knowledge Base

## Day 18 – Identity Intelligence and Evidence Separation

---

# Key Lesson

A security investigation should distinguish between different categories of information rather than treating every extracted value as an IOC.

---

# Identity vs Infrastructure

Before Day 18, ORION treated all extracted values as indicators.

This created situations where parts of an email address could be incorrectly interpreted as DNS domains.

Example:

john.smith@contoso.com

Identity:

john.smith@contoso.com

Infrastructure:

contoso.com

The local portion:

john.smith

is neither an identity nor a domain.

Separating these concepts improves investigation accuracy.

---

# Stable Data Models

A stable data model should be designed before connecting external data sources.

The Identity Engine already returns:

- Display Name
- Email
- Department
- Manager
- Role
- Privilege
- Risk

Although many fields currently contain placeholder values, downstream modules already understand the structure.

Future Microsoft Graph integration can populate the same model without changing other components.

---

# Preserve Evidence

Original investigation text should remain unchanged whenever possible.

Rather than modifying evidence, ORION creates temporary working copies for extraction.

This preserves evidence integrity while allowing smarter interpretation.

---

# Modular Investigation Pipeline

Current investigation flow:

Investigation

↓

IOC Extraction

↓

Identity Extraction

↓

IOC Enrichment

↓

Threat Intelligence

↓

Threat Correlation

↓

Behaviour Analysis

↓

Attack Pattern Detection

↓

MITRE ATT&CK

↓

Contextual Risk

↓

Response Playbooks

Each stage performs one responsibility before passing structured information to the next module.

---

# Explainable Decision Making

Contextual Risk Assessment introduced explainable security decisions.

Instead of simply returning:

Critical

ORION now records the evidence responsible for the decision.

Example:

- Credential submission
- MFA changes
- Mailbox rules
- Suspicious authentication
- Sensitive mailbox access

Providing supporting evidence improves analyst confidence and future auditability.

---

# Architecture Principle Learned

Identity Intelligence and Infrastructure Intelligence should remain independent.

Identity Intelligence focuses on:

- Users
- Departments
- Managers
- Privilege
- Risk

Infrastructure Intelligence focuses on:

- URLs
- Domains
- IP Addresses
- Hashes

Keeping these concepts separate results in cleaner investigations and more maintainable software.

---

# Engineering Principle

Never modify evidence unless absolutely necessary.

Instead:

- Improve extraction.
- Improve interpretation.
- Preserve the original investigation.

---

# Long-Term Benefit

Separating identity from infrastructure creates a scalable architecture that will support:

- Microsoft Graph
- Active Directory
- Defender XDR
- CrowdStrike
- ServiceNow
- Cloud investigations

without requiring major redesign of the investigation pipeline.

---

# Day 18 Summary

Major achievements:

✔ Contextual Risk Assessment

✔ Identity Engine Version 1

✔ Identity reporting

✔ Domain extraction refinement

✔ IOC Coverage Roadmap

✔ Clear separation between identity and infrastructure intelligence

Day 18 marks the point where ORION evolved from an IOC parser into a structured investigation platform capable of reasoning about users, infrastructure, behaviour and risk independently.