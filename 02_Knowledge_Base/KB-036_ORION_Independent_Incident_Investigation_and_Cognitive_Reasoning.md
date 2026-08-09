# KB-036 â€” ORION Independent Incident Investigation and Cognitive Reasoning

## Purpose

This document defines how ORION processes incoming security alerts and incidents independently while using environmental correlation as investigation enrichment.

---

## 1. Core Architectural Principle

ORION follows this rule:

> **One incoming alert or incident creates one independent investigation context.**

Multiple alerts must not automatically be combined simply because they were collected during the same polling cycle or originated from the same security platform.

This reflects the way a real SOC alert queue operates.

Each alert enters the investigation workflow independently and receives its own:

- Evidence
- Findings
- Investigation questions
- Hypotheses
- Risk assessment
- Business impact assessment
- Operational decision
- Disposition

---

## 2. Why Investigation Isolation Matters

Enterprise SOC environments continuously generate alerts from platforms such as:

- Microsoft Sentinel
- Microsoft Defender XDR
- CrowdStrike
- Google SecOps
- Splunk
- Darktrace

These alerts normally enter investigation queues.

Each alert must initially be treated as its own security problem until evidence establishes a meaningful relationship with another event.

ORION therefore separates two concepts:

```text
INVESTIGATION
     !=
CORRELATION
```

Investigation determines what happened within the current alert.

Correlation searches the wider environment for related activity.

---

## 3. Independent Investigation Architecture

```text
Security Provider
       |
       v
Incoming Alert / Incident
       |
       v
Provider Normalisation
       |
       v
SecurityIncident
       |
       v
Independent Investigation Context
       |
       +--> Evidence Collection
       |
       +--> Entity Extraction
       |
       +--> Evidence Reasoning
       |
       +--> Findings
       |
       +--> Investigation Questions
       |
       +--> Hypotheses
       |
       +--> Contextual Risk
       |
       +--> Business Impact
       |
       v
Operational Decision
```

Each pipeline execution must remain isolated from other investigations.

For example:

```text
Alert 001 -> Investigation 001

Alert 002 -> Investigation 002

Alert 003 -> Investigation 003
```

ORION must not create:

```text
Alert 001
Alert 002  ---> One Combined Investigation
Alert 003
```

unless later correlation evidence demonstrates that the events genuinely belong to the same security case.

---

## 4. Vendor-Neutral Incident Normalisation

Provider-specific incidents are converted into ORION's internal security models before cognitive reasoning occurs.

For Microsoft Sentinel:

```text
Microsoft Sentinel Incident
            |
            v
Sentinel Incident Factory
            |
            v
SecurityIncident
```

The vendor-neutral `SecurityIncident` model can contain:

- Incident ID
- Title
- Severity
- Status
- Created timestamp
- Source provider
- Source product
- MITRE ATT&CK tactics
- MITRE ATT&CK techniques
- Entities
- Associated alerts
- Raw provider metadata

This allows downstream ORION components to operate without being tightly coupled to Microsoft Sentinel.

The same architecture can later support other security providers.

---

## 5. Evidence Reasoning Architecture

Provider evidence is transformed into investigation findings through specialised reasoners.

Current reasoning areas include:

```text
Infrastructure
Network
Authentication
Identity
Identity Risk
Conditional Access
Device Trust
Device Compliance
Endpoint
Process
File
File Hash
Malware
```

The architecture follows:

```text
Raw Evidence
      |
      v
Evidence Reasoner
      |
      v
Finding
```

Reasoners analyse evidence.

Factories create the resulting cognitive objects.

This separation keeps ORION modular, auditable and testable.

---

## 6. ORION Cognitive Investigation Pipeline

ORION's cognitive pipeline processes investigation evidence through several stages:

```text
Evidence
   |
   v
Findings
   |
   v
Investigation Questions
   |
   v
Hypotheses
   |
   v
Investigation Outcome
```

The objective is not simply to classify an alert.

ORION should progressively answer:

```text
What happened?

What evidence supports it?

What remains unknown?

What alternative explanations exist?

What additional evidence is required?

How confident are we?

What should happen next?
```

This forms the foundation of ORION's analyst-like investigation capability.

---

## 7. Investigation Question Generation

Findings generate investigation questions that identify missing information.

For example:

```text
Finding:
Suspicious process execution observed.

Questions:

- What was the parent process?
- What command line was executed?
- Was the executable signed?
- Is the executable known to be malicious?
- Did the process establish network connections?
```

Question deduplication prevents repeated findings from creating identical investigation questions.

This keeps the investigation plan concise while still preserving the underlying evidence.

---

## 8. Operational Decision Model

The final operational decision must not rely solely on the severity assigned by the originating security product.

ORION considers several signals:

```text
Provider Severity
       +
Contextual Risk
       +
Business Impact
       +
Investigation Findings
       +
Cognitive Outcome
       =
Operational Decision
```

Potential operational outcomes include:

```text
Auto-Close

Monitor

Analyst Review

Escalation

Priority Escalation

Containment Approval
```

---

## 9. Auto-Close Guardrail

A low-severity alert is not automatically benign.

ORION should only auto-close an alert when sufficient investigation evidence supports that decision.

Example:

```text
Provider Severity = Low

Evidence = Incomplete

Cognitive Outcome = Needs Human Review

Operational Result:

AUTO-CLOSE BLOCKED
```

This protects against malicious activity being incorrectly closed simply because the originating security product assigned a low severity.

The desired future behaviour is:

```text
Low Fidelity
+
Strong Benign Evidence
+
No Significant Correlation
+
No Unresolved Investigation Questions
        |
        v
AUTO-CLOSE ELIGIBLE
```

Otherwise:

```text
Uncertainty / Suspicious Evidence
        |
        v
ESCALATE FOR REVIEW
```

---

## 10. Environment-Wide Correlation

Correlation will operate as an enrichment capability rather than automatically combining alerts.

After ORION extracts useful entities and indicators from an investigation, it can search the wider customer environment.

```text
Independent Investigation
          |
          v
IOC / Entity Extraction
          |
          v
Environment Search
          |
          +--> Historical Alerts
          |
          +--> Current Alerts
          |
          +--> Endpoint Telemetry
          |
          +--> Identity Activity
          |
          +--> Network Activity
          |
          +--> Email Activity
          |
          +--> Threat Intelligence
          |
          v
Correlation Evidence
```

Potential correlation keys include:

- IP addresses
- Domains
- URLs
- File hashes
- Users
- Hosts
- Processes
- Mailboxes
- Applications
- MITRE ATT&CK techniques
- Temporal relationships

---

## 11. Correlation Does Not Automatically Mean Merging

Finding a relationship does not automatically merge investigations.

ORION should maintain:

```text
Investigation A

Investigation B

Investigation C
```

while recording relationships such as:

```text
Investigation A
      |
      | Same SHA256
      |
Investigation B
```

or:

```text
Investigation B
      |
      | Same malicious IP
      |
Investigation C
```

This allows ORION to say:

> The current alert is being investigated independently, but the same indicator has been observed elsewhere in the environment.

Only sufficiently strong relationships should justify creating a parent case, campaign-level investigation, or coordinated incident.

---

## 12. Intended Enterprise SOC Workflow

The target ORION operating model is:

```text
                     ALERT QUEUE
                          |
                          v
                        ORION
                          |
                          v
              Independent Investigation
                          |
          +---------------+---------------+
          |               |               |
          v               v               v
      Evidence        Enrichment     Environment Search
          |                               |
          +---------------+---------------+
                          |
                          v
                      Correlation
                          |
                          v
                  Cognitive Reasoning
                          |
                          v
                    Risk Assessment
                          |
                          v
                    Business Impact
                          |
                          v
                      Disposition
                          |
               +----------+----------+
               |                     |
               v                     v
       BENIGN / LOW FIDELITY   SUSPICIOUS / MALICIOUS
               |                     |
               v                     v
           AUTO-CLOSE             ESCALATE
                                     |
                                     v
                              SENIOR ANALYST
                                     |
                                     v
                           APPROVE REMEDIATION
                                     |
                                     v
                                   ORION
                                     |
                                     v
                            EXECUTE RESPONSE
```

---

## 13. Tier 1 / Tier 2 Automation Objective

ORION is intended to automate repetitive investigation work normally performed across Tier 1 and selected Tier 2 SOC functions.

For routine alerts, ORION should eventually be capable of:

1. Receiving the alert.
2. Creating an independent investigation.
3. Collecting relevant evidence.
4. Extracting entities and IOCs.
5. Enriching those indicators.
6. Searching the wider environment.
7. Identifying meaningful correlations.
8. Generating findings.
9. Generating investigation questions.
10. Building competing hypotheses.
11. Assessing contextual risk.
12. Assessing business impact.
13. Determining a disposition.
14. Auto-closing sufficiently proven benign alerts.
15. Escalating suspicious or malicious activity.
16. Presenting the senior analyst with the evidence and recommended remediation.
17. Executing remediation after approval where required.

The senior analyst should therefore receive an investigation that is already evidence-rich rather than starting investigation from scratch.

---

## 14. Current Validation State

Current regression validation:

```powershell
ruff check .
```

Result:

```text
All checks passed!
```

Full test suite:

```powershell
python -m pytest -q
```

Result:

```text
23 passed
```

Independent Microsoft Sentinel investigation execution has now been incorporated into the ORION architecture.

---

## 15. Future Engineering Work

Planned capabilities include:

1. Environment-wide IOC and entity search.
2. Correlation engine.
3. Correlation confidence scoring.
4. Historical incident relationship analysis.
5. Dedicated phishing/BEC investigation capability.
6. Expanded hypothesis reasoning.
7. Improved confidence scoring.
8. Auto-close eligibility engine.
9. Remediation approval workflow.
10. Dashboard investigation queue.
11. Analyst-facing evidence packages.
12. Cross-provider correlation.

---

## Architectural Rule

> **Investigate independently. Search globally. Correlate based on evidence. Merge only when justified.**
