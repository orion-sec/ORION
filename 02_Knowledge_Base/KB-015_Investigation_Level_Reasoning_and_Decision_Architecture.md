# Investigation-Level Reasoning and Decision Architecture

## ORION Knowledge Base

---

## 1. Purpose

This document explains the difference between IOC-level analysis and investigation-level reasoning within ORION.

The purpose of the investigation-level reasoning layer is to combine multiple security signals into a contextual assessment of an entire investigation.

Security investigations should not be closed or escalated based only on the reputation of a single IOC.

An investigation may contain:

- Clean IP addresses.
- Suspicious URLs.
- Suspicious domains.
- Identity anomalies.
- Endpoint activity.
- Threat intelligence findings.
- Multiple weak signals that become meaningful when correlated.

ORION therefore separates individual IOC assessment from overall investigation assessment.

---

## 2. Core Principle

**An IOC is evidence. An investigation is the interpretation of all available evidence together.**

For example:

A public IP may have:

- No current malicious reputation.
- A low risk score.
- No confirmed malicious threat intelligence.

However, the same investigation may also contain:

- A suspicious authentication URL.
- A suspicious domain.
- An unusual sign-in.
- Endpoint activity.
- Additional related indicators.

The IP result should remain clean or low risk.

However, the overall investigation may still require further investigation.

ORION must preserve both conclusions without allowing one to overwrite the other.

---

## 3. Two-Layer Decision Model

ORION uses two decision layers.

### Layer 1 — IOC-Level Analysis

IOC-level analysis evaluates individual indicators.

Examples:

- IP address.
- URL.
- Domain.
- File hash.
- Email address.

The IOC layer may produce:

- Risk classification.
- Risk score.
- Reputation.
- Confidence.
- Recommended IOC actions.
- IOC priority.

Example:

IP: `8.8.8.8`

Result:

- Risk: Low.
- Score: 20.
- Threat Intelligence: Clean.
- IOC Priority: P3.

This result describes the IP only.

---

### Layer 2 — Investigation-Level Analysis

Investigation-level analysis combines evidence from multiple sources.

Inputs may include:

- IP risk results.
- URL risk results.
- Domain intelligence.
- Threat intelligence correlation.
- Identity context.
- Endpoint telemetry.
- Email telemetry.
- Historical activity.
- Asset criticality.

The investigation layer produces:

- Overall verdict.
- Confidence.
- Strong signal count.
- Suspicious signal count.
- Evidence score.
- Investigation recommendations.
- Overall investigation priority.

This result describes the case as a whole.

---

## 4. Investigation Reasoning Pipeline

The current ORION reasoning pipeline is:

Extract  
→ Enrich  
→ Score  
→ Threat Intelligence  
→ Correlate  
→ Assess Investigation  
→ Recommend  
→ Prioritise  
→ Display

Each stage has a separate responsibility.

---

## 5. Extraction Layer

The extraction layer identifies security-relevant indicators from investigation text.

Current supported indicators include:

- URLs.
- IP addresses.
- MD5 hashes.
- SHA1 hashes.
- SHA256 hashes.
- Email addresses.
- Domains.

The extraction layer does not decide whether an IOC is malicious.

Its responsibility is identification.

---

## 6. Enrichment Layer

The enrichment layer adds context to extracted indicators.

Examples include:

### IP Enrichment

- IP version.
- Private or public status.
- Global status.
- Loopback status.
- Multicast status.
- Reserved status.

### URL Enrichment

- Scheme.
- Hostname.
- Port.
- Path.
- Query parameters.

Enrichment converts raw indicators into structured data that can be evaluated by later stages.

---

## 7. Scoring Layer

The scoring layer evaluates individual indicators.

Examples include:

### IP Scoring

May consider:

- Public or private status.
- Threat intelligence reputation.
- Threat intelligence confidence.
- Correlation results.

### URL Scoring

May consider:

- Suspicious keywords.
- URL structure.
- Authentication-related paths.
- Other URL characteristics.

Scoring remains an IOC-level process.

---

## 8. Threat Intelligence Layer

Threat intelligence provides external reputation context.

Current implementation includes AbuseIPDB for IP reputation.

Threat intelligence results may include:

- Reputation.
- Confidence.
- Number of reports.
- Source availability.

A clean threat intelligence result does not prove that an investigation is benign.

It only means that the intelligence source did not provide sufficient malicious evidence for that IOC at the time of the query.

---

## 9. Threat Correlation Layer

The correlation layer combines available threat intelligence results.

Possible correlation verdicts include:

- Malicious.
- Suspicious.
- Clean.

The correlation result becomes one source of evidence for the investigation assessment engine.

Threat correlation should contribute to the investigation decision but should not automatically become the investigation decision.

---

## 10. Investigation Assessment Layer

The investigation assessment layer is responsible for combining evidence.

Current implementation:

`assess_investigation()`

Current inputs:

- IP scores.
- URL scores.
- Domain intelligence.
- Threat correlation.

The engine evaluates these inputs and classifies evidence into:

- Strong signals.
- Suspicious signals.

---

## 11. Strong Signals

Strong signals represent higher-confidence security evidence.

Examples may include:

- High-risk IP.
- High-risk URL.
- Confirmed malicious threat intelligence correlation.

Strong signals have greater influence over the final verdict.

Current decision logic:

- Two or more strong signals → Malicious / High Confidence.
- One strong signal → Suspicious / High Confidence.

---

## 12. Suspicious Signals

Suspicious signals represent evidence requiring validation.

Examples may include:

- Medium-risk IOC.
- Suspicious URL characteristics.
- Suspicious domain characteristics.
- Suspicious threat intelligence correlation.

Current decision logic:

- Two or more suspicious signals → Suspicious / Medium Confidence.
- One suspicious signal → Review Required / Low Confidence.

---

## 13. Evidence Score

The evidence score provides a numeric representation of accumulated evidence.

However, the evidence score should not be treated as the only decision mechanism.

The investigation verdict also considers:

- Signal type.
- Signal strength.
- Number of signals.
- Correlation between evidence sources.

This creates a more explainable model than relying only on a single total score.

---

## 14. Investigation Verdicts

Current investigation verdicts include:

### Malicious

Used when sufficient strong evidence indicates likely malicious activity.

### Suspicious

Used when evidence requires active investigation but does not yet confirm compromise.

### Review Required

Used when limited suspicious evidence exists and contextual analyst validation is required.

### No Significant Threat Identified

Used when no meaningful strong or suspicious signals are identified.

---

## 15. Confidence

Confidence describes how strongly the available evidence supports the verdict.

Current confidence levels include:

- High.
- Medium.
- Low.

Verdict and confidence should be considered together.

For example:

`Suspicious / High Confidence`

is more urgent than:

`Review Required / Low Confidence`

even if neither result is classified as Malicious.

---

## 16. Investigation Recommendations

Investigation-level recommendations are based on the overall investigation verdict.

They should guide the analyst toward the next logical investigation actions.

Examples include:

- Review identity and sign-in activity.
- Validate MFA status.
- Check endpoint activity in EDR.
- Search for additional affected users.
- Search for additional affected hosts.
- Review historical activity.
- Escalate when supporting evidence confirms malicious activity.

These recommendations differ from IOC-level recommendations because they address the investigation as a whole.

---

## 17. Investigation Priority

Overall investigation priority is based on the investigation assessment.

Current model:

### P1

Immediate investigation, containment, and escalation required.

Typical condition:

- Malicious verdict.

### P2

High-priority investigation or suspicious activity validation required.

Typical condition:

- Suspicious verdict.

### P3

Analyst review and contextual validation required.

Typical condition:

- Review Required verdict.

### P4

Document findings and continue monitoring.

Typical condition:

- No Significant Threat Identified.

---

## 18. IOC Priority vs Investigation Priority

These priorities must remain separate.

Example:

### IOC-Level Result

IP: `8.8.8.8`

- Risk: Low.
- IOC Priority: P3.

### Investigation-Level Result

Combined evidence:

- Suspicious URL characteristics.
- Suspicious domain characteristics.
- Clean IP reputation.
- Clean threat correlation.

Final result:

- Verdict: Suspicious.
- Confidence: Medium.
- Overall Investigation Priority: P2.

There is no contradiction.

The IOC priority describes one indicator.

The investigation priority describes the complete case context.

---

## 19. Why This Architecture Matters

SOC investigations frequently contain incomplete or conflicting evidence.

Examples include:

- A clean IP used in suspicious authentication activity.
- A newly registered domain with no threat intelligence history.
- A legitimate cloud service abused by an attacker.
- A malicious URL hosted on otherwise legitimate infrastructure.
- Multiple low-confidence signals appearing together.

A security investigation platform must therefore avoid the logic:

`Clean IOC = Clean Investigation`

Instead, ORION uses:

`Multiple Evidence Sources → Correlation → Contextual Assessment`

---

## 20. Explainability

Every investigation decision should be explainable.

ORION therefore returns:

- Verdict.
- Confidence.
- Strong signal count.
- Suspicious signal count.
- Evidence score.
- Evidence descriptions.
- Recommendations.
- Priority.

The goal is for an analyst to understand:

1. What ORION identified.
2. Why ORION reached the verdict.
3. How confident the system is.
4. What evidence influenced the decision.
5. What the analyst should investigate next.

This is important for:

- SOC analyst trust.
- Incident review.
- Auditability.
- Detection tuning.
- Future AI-assisted investigation.
- Human approval workflows.

---

## 21. Current Limitations

The current investigation assessment engine is an early deterministic implementation.

Current limitations include:

- Simplified evidence weighting.
- Limited threat intelligence sources.
- Domain analysis based partly on suspicious keywords.
- Limited handling of multiple IP correlation results.
- No identity context.
- No endpoint telemetry.
- No asset criticality.
- No historical behavioural baseline.
- No MITRE ATT&CK mapping.
- No allowlist or trusted infrastructure context.

These limitations are expected at the current development stage.

---

## 22. Future Architecture

The investigation assessment engine can later receive additional evidence from:

### Identity

- Entra ID.
- Risky sign-ins.
- MFA status.
- Conditional Access.
- Session activity.

### Endpoint

- Microsoft Defender.
- CrowdStrike.
- SentinelOne.

### Email

- Microsoft Defender for Office 365.
- Abnormal Security.
- Exchange audit data.

### Vulnerability

- Qualys.
- Asset exposure.
- Known vulnerabilities.

### SIEM

- Microsoft Sentinel.
- Google SecOps.
- Splunk.

### Case Management

- ServiceNow.

As these integrations are added, the investigation engine can aggregate a broader set of security evidence.

---

## 23. Design Principle

The long-term design principle for ORION is:

**Automation gathers evidence.**

**Correlation connects evidence.**

**The reasoning engine interprets evidence.**

**The analyst retains authority over high-impact actions.**

Destructive or high-impact actions should continue to require human approval, including:

- Disabling accounts.
- Revoking sessions.
- Resetting passwords.
- Isolating critical endpoints or servers.
- Blocking domains or URLs.
- Deleting emails.

---

## 24. Summary

ORION separates IOC-level analysis from investigation-level reasoning.

This allows the system to preserve accurate individual IOC findings while still identifying suspicious patterns across the wider investigation.

The architecture supports the progression from:

Raw Investigation Text  
→ Structured Indicators  
→ Enriched Evidence  
→ IOC Risk  
→ Threat Intelligence  
→ Correlated Evidence  
→ Investigation Verdict  
→ Recommendations  
→ Priority

This investigation-level reasoning layer is a foundational component of ORION's future development as a security investigation and decision-support platform.