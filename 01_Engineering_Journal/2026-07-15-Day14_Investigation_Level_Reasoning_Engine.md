# ORION Engineering Journal — Day 14

## Investigation-Level Reasoning and Decision Engine

**Project:** ORION  
**Day:** 14  
**Focus:** Investigation-Level Evidence Aggregation, Contextual Decision-Making, Recommendations, and Priority Assignment

---

## 1. Objective

The objective of Day 14 was to move ORION beyond analysing individual Indicators of Compromise (IOCs) independently.

Before today's work, ORION could:

- Extract IOCs from investigation text.
- Enrich IP addresses.
- Parse and enrich URLs.
- Score IP addresses.
- Score URLs.
- Inspect domain characteristics.
- Query threat intelligence.
- Correlate threat intelligence results.
- Generate IOC-level recommendations.
- Assign IOC-level priorities.

However, these components operated mainly at the individual IOC level.

The goal for Day 14 was to introduce an investigation-level reasoning layer capable of combining multiple pieces of evidence and producing a single contextual assessment for the overall investigation.

---

## 2. Problem Identified

A security investigation cannot always be accurately assessed by looking at one IOC in isolation.

For example:

- An IP address may have a clean reputation.
- A URL may contain suspicious authentication-related keywords.
- A domain may contain suspicious characteristics.
- Threat intelligence may not identify any confirmed malicious activity.

Individually, none of these signals may justify a malicious verdict.

However, when multiple suspicious indicators appear together within the same investigation, the overall context may require further investigation.

This created the need for an investigation-level reasoning engine.

---

## 3. Architecture Before Day 14

The previous ORION processing flow was approximately:

Investigation Text  
→ IOC Extraction  
→ IOC Enrichment  
→ IOC Scoring  
→ Threat Intelligence  
→ Threat Correlation  
→ IOC Recommendations  
→ IOC Priority  
→ Display Results

This architecture provided useful IOC-level analysis but did not generate a unified investigation verdict.

---

## 4. Architecture After Day 14

The ORION processing flow now includes an investigation assessment and decision layer:

Investigation Text  
→ Extract  
→ Enrich  
→ Score  
→ Threat Intelligence  
→ Correlate  
→ Assess Investigation  
→ Recommend  
→ Prioritise  
→ Display

The new investigation-level layer combines evidence from:

- IP risk scores.
- URL risk scores.
- Domain intelligence.
- Threat intelligence correlation.

The combined evidence is then used to determine:

- Overall investigation verdict.
- Confidence level.
- Strong signal count.
- Suspicious signal count.
- Evidence score.
- Investigation-level recommendations.
- Overall investigation priority.

---

## 5. New Investigation Assessment Engine

A new module was introduced:

`11_Modules/investigation_engine.py`

The primary function is:

`assess_investigation()`

The function receives:

- IP scoring results.
- URL scoring results.
- Domain intelligence results.
- Threat correlation results.

The function then evaluates the evidence and classifies signals into two main categories:

### Strong Signals

Strong signals represent evidence with a higher level of confidence or severity.

Examples include:

- High-risk IP evidence.
- High-risk URL evidence.
- Malicious threat intelligence correlation.

Strong signals have a greater impact on the final investigation verdict.

### Suspicious Signals

Suspicious signals represent evidence that requires further investigation but does not independently confirm malicious activity.

Examples include:

- Medium-risk IP evidence.
- Low or medium suspicious URL characteristics.
- Suspicious domain characteristics.
- Suspicious threat intelligence correlation.

The engine counts these signals and uses the combined evidence to determine the overall investigation verdict.

---

## 6. Investigation Verdict Logic

The investigation engine currently uses signal-based decision logic.

### Malicious

If two or more strong signals are identified:

- Verdict: Malicious
- Confidence: High

### Suspicious — High Confidence

If one strong signal is identified:

- Verdict: Suspicious
- Confidence: High

### Suspicious — Medium Confidence

If two or more suspicious signals are identified:

- Verdict: Suspicious
- Confidence: Medium

### Review Required

If one suspicious signal is identified:

- Verdict: Review Required
- Confidence: Low

### No Significant Threat Identified

If no strong or suspicious signals are identified:

- Verdict: No Significant Threat Identified
- Confidence: Low

This prevents ORION from relying only on a single numeric score when making an overall investigation decision.

---

## 7. Investigation-Level Decision Functions

The existing `decision.py` module was extended with two new investigation-level functions.

### `recommend_investigation_action()`

This function generates analyst recommendations based on the overall investigation assessment rather than an individual IOC.

For a suspicious investigation, recommendations may include:

1. Perform further investigation to validate the suspicious indicators.
2. Review related identity and sign-in activity.
3. Check endpoint activity in EDR.
4. Search for additional users, hosts, or events associated with the indicators.
5. Escalate if additional suspicious or malicious evidence is identified.

This is closer to a real SOC investigation workflow because recommendations are based on the combined case context.

---

### `determine_investigation_priority()`

This function assigns an overall investigation priority based on the investigation verdict and confidence.

Current priority logic includes:

- P1 — Malicious activity requiring immediate investigation, containment, and escalation.
- P2 — Suspicious activity requiring investigation and supporting evidence validation.
- P3 — Analyst review and contextual validation required.
- P4 — Document findings and continue monitoring.

This is separate from the existing IOC-level priority logic.

---

## 8. Integration into the Main ORION Workflow

The main script:

`07_Scripts/ioc_extractor.py`

was updated to call the investigation assessment engine after IOC enrichment, scoring, domain analysis, and threat intelligence correlation.

The workflow now creates:

- `Investigation Assessment`
- `Investigation Recommendations`
- `Investigation Priority`

These results are added to the main `results` dictionary and passed to the reporting layer.

This means the main ORION pipeline now produces both:

1. IOC-level analysis.
2. Investigation-level analysis.

---

## 9. Display Layer Enhancements

The `display.py` module was extended with new functions:

- `display_investigation_assessment()`
- `display_investigation_recommendations()`
- `display_investigation_priority()`

The final report now displays:

### Investigation-Level Output

- Investigation Assessment.
- Investigation Recommendations.
- Overall Investigation Priority.

### IOC-Level Output

- IOC Risk Scores.
- IOC-Level Recommendations.
- IOC-Level Priority.

To avoid confusion, the previous headings were renamed:

`RISK SCORES`

became:

`IOC RISK SCORES`

`ANALYST RECOMMENDATIONS`

became:

`IOC-LEVEL RECOMMENDATIONS`

`INVESTIGATION PRIORITY`

became:

`IOC-LEVEL PRIORITY`

This clearly separates local IOC decisions from the overall investigation decision.

---

## 10. Test Scenario

The following investigation text was used:

> User authenticated from source IP 8.8.8.8 and later visited https://login.example.com:443/account/reset?user=sam during the investigation.

ORION extracted:

- IP Address: `8.8.8.8`
- URL: `https://login.example.com:443/account/reset?user=sam`
- Domain: `login.example.com`

---

## 11. Test Results

### IP Analysis

The IP address was identified as:

- Public IPv4 address.
- Low IOC risk.
- Risk score: 20.
- AbuseIPDB reputation: Clean.
- Threat correlation verdict: Clean.
- Threat correlation confidence: Low.

The IP alone did not provide strong malicious evidence.

---

### URL Analysis

The URL received:

- Risk: Low.
- Score: 15.

Suspicious keywords identified:

- `login`
- `account`
- `reset`

The URL therefore contributed one low-confidence suspicious signal.

---

### Domain Analysis

The domain:

`login.example.com`

was classified as:

- Reputation: Suspicious.
- Confidence: 40.
- Matched keyword: `login`

The domain contributed another suspicious signal.

---

## 12. Final Investigation Assessment

The combined investigation result was:

- Verdict: Suspicious
- Confidence: Medium
- Strong Signals: 0
- Suspicious Signals: 2
- Evidence Score: 35

Evidence identified:

- Low-confidence suspicious URL characteristics.
- Suspicious domain characteristics.

Although the IP itself was clean and threat intelligence did not identify malicious activity, the combination of two suspicious signals resulted in an overall Suspicious verdict.

---

## 13. Overall Investigation Priority

The final investigation priority was:

- Priority: P2
- Action: Investigate suspicious activity and validate supporting evidence.

At the same time, the individual IP remained:

- IOC Risk: Low.
- IOC Priority: P3.

This difference is intentional.

---

## 14. Key Engineering Lesson

The most important lesson from Day 14 was:

**IOC risk is not the same as investigation risk.**

A single IOC may appear clean or low risk while the wider investigation context contains multiple suspicious signals.

ORION must therefore maintain two separate decision layers:

### IOC-Level Decision Layer

Answers:

- How risky is this individual indicator?
- What should the analyst do about this IOC?

### Investigation-Level Decision Layer

Answers:

- What does all available evidence mean when analysed together?
- What is the overall case verdict?
- How urgently should the investigation be handled?
- What should the analyst investigate next?

This separation improves explainability and prevents a clean IOC from automatically causing an entire investigation to be closed.

---

## 15. Validation Outcome

Day 14 testing confirmed that ORION can now:

- Analyse multiple evidence sources.
- Preserve individual IOC findings.
- Aggregate suspicious evidence.
- Distinguish strong signals from suspicious signals.
- Produce an overall investigation verdict.
- Assign confidence.
- Generate contextual investigation recommendations.
- Assign an overall investigation priority.
- Explain the evidence supporting the decision.

The test completed successfully with no VS Code errors.

---

## 16. Current ORION Investigation Pipeline

The current pipeline is:

1. Receive investigation text.
2. Extract IOCs.
3. Enrich IP addresses.
4. Enrich URLs.
5. Inspect domains.
6. Score IP addresses.
7. Score URLs.
8. Query threat intelligence.
9. Correlate threat intelligence.
10. Aggregate investigation evidence.
11. Determine investigation verdict.
12. Determine confidence.
13. Generate investigation recommendations.
14. Assign overall investigation priority.
15. Display IOC-level and investigation-level findings.

---

## 17. Day 14 Achievement

Day 14 introduced ORION's first true investigation-level reasoning layer.

ORION is no longer limited to answering:

> "Is this IP suspicious?"

It can now begin answering:

> "Considering all available evidence, what is the overall state of this investigation, why was that decision reached, and what should the analyst do next?"

This represents an important transition from an IOC utility toward a modular security investigation engine.

---

## 18. Next Steps

Future development may include:

- Supporting investigations with no IP addresses.
- Supporting multiple IPs and multiple threat correlation results.
- Improving domain intelligence beyond keyword matching.
- Introducing domain age and registration intelligence.
- Adding allowlists for trusted infrastructure.
- Adding identity context.
- Adding endpoint context.
- Adding MITRE ATT&CK mapping.
- Improving evidence weighting.
- Adding confidence calibration.
- Adding structured case output.
- Adding automated investigation summaries.
- Adding human approval gates before remediation actions.

---

## Day 14 Status

**Completed successfully.**

ORION now supports investigation-level evidence aggregation, contextual verdict generation, investigation recommendations, and overall investigation prioritisation.