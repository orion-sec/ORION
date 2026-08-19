# KB-040 — ORION Evidence-Driven Cognitive Question Resolution

**Project:** ORION  
**Component:** Cognitive Investigation Engine  
**Date:** 19 August 2026  
**Status:** Implemented and Tested

---

## 1. Purpose

This Knowledge Base documents ORION's evidence-driven investigation question
architecture.

The capability improves ORION's cognitive reasoning by changing investigation
questions from simple generic follow-up questions into structured investigation
objects that identify the specific evidence required to answer them.

The architecture establishes the foundation for ORION to progressively investigate
security incidents rather than repeatedly generating static questions.

---

## 2. Problem

Earlier cognitive pipeline testing showed that ORION could generate useful
investigation questions, but many questions contained similar or generic reasoning.

For example:

"Was the suspicious executable actually executed on the endpoint?"

The question itself is valid, but ORION previously lacked an explicit representation
of what evidence was required to answer it.

This created several limitations:

- Questions could remain generic.
- ORION could not clearly identify the missing investigation evidence.
- Newly collected evidence could not reliably resolve outstanding questions.
- Questions could be repeatedly generated even when relevant evidence existed.
- The cognitive engine lacked investigation-state awareness.

---

## 3. Architectural Principle

ORION now separates an investigation question from the evidence required to
answer that question.

The cognitive flow becomes:

Security Evidence
    ↓
Finding
    ↓
Investigation Question
    ↓
Evidence Gap
    ↓
Evidence Collection
    ↓
Question Resolution
    ↓
Investigation Decision

This is an important distinction.

A question represents:

"What does ORION need to know?"

An evidence gap represents:

"What evidence must ORION obtain to answer it?"

---

## 4. Structured Question Model

The Question cognitive model was extended to carry investigation context.

A question can now contain:

- question
- reason
- category
- evidence_gap
- priority
- status

Example:

Question:
"Was the malicious file executed?"

Category:
Execution

Evidence Gap:
- process-execution
- endpoint-telemetry

Priority:
High

Status:
Unresolved

This provides significantly more investigation context than a plain-text question.

---

## 5. Evidence Gaps

Evidence gaps describe specific facts or telemetry that ORION still needs to
establish.

Examples may include:

- process-execution
- endpoint-telemetry
- file-reputation
- file-prevalence
- network-communication
- authentication-activity
- user-signin-history
- infrastructure-reputation

Evidence gaps create a bridge between cognitive reasoning and ORION's security
providers.

Future ORION investigation logic can use the evidence gap to determine which
provider or security platform should be queried.

Example:

process-execution
    ↓
Endpoint provider
    ↓
Microsoft Defender / CrowdStrike
    ↓
Process telemetry
    ↓
Question resolution

---

## 6. Question Factory

The question factory was enhanced so generated Question objects can receive
structured investigation metadata.

The factory remains responsible for creating Question objects.

It does not perform investigation logic.

This preserves ORION's architectural separation between:

Factories
    → create cognitive objects

Cognitive pipelines
    → coordinate reasoning

Providers
    → retrieve security evidence

Decision engine
    → determine investigation outcome

---

## 7. Question Resolution

A dedicated question-resolution capability was introduced.

Its responsibility is to compare outstanding evidence gaps against evidence that
has already been collected.

Conceptually:

Unresolved Question
    ↓
Required Evidence Gap
    ↓
Available Investigation Evidence
    ↓
Evidence Match?
   / \
 No  Yes
 ↓    ↓
Keep  Resolve
Open  Question

This gives ORION the ability to maintain investigation state rather than treating
every cognitive execution as an isolated reasoning event.

---

## 8. Cognitive Pipeline Integration

Question resolution was integrated into ORION's cognitive investigation flow.

The cognitive pipeline coordinates:

Evidence
    ↓
Findings
    ↓
Questions
    ↓
Question Resolution
    ↓
Hypotheses
    ↓
Investigation Outcome

This allows newly collected evidence to influence the state of previously generated
investigation questions.

---

## 9. Indicator Intelligence Cognitive Bridge

Day 42 also strengthened the connection between ORION's Indicator Intelligence
layer and the Cognitive Investigation Engine.

Structured indicator intelligence can now be promoted into cognitive evidence.

Relevant intelligence may include:

- indicator type
- indicator value
- malicious classification
- risk level
- confidence
- threat family
- provider
- internal prevalence
- intelligence sources
- MITRE ATT&CK techniques
- investigation recommendations

Example:

VirusTotal
    ↓
IndicatorProfile
    ↓
Confirmed Malicious
    ↓
Cognitive Evidence
    ↓
Finding
    ↓
Investigation Question

This prevents threat-intelligence enrichment from remaining isolated from ORION's
reasoning engine.

---

## 10. Example Investigation

Consider a Microsoft Sentinel incident containing a suspicious file.

ORION receives:

File hash:
SHA-256 indicator

Threat Intelligence:
Confirmed Malicious

Threat Family:
Ransomware

MITRE ATT&CK:
T1204.002

ORION can establish that the file is malicious.

However, malicious reputation alone does not prove execution.

The cognitive engine can therefore generate:

Question:
"Was the malicious file executed?"

Evidence Gap:
process-execution

Status:
Unresolved

ORION can later retrieve endpoint telemetry.

If process execution evidence confirms the file executed:

Evidence Gap:
process-execution

Status:
Resolved

The investigation can then progress to subsequent questions such as persistence,
lateral movement, credential access, network communication, or containment.

---

## 11. Why This Matters

This architecture moves ORION away from:

Alert
    ↓
Generic Questions
    ↓
Generic Recommendations

toward:

Alert
    ↓
Evidence
    ↓
Finding
    ↓
Specific Investigation Question
    ↓
Evidence Gap
    ↓
Targeted Evidence Collection
    ↓
Resolution
    ↓
Next Investigation Decision

This is much closer to the workflow followed by an experienced SOC or Incident
Response analyst.

---

## 12. Key Implementation Files

Modified:

- cognitive/cognitive_pipeline.py
- cognitive/question_pipeline.py
- factories/question_factory.py
- models/question.py
- pipeline.py

Created:

- cognitive/question_resolver.py
- tests/test_cognitive_question_resolution.py
- tests/test_pipeline_indicator_cognitive_bridge.py
- tests/test_question_factory_evidence_gaps.py
- tests/test_question_model.py
- tests/test_question_resolver.py

---

## 13. Testing

Focused Day 42 regression tests:

10 passed.

Code-quality validation:

ruff check .
All checks passed.

Full regression:

57 passed
4 skipped
2 failed

The two failures were live environment-search tests where the Microsoft Log
Analytics workspace returned no recent Entra SigninLogs.

These were live telemetry/data availability conditions and were not failures of
the Day 42 cognitive-question architecture.

---

## 14. Current Capability

ORION can now represent:

What is known
    ↓
What remains unknown
    ↓
What evidence is required
    ↓
Whether that evidence has been collected
    ↓
Whether the investigation question is resolved

This creates the foundation required for automated investigation orchestration.

---

## 15. Future Architecture

The next evolution of this capability is:

Evidence Gap
    ↓
Provider Selection
    ↓
Investigation Query
    ↓
Evidence Collection
    ↓
Evidence Normalisation
    ↓
Question Resolution
    ↓
Cognitive Re-evaluation
    ↓
Next Investigation Action

The long-term objective is for ORION to determine which security platform should
be queried based on the evidence required to resolve an investigation question.

For example:

process-execution
    → Defender / CrowdStrike

authentication-activity
    → Entra ID / Sentinel

file-reputation
    → VirusTotal

network-communication
    → SIEM / EDR / Network telemetry

internal-prevalence
    → Enterprise environment search

This provides the architectural foundation for an autonomous, evidence-driven
SOC investigation loop.

---

## 16. Engineering Outcome

Day 42 established a significant cognitive architecture milestone.

ORION no longer needs to treat investigation questions purely as text.

Questions can now represent structured investigation state, including what
evidence is missing and whether that evidence has subsequently been obtained.

This enables ORION to progressively reason through an investigation rather than
simply producing a static list of security questions.