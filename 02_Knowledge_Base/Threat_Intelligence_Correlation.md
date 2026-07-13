# Threat Intelligence Correlation

## Overview

Threat intelligence correlation is the process of evaluating intelligence findings together to produce a unified security assessment.

A single threat intelligence source provides enrichment.

Correlation attempts to answer a broader question:

> What conclusion should the investigation reach when the available threat intelligence findings are evaluated together?

---

## Enrichment vs Correlation

### Threat Intelligence Enrichment

Enrichment provides additional context about an Indicator of Compromise (IOC).

Examples include:

- IP reputation
- Confidence score
- Number of abuse reports
- Intelligence source
- Availability status

Example:

IP Address → AbuseIPDB → Reputation: Clean

### Threat Intelligence Correlation

Correlation evaluates threat intelligence results and produces a combined verdict.

Example:

Threat Source A → Malicious  
Threat Source B → Malicious

Correlation Result:

Verdict → Malicious  
Confidence → High

Correlation therefore acts as a decision layer between threat intelligence lookup and risk scoring.

---

## ORION Correlation Architecture

The current ORION pipeline is:

Investigation Text  
→ IOC Extraction  
→ IP Enrichment  
→ Threat Intelligence Lookup  
→ Threat Intelligence Correlation  
→ Risk Scoring  
→ Investigation Priority  
→ Analyst Recommendation  
→ Investigation Report

The correlation engine is implemented in:

`11_Modules/threat_engine.py`

Primary function:

`correlate_threat_intelligence()`

---

## Correlation Result Structure

The correlation engine returns a Python dictionary containing:

- verdict
- confidence
- sources
- reason

Example:

```python
{
    "verdict": "Clean",
    "confidence": "Low",
    "sources": 1,
    "reason": "No available threat intelligence source identified malicious activity"
}