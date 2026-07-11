# SOC Decision and Investigation Priority Engine

## Overview

A SOC decision engine converts security investigation data into structured analyst guidance.

Instead of only identifying an IOC, the system evaluates available characteristics and determines the appropriate investigation response.

In ORION, the decision pipeline currently uses risk scoring to generate:

- Analyst recommendations
- Investigation priority
- Suggested investigation actions

---

## Decision Pipeline

IOC
 ↓
Enrichment
 ↓
Risk Classification
 ↓
Risk Score
 ↓
Analyst Recommendation
 ↓
Investigation Priority

Each stage provides additional context to the next stage.

---

## Risk Score

The risk scoring engine evaluates characteristics associated with an IP address.

Current classifications include:

### Loopback Address

Risk: Informational

Score: 0

Example:

127.0.0.1

Loopback traffic normally represents communication with the local host.

---

### Private IP Address

Risk: Low

Score: 10

Examples:

10.0.0.5

192.168.1.10

Private IP addresses normally represent internal network infrastructure.

Internal activity should still be validated against known assets and expected behaviour.

---

### Reserved Address

Risk: Low

Score: 15

Reserved addresses require validation to determine whether the activity is expected.

---

### Public Global IP

Risk: Medium

Score: 50

Example:

8.8.8.8

A public IP requires additional investigation context.

The IP being public does not automatically mean that it is malicious.

Additional enrichment and activity correlation are required.

---

## Rule Precedence

Rule precedence defines the order in which decision conditions are evaluated.

More specific conditions should normally be evaluated before broader conditions.

Example:

127.0.0.1 may be classified as:

Private: True

Loopback: True

If the private IP condition is evaluated first and immediately returns a result, the loopback condition may never execute.

Incorrect order:

Private IP
 ↓
Loopback IP

Preferred order:

Loopback IP
 ↓
Private IP

General principle:

Specific rule before broad rule.

This principle is relevant to:

- SIEM detection rules
- Firewall processing
- Conditional Access
- SOAR workflows
- Detection engineering
- Security decision systems

---

## Function Return Behaviour

When a Python function executes a return statement, the function immediately stops processing.

Example:

if ip["is_private"]:
    return result

Any conditions below the return statement will not be evaluated once the condition matches.

Decision logic must therefore be designed carefully.

---

## Investigation Priority

Investigation priority determines how quickly a security event should enter the SOC investigation workflow.

ORION currently uses the following model.

### P1

Score: 80 or greater

Action:

Immediate investigation and escalation required.

---

### P2

Score: 50 or greater

Action:

Investigate within standard SOC workflow.

---

### P3

Score: 20 or greater

Action:

Review and validate supporting activity.

---

### P4

Score: Below 20

Action:

Document and monitor.

---

## Analyst Recommendations

ORION generates investigation recommendations based on the calculated risk result.

Example recommendations for a public IOC include:

1. Enrich the IOC using threat intelligence.
2. Review identity and sign-in activity.
3. Validate MFA authentication status.
4. Check endpoint activity in EDR.
5. Search for additional users or hosts associated with the IOC.
6. Escalate if suspicious activity is confirmed.

These recommendations reflect a practical SOC investigation workflow.

---

## Security Engineering Lesson

Successful code execution does not guarantee correct security logic.

A security decision engine may execute without errors while still producing an incorrect classification.

Testing must therefore validate:

- Code execution
- Input handling
- Data enrichment
- Rule order
- Decision accuracy
- Expected security outcome

This is particularly important when building automated security triage and response systems.

---

## ORION Design Principle

ORION should support analyst decisions rather than blindly perform destructive actions.

Investigation recommendations and priorities can be automatically generated.

High-impact remediation actions should remain subject to human approval.

Examples include:

- Disabling a user account
- Revoking active sessions
- Resetting passwords
- Isolating endpoints or servers
- Blocking domains or URLs
- Deleting or removing email

This maintains human oversight within the security response process.