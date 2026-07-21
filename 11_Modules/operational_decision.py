def determine_operational_decision(contextual_risk, business_impact):
    """
    Produce a deterministic operational decision using contextual risk
    and business impact.

    This layer is intentionally rule-based so that decisions remain
    transparent, predictable and auditable.
    """

    risk_severity = str(
        contextual_risk.get("severity", "Unknown")
    ).lower()

    impact_level = str(
        business_impact.get("impact", "Unknown")
    ).lower()

    reasons = []

    if risk_severity == "critical" and impact_level in {"critical", "high"}:
        decision = "Immediate Escalation and Containment"
        priority = "P1"
        automation_readiness = "Approval Required"
        actions = [
            "Escalate immediately to Incident Response.",
            "Contain the affected identity or asset.",
            "Notify relevant business and security stakeholders.",
            "Begin major-incident assessment.",
        ]
        reasons.append(
            "Critical security risk is combined with high or critical business impact."
        )

    elif risk_severity == "critical":
        decision = "Immediate Security Escalation"
        priority = "P1"
        automation_readiness = "Approval Required"
        actions = [
            "Escalate immediately to Incident Response.",
            "Perform urgent containment.",
            "Reset credentials and revoke active sessions where applicable.",
            "Continue business-impact validation.",
        ]
        reasons.append(
            "The investigation has critical security risk even though current business impact is lower."
        )

    elif risk_severity == "high" and impact_level in {"critical", "high"}:
        decision = "Priority Escalation"
        priority = "P1"
        automation_readiness = "Approval Required"
        actions = [
            "Escalate for priority investigation.",
            "Notify relevant stakeholders.",
            "Prepare containment actions.",
            "Increase monitoring of the affected identity or asset.",
        ]
        reasons.append(
            "High security risk affects a high-impact identity."
        )

    elif risk_severity == "high":
        decision = "Escalate for Investigation"
        priority = "P2"
        automation_readiness = "Analyst Review Required"
        actions = [
            "Escalate to the appropriate investigation tier.",
            "Validate the available evidence.",
            "Apply containment if compromise is confirmed.",
        ]
        reasons.append(
            "High security risk requires investigation and possible containment."
        )

    elif risk_severity == "medium" and impact_level in {"critical", "high"}:
        decision = "Priority Investigation"
        priority = "P2"
        automation_readiness = "Analyst Review Required"
        actions = [
            "Prioritise investigation because of the affected identity's business importance.",
            "Notify the relevant manager or system owner where appropriate.",
            "Increase monitoring while evidence is validated.",
        ]
        reasons.append(
            "Moderate security risk affects a high-impact identity."
        )

    elif risk_severity == "medium":
        decision = "Standard Investigation"
        priority = "P2"
        automation_readiness = "Analyst Review Required"
        actions = [
            "Continue standard investigation.",
            "Validate suspicious evidence.",
            "Escalate if additional malicious activity is identified.",
        ]
        reasons.append(
            "Moderate security risk requires further investigation."
        )

    elif risk_severity == "low" and impact_level in {"critical", "high"}:
        decision = "Monitor and Validate"
        priority = "P3"
        automation_readiness = "Manual Review"
        actions = [
            "Validate the activity before closure.",
            "Monitor the high-impact identity for related activity.",
            "Document the evidence and decision.",
        ]
        reasons.append(
            "Low technical risk affects an identity with significant business importance."
        )

    else:
        decision = "Close or Monitor"
        priority = "P3"
        automation_readiness = "Potentially Automatable"
        actions = [
            "Confirm that no additional suspicious evidence exists.",
            "Document the investigation outcome.",
            "Close or continue routine monitoring.",
        ]
        reasons.append(
            "Both contextual risk and business impact are currently low."
        )

    return {
        "decision": decision,
        "priority": priority,
        "automation_readiness": automation_readiness,
        "actions": actions,
        "reasons": reasons,
        "inputs": {
            "contextual_risk": contextual_risk.get("severity", "Unknown"),
            "business_impact": business_impact.get("impact", "Unknown"),
        },
    }