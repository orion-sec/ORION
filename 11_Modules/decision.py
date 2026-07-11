def recommend_action(risk_result):

    risk = risk_result["risk"]

    if risk == "Informational":
        return [
            "No immediate security action required.",
            "Document the finding."
        ]

    if risk == "Low":
        return [
            "Validate the activity against known internal infrastructure.",
            "Review historical activity for the IOC.",
            "Consider alert suppression if repeatedly confirmed as expected."
        ]

    if risk == "Medium":
        return [
            "Enrich the IOC using threat intelligence.",
            "Review identity and sign-in activity.",
            "Validate MFA authentication status.",
            "Check endpoint activity in EDR.",
            "Search for additional users or hosts associated with the IOC.",
            "Escalate if suspicious activity is confirmed."
        ]

    if risk == "High":
        return [
            "Immediately investigate for active compromise.",
            "Review successful authentication activity.",
            "Revoke active sessions if account compromise is suspected.",
            "Reset the affected user password.",
            "Contain the endpoint if malicious activity is confirmed.",
            "Escalate to Incident Response."
        ]

    return [
        "Manual analyst review required."
    ]

def determine_priority(score):

    if score >= 80:
        return {
            "priority": "P1",
            "action": "Immediate investigation and escalation required"
        }

    if score >= 50:
        return {
            "priority": "P2",
            "action": "Investigate within standard SOC workflow"
        }

    if score >= 20:
        return {
            "priority": "P3",
            "action": "Review and validate supporting activity"
        }

    return {
        "priority": "P4",
        "action": "Document and monitor"
    }