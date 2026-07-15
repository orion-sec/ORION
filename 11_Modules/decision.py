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

def recommend_investigation_action(assessment):

    verdict = assessment["verdict"]

    if verdict == "Malicious":
        return [
            "Immediately investigate for active compromise.",
            "Identify affected users, hosts, and related indicators.",
            "Review identity, endpoint, email, and network activity.",
            "Contain affected assets where malicious activity is confirmed.",
            "Revoke active sessions and reset credentials if account compromise is suspected.",
            "Escalate to Incident Response."
        ]

    if verdict == "Suspicious":
        return [
            "Perform further investigation to validate the suspicious indicators.",
            "Review related identity and sign-in activity.",
            "Check endpoint activity in EDR.",
            "Search for additional users, hosts, or events associated with the indicators.",
            "Escalate if additional suspicious or malicious evidence is identified."
        ]

    if verdict == "Review Required":
        return [
            "Review the identified indicator in context.",
            "Validate the activity against expected user and system behaviour.",
            "Check historical activity for similar events.",
            "Document the investigation findings."
        ]

    return [
        "No significant threat identified.",
        "Document the investigation findings.",
        "Continue monitoring for related activity."
    ]


def determine_investigation_priority(assessment):

    verdict = assessment["verdict"]
    confidence = assessment["confidence"]

    if verdict == "Malicious":
        return {
            "priority": "P1",
            "action": "Immediate investigation, containment, and escalation required"
        }

    if verdict == "Suspicious" and confidence == "High":
        return {
            "priority": "P2",
            "action": "High-priority investigation required"
        }

    if verdict == "Suspicious":
        return {
            "priority": "P2",
            "action": "Investigate suspicious activity and validate supporting evidence"
        }

    if verdict == "Review Required":
        return {
            "priority": "P3",
            "action": "Analyst review and contextual validation required"
        }

    return {
        "priority": "P4",
        "action": "Document findings and continue monitoring"
    }