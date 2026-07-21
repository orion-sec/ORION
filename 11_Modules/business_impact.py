def assess_business_impact(enriched_identity):
    """
    Assess the organisational impact associated with an enriched identity.

    Contextual risk evaluates the security evidence in an investigation.
    Business impact evaluates the importance of the affected identity to
    the organisation.

    Future versions may use Microsoft Graph, Entra ID, HR, CMDB and asset
    inventory data.
    """

    if enriched_identity is None:
        return {
            "score": 0,
            "impact": "Unknown",
            "confidence": "Low",
            "escalation": "Identity enrichment required",
            "evidence": [
                "No enriched identity was available for business-impact assessment."
            ],
        }

    score = 0
    evidence = []

    privilege_level = str(
        enriched_identity.get("privilege_level", "Unknown")
    ).lower()

    vip = enriched_identity.get("vip", False)

    criticality = str(
        enriched_identity.get("criticality", "Unknown")
    ).lower()

    department = str(
        enriched_identity.get("department", "Unknown")
    ).lower()

    job_title = str(
        enriched_identity.get("job_title", "Unknown")
    ).lower()

    account_type = str(
        enriched_identity.get("account_type", "Unknown")
    ).lower()

    device_count = enriched_identity.get("device_count", 0)

    # Privileged identities can affect a wider part of the environment.
    if privilege_level in {
        "administrator",
        "admin",
        "privileged",
        "global administrator",
        "high",
    }:
        score += 30
        evidence.append(
            "The affected identity has elevated or administrative privileges."
        )

    # VIP identities may create regulatory, reputational or executive risk.
    if vip is True:
        score += 25
        evidence.append(
            "The affected identity is classified as a VIP."
        )

    # Criticality represents the organisation's classification of the account.
    if criticality == "critical":
        score += 25
        evidence.append(
            "The identity is classified as business critical."
        )
    elif criticality == "high":
        score += 20
        evidence.append(
            "The identity has high organisational criticality."
        )
    elif criticality == "medium":
        score += 10
        evidence.append(
            "The identity has medium organisational criticality."
        )

    # Certain departments commonly handle sensitive systems or information.
    sensitive_departments = {
        "finance",
        "treasury",
        "legal",
        "human resources",
        "hr",
        "executive",
        "information security",
        "cyber security",
        "it",
    }

    if department in sensitive_departments:
        score += 15
        evidence.append(
            f"The identity belongs to a sensitive department: {department.title()}."
        )

    # Leadership roles may carry greater authority and business exposure.
    leadership_keywords = {
        "chief",
        "director",
        "executive",
        "president",
        "vice president",
        "head of",
        "manager",
    }

    if any(keyword in job_title for keyword in leadership_keywords):
        score += 15
        evidence.append(
            "The affected identity holds a leadership or decision-making role."
        )

    # Non-human accounts may have broad automated access.
    if account_type in {
        "service account",
        "application",
        "shared account",
        "automation account",
    }:
        score += 20
        evidence.append(
            "The affected identity is a non-standard account that may have broad access."
        )

    # Multiple associated devices increase the possible exposure surface.
    if isinstance(device_count, int) and device_count >= 5:
        score += 10
        evidence.append(
            "The identity is associated with five or more devices."
        )
    elif isinstance(device_count, int) and device_count >= 1:
        score += 5
        evidence.append(
            "The identity is associated with one or more devices."
        )

    score = min(score, 100)

    if score >= 70:
        impact = "Critical"
        escalation = "Immediate business and security escalation required"
    elif score >= 45:
        impact = "High"
        escalation = "Priority escalation and stakeholder notification recommended"
    elif score >= 20:
        impact = "Medium"
        escalation = "Standard security escalation may be required"
    else:
        impact = "Low"
        escalation = "Handle through the normal investigation process"

    known_fields = 0

    fields_to_check = [
        enriched_identity.get("department"),
        enriched_identity.get("job_title"),
        enriched_identity.get("privilege_level"),
        enriched_identity.get("criticality"),
        enriched_identity.get("account_type"),
    ]

    for value in fields_to_check:
        if value not in {None, "", "Unknown"}:
            known_fields += 1

    if known_fields >= 4:
        confidence = "High"
    elif known_fields >= 2:
        confidence = "Medium"
    else:
        confidence = "Low"

    if not evidence:
        evidence.append(
            "No high-impact identity attributes were identified."
        )

    return {
        "score": score,
        "impact": impact,
        "confidence": confidence,
        "escalation": escalation,
        "evidence": evidence,
    }