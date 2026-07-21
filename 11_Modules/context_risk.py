def assess_contextual_risk(investigation):
    """
    Assess the seriousness of an investigation using behavioural
    and incident-context evidence found in the investigation narrative.
    """

    investigation_text = investigation.lower()

    score = 0
    evidence = []

    if any(
        phrase in investigation_text
        for phrase in [
            "entered credentials",
            "submitted credentials",
            "entered password",
            "submitted password",
            "provided credentials",
            "login details entered",
        ]
    ):
        score += 25
        evidence.append("User credentials were submitted to a suspicious page.")

    if any(
        phrase in investigation_text
        for phrase in [
            "mfa disabled",
            "mfa bypassed",
            "mfa method changed",
            "authentication method changed",
            "new mfa device registered",
        ]
    ):
        score += 25
        evidence.append("Suspicious MFA or authentication-method activity identified.")

    if any(
        phrase in investigation_text
        for phrase in [
            "inbox rule created",
            "forwarding rule created",
            "mail forwarding enabled",
            "external forwarding rule",
            "suspicious inbox rule",
        ]
    ):
        score += 20
        evidence.append("Suspicious mailbox rule or forwarding activity identified.")

    if any(
        phrase in investigation_text
        for phrase in [
            "impossible travel",
            "unusual sign-in",
            "suspicious sign-in",
            "foreign login",
            "login from another country",
        ]
    ):
        score += 15
        evidence.append("Suspicious authentication activity identified.")

        # Detect sensitive mailbox or data access using concept matching
    mailbox_keywords = [
        "mailbox",
        "email",
        "mail",
    ]

    access_keywords = [
        "access",
        "accessed",
        "opened",
        "read",
    ]

    sensitive_keywords = [
        "sensitive",
        "confidential",
        "restricted",
    ]

    if (
        any(word in investigation_text for word in mailbox_keywords)
        and any(word in investigation_text for word in access_keywords)
        and any(word in investigation_text for word in sensitive_keywords)
    ):
        score += 15
        evidence.append("Potential access to sensitive mailbox or confidential information identified.")

    if score >= 70:
        severity = "Critical"
        confidence = "High"
        containment = "Immediate containment required"
    elif score >= 45:
        severity = "High"
        confidence = "High"
        containment = "Containment strongly recommended"
    elif score >= 20:
        severity = "Medium"
        confidence = "Medium"
        containment = "Further investigation required"
    else:
        severity = "Low"
        confidence = "Low"
        containment = "Monitor and validate available evidence"

    return {
        "score": score,
        "severity": severity,
        "confidence": confidence,
        "containment": containment,
        "evidence": evidence,
    }