from factories.narrative_factory import create_incident_narrative


"""
ORION Incident Narrative Generator

Transforms a structured investigation outcome and alert context
into an analyst-ready executive summary and verdict.
"""


def _get_disposition_value(outcome):
    """
    Safely returns a human-readable disposition value.
    """

    disposition = getattr(outcome, "disposition", "Unknown")

    return getattr(
        disposition,
        "value",
        str(disposition)
    )


def _get_process_chain(alert_details):
    """
    Builds a readable parent-child process chain.
    """

    processes = [
        alert_details.get("parent_process"),
        alert_details.get("child_process"),
        alert_details.get("grandchild_process")
    ]

    processes = [
        process
        for process in processes
        if process
    ]

    if not processes:
        return "No process chain was available"

    return " -> ".join(processes)


def _build_key_evidence(outcome, maximum_items=8):
    """
    Returns the most relevant evidence items for the narrative.
    """

    evidence = getattr(
        outcome,
        "supporting_evidence",
        []
    )

    return evidence[:maximum_items]


def generate_incident_narrative(alert_details, outcome):
    """
    Produces an analyst-ready incident narrative.

    Args:
        alert_details:
            Dictionary containing normalized alert context.

        outcome:
            ORION InvestigationOutcome object.

    Returns:
        IncidentNarrative
    """

    disposition = _get_disposition_value(outcome)
    confidence = getattr(outcome, "confidence", 0)

    severity = alert_details.get(
        "severity",
        "Unknown"
    )

    title = alert_details.get(
        "title",
        "Security investigation"
    )

    hostname = alert_details.get(
        "hostname",
        "an unknown endpoint"
    )

    user = alert_details.get(
        "user",
        "an unknown user"
    )

    department = alert_details.get(
        "department",
        "an unspecified business area"
    )

    asset_criticality = alert_details.get(
        "asset_criticality",
        "Unknown"
    )

    process_chain = _get_process_chain(
        alert_details
    )

    reason = getattr(
        outcome,
        "reason",
        "No investigation reason was provided."
    )

    key_evidence = _build_key_evidence(
        outcome
    )

    executive_summary = (
        f"ORION investigated the alert '{title}' affecting "
        f"{hostname} and user {user}. The observed process chain was "
        f"{process_chain}. The affected asset belongs to the "
        f"{department} function and has an asset criticality rating of "
        f"{asset_criticality}. "
        f"The investigation was classified as {disposition} with "
        f"{confidence}% confidence. {reason}"
    )

    if disposition == "True Positive":
        analyst_verdict = (
            "This incident represents confirmed malicious or unauthorised "
            "activity requiring immediate containment, evidence preservation, "
            "scope assessment and incident-response escalation."
        )

    elif disposition == "False Positive":
        analyst_verdict = (
            "The alert did not represent malicious activity. The triggering "
            "detection condition should be reviewed and tuned where appropriate."
        )

    elif disposition == "Benign Positive":
        analyst_verdict = (
            "The activity was correctly detected but was verified as legitimate "
            "and authorised. Retain the validation evidence before closure."
        )

    elif disposition == "Authorized Security Testing":
        analyst_verdict = (
            "The observed behaviour matched an approved security-testing "
            "activity. Confirm scope compliance and retain the evidence for audit."
        )

    elif disposition == "Authorized Administrative Activity":
        analyst_verdict = (
            "The activity was performed for an approved administrative purpose. "
            "Confirm privileged-access compliance before closure."
        )

    elif disposition == "Misconfiguration":
        analyst_verdict = (
            "The investigation identified a security configuration weakness "
            "requiring remediation and post-remediation validation."
        )

    elif disposition == "Policy Violation":
        analyst_verdict = (
            "The investigation confirmed a security-policy violation requiring "
            "documentation, ownership and the approved enforcement process."
        )

    elif disposition == "Infrastructure Issue":
        analyst_verdict = (
            "The alert was associated with an infrastructure or service issue. "
            "Route remediation to the appropriate technical owner while maintaining "
            "security monitoring."
        )

    elif disposition == "Business Risk":
        analyst_verdict = (
            "The investigation identified material business exposure requiring "
            "risk ownership, remediation tracking and control validation."
        )

    elif disposition == "Threat Hunt Candidate":
        analyst_verdict = (
            "The evidence is not conclusive enough for an incident declaration, "
            "but the behaviour warrants proactive hunting across the environment."
        )

    elif disposition == "Suspicious":
        analyst_verdict = (
            "The activity presents a high-risk pattern but requires additional "
            "independent confirmation before it can be declared malicious."
        )

    elif disposition == "Insufficient Evidence":
        analyst_verdict = (
            "A reliable disposition cannot yet be reached because relevant "
            "endpoint, identity, network or threat-intelligence evidence is missing."
        )

    else:
        analyst_verdict = (
            "The available evidence requires additional analyst review before "
            "a final investigation disposition can be approved."
        )

    return create_incident_narrative(
        executive_summary=executive_summary,
        analyst_verdict=analyst_verdict,
        severity=severity,
        disposition=disposition,
        confidence=confidence,
        key_evidence=key_evidence
    )