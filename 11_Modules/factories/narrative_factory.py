from models.incident_narrative import IncidentNarrative


def create_incident_narrative(
    executive_summary,
    analyst_verdict,
    severity,
    disposition,
    confidence,
    key_evidence=None
):
    """
    Creates a standardized IncidentNarrative object.
    """

    return IncidentNarrative(
        executive_summary=executive_summary,
        analyst_verdict=analyst_verdict,
        severity=severity,
        disposition=disposition,
        confidence=confidence,
        key_evidence=key_evidence or []
    )