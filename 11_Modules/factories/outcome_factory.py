from models.investigation_outcome import InvestigationOutcome

"""
Outcome Factory

Creates standardized investigation outcome objects.
"""


def create_outcome(
    disposition,
    confidence,
    reason,
    supporting_evidence=None,
    contradicting_evidence=None,
    unresolved_questions=None,
    recommended_actions=None
):
    """
    Creates an InvestigationOutcome cognitive model.
    """

    return InvestigationOutcome(
        disposition=disposition,
        confidence=confidence,
        reason=reason,
        supporting_evidence=supporting_evidence or [],
        contradicting_evidence=contradicting_evidence or [],
        unresolved_questions=unresolved_questions or [],
        recommended_actions=recommended_actions or []
    )