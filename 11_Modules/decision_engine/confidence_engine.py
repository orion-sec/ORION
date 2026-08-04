from models.confidence_assessment import ConfidenceAssessment


"""
ORION Confidence Engine

Combines normalized investigation-risk signals into one
explainable confidence score.
"""


DEFAULT_WEIGHTS = {
    "evidence_strength": 0.35,
    "identity_risk": 0.15,
    "threat_intelligence_risk": 0.15,
    "hypothesis_support": 0.15,
    "business_context_risk": 0.10,
    "historical_behavior_risk": 0.05,
    "detection_quality": 0.05,
}


def validate_score(name, score):
    """
    Ensures a score is numeric and within the 0–100 range.
    """

    if not isinstance(score, (int, float)):
        raise TypeError(f"{name} must be a number.")

    if not 0 <= score <= 100:
        raise ValueError(f"{name} must be between 0 and 100.")


def calculate_confidence(signals, weights=None):
    """
    Calculates an explainable weighted confidence score.

    Args:
        signals:
            Dictionary containing normalized risk scores.

        weights:
            Optional custom weighting dictionary.

    Returns:
        ConfidenceAssessment
    """

    active_weights = weights or DEFAULT_WEIGHTS

    breakdown = {}
    explanations = []

    for signal_name, weight in active_weights.items():

        score = signals.get(signal_name, 0)

        validate_score(signal_name, score)

        contribution = score * weight

        breakdown[signal_name] = round(contribution, 2)

        explanations.append(
            (
                f"{signal_name.replace('_', ' ').title()} "
                f"contributed {contribution:.2f} points "
                f"from a score of {score}/100 "
                f"with a weight of {weight:.0%}."
            )
        )

    final_score = round(sum(breakdown.values()))

    final_score = max(0, min(100, final_score))

    return ConfidenceAssessment(
        final_score=final_score,
        breakdown=breakdown,
        weights=active_weights.copy(),
        explanations=explanations
    )