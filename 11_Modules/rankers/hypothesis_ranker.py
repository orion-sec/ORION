"""
Hypothesis Ranker

Ranks competing hypotheses by confidence.
"""


def rank_hypotheses(hypotheses):
    """
    Returns hypotheses sorted by confidence (highest first).
    """

    return sorted(
        hypotheses,
        key=lambda hypothesis: hypothesis.confidence,
        reverse=True
    )