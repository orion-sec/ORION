from rankers.hypothesis_ranker import rank_hypotheses
from reasoners.hypothesis_reasoner import reason_from_infrastructure


"""
Hypothesis Pipeline

Generates and ranks competing investigation hypotheses.
"""


def generate_hypotheses(findings):
    """
    Executes the Hypothesis stage.
    """

    hypotheses = []

    hypotheses.extend(
        reason_from_infrastructure(findings)
    )

    return rank_hypotheses(hypotheses)