from rankers.hypothesis_ranker import rank_hypotheses
from reasoners.hypothesis_reasoner import reason_from_findings

"""
Hypothesis Pipeline

Generates and ranks competing investigation hypotheses.
"""


def generate_hypotheses(findings):
    """
    Executes the Hypothesis stage.
    """

    hypotheses = reason_from_findings(findings)

    return rank_hypotheses(hypotheses)
