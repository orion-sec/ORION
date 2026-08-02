from reasoners.hypothesis_reasoner import reason_from_infrastructure

"""
Hypothesis Pipeline

Transforms Finding objects into Hypothesis objects.
"""


def generate_hypotheses(findings):
    """
    Executes the Hypothesis stage.
    """

    hypotheses = []

    hypotheses.extend(

        reason_from_infrastructure(findings)

    )

    return hypotheses