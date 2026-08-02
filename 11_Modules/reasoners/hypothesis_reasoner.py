from factories.hypothesis_factory import create_hypothesis

"""
Hypothesis Reasoner

Produces investigation hypotheses from findings.

Reasoners create explanations,
not evidence.
"""


def reason_from_infrastructure(findings):
    """
    Generates hypotheses from infrastructure findings.
    """

    hypotheses = []

    for finding in findings:

        if finding.category != "Infrastructure":
            continue

        hypotheses.append(

            create_hypothesis(

                title="Cloud-hosted scanning activity",

                explanation=(
                    "The hosted infrastructure findings may indicate "
                    "externally hosted reconnaissance."
                ),

                confidence=40
            )

        )

    return hypotheses