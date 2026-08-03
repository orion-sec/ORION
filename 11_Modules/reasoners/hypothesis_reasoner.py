from factories.hypothesis_factory import create_hypothesis

"""
Hypothesis Reasoner

Produces investigation hypotheses from findings.

Reasoners create explanations,
not evidence.
"""


def reason_from_infrastructure(findings):
    """
    Generates competing hypotheses from infrastructure findings.
    """

    hypotheses = []

    for finding in findings:

        if finding.category != "Infrastructure":
            continue

        hypotheses.extend(
            [
                create_hypothesis(
                    title="Cloud-hosted reconnaissance",
                    explanation=(
                        "Hosted or data-centre infrastructure may be "
                        "supporting externally initiated reconnaissance."
                    ),
                    confidence=40
                ),
                create_hypothesis(
                    title="Legitimate cloud service activity",
                    explanation=(
                        "The infrastructure may belong to an approved "
                        "cloud provider, vendor, scanner, or business service."
                    ),
                    confidence=30
                ),
                create_hypothesis(
                    title="Security testing activity",
                    explanation=(
                        "The observed infrastructure may be associated with "
                        "an authorized vulnerability scan or penetration test."
                    ),
                    confidence=20
                ),
            ]
        )

    return hypotheses