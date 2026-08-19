from cognitive.question_resolver import (
    filter_resolved_questions,
    resolved_evidence_gaps,
)
from factories.question_factory import (
    create_questions_from_findings,
)

"""
Question Pipeline

Transforms Finding objects into evidence-aware Question objects.
"""


def generate_questions(
    findings,
    indicator_intelligence=None,
):
    """
    Execute the Question stage.

    Candidate questions are generated from findings and then
    filtered against investigation facts that are already known.
    """

    questions = create_questions_from_findings(
        findings
    )

    resolved_gaps = resolved_evidence_gaps(
        indicator_intelligence
    )

    return filter_resolved_questions(
        questions,
        resolved_gaps,
    )