from models.question import Question


"""
Question Factory

Creates Question cognitive objects from investigation findings.

Factories create objects.
They do not perform investigation logic.
"""


def create_question(question, reason):
    """
    Creates a Question cognitive model.
    """
    return Question(
        question=question,
        reason=reason
    )


def generate_infrastructure_questions(finding):
    """
    Generates investigation questions from infrastructure findings.
    """
    return [
        create_question(
            question="Is this infrastructure expected for this environment?",
            reason=finding.finding
        )
    ]


QUESTION_GENERATORS = {
    "Infrastructure": generate_infrastructure_questions,
}


def create_questions_from_findings(findings):
    """
    Creates Question objects from investigation findings.
    """

    questions = []

    for finding in findings:

        category = finding.category

        handler = QUESTION_GENERATORS.get(category)

        if handler:

            questions.extend(
                handler(finding)
            )

    return questions