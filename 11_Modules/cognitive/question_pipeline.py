from factories.question_factory import create_questions_from_findings

"""
Question Pipeline

Transforms Finding objects into Question objects.
"""


def generate_questions(findings):
    """
    Executes the Question stage.
    """

    return create_questions_from_findings(findings)