from models.hypothesis import Hypothesis

"""
Hypothesis Factory

Creates Hypothesis cognitive objects.

Factories create objects.
They do not perform investigation logic.
"""


def create_hypothesis(title, explanation, confidence=0):
    """
    Creates a Hypothesis cognitive model.
    """

    return Hypothesis(
        title=title,
        explanation=explanation,
        confidence=confidence
    )