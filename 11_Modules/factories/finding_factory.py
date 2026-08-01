from models.finding import Finding

"""
Finding Factory

Creates Finding cognitive objects.

Factories create objects.
They do not perform investigation logic.
"""


def create_finding(category, finding):
    """
    Creates a Finding cognitive model.
    """

    return Finding(
        category=category,
        finding=finding
    )