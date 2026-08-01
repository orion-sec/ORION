from factories.finding_factory import create_finding


"""
Infrastructure Reasoner

Responsible for reasoning about infrastructure evidence.

Reasoners analyze evidence.
They do not create models directly.
"""


def reason_about_infrastructure(item):
    """
    Produces infrastructure findings from infrastructure evidence.
    """

    return create_finding(
        "Infrastructure",
        (
            "The investigated IP appears to originate "
            "from hosted or data-centre infrastructure."
        )
    )