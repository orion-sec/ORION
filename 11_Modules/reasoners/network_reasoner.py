from factories.finding_factory import create_finding


"""
Network Reasoner

Responsible for reasoning about network evidence.

Reasoners analyze evidence.
They do not create models directly.
"""


def reason_about_network(item):
    """
    Produces network findings from network evidence.
    """

    return create_finding(
        "Network",
        (
            "The investigated IP is publicly accessible "
            "over the Internet."
        )
    )