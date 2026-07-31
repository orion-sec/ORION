def create_finding(category, finding):
    """
    Creates a standardized ORION finding object.
    """
    return {
        "category": category,
        "finding": finding
    }

def reason_about_infrastructure(item):
    """
    Produces an infrastructure finding from infrastructure evidence.
    """
    return create_finding(
        "Infrastructure",
        (
            "The investigated IP appears to originate "
            "from hosted or data-centre infrastructure."
        )
    )

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

REASONING_ROUTES = {
    "Infrastructure": reason_about_infrastructure,
    "Network": reason_about_network,
}

def reason_over_evidence(evidence):
    """
    Converts structured evidence into structured findings.
    """
    findings = []

    for item in evidence:
        category = item.get("category")

        handler = REASONING_ROUTES.get(category)

        if handler:
            findings.append(
                handler(item)
            )

    return findings