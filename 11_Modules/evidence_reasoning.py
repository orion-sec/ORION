from reasoners.infrastructure_reasoner import reason_about_infrastructure
from reasoners.network_reasoner import reason_about_network

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