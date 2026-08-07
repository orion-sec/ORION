from models.signin_evidence import SignInEvidence
from reasoners.infrastructure_reasoner import reason_about_infrastructure
from reasoners.network_reasoner import reason_about_network
from reasoners.signin_reasoner import reason_about_signin

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
        # Microsoft Entra sign-in evidence
        if isinstance(item, SignInEvidence):
            findings.extend(reason_about_signin(item))
            continue

        # Existing dictionary-based evidence
        if not isinstance(item, dict):
            continue

        category = item.get("category")

        if not isinstance(category, str):
            continue

        handler = REASONING_ROUTES.get(category)

        if handler:
            finding = handler(item)

            if finding is not None:
                findings.append(finding)

    return findings
