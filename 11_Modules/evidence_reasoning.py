from models.signin_evidence import SignInEvidence
from reasoners.endpoint_reasoner import reason_about_endpoint
from reasoners.file_reasoner import reason_about_file
from reasoners.identity_reasoner import reason_about_identity
from reasoners.infrastructure_reasoner import reason_about_infrastructure
from reasoners.malware_reasoner import reason_about_malware
from reasoners.network_reasoner import reason_about_network
from reasoners.process_reasoner import reason_about_process
from reasoners.signin_reasoner import reason_about_signin

REASONING_ROUTES = {
    "Endpoint": reason_about_endpoint,
    "File": reason_about_file,
    "Identity": reason_about_identity,
    "Infrastructure": reason_about_infrastructure,
    "Malware": reason_about_malware,
    "Network": reason_about_network,
    "Process": reason_about_process,
}


def reason_over_evidence(evidence):
    """
    Converts structured evidence into structured findings.
    """

    findings = []

    for item in evidence:
        #
        # Microsoft Entra sign-in evidence.
        #
        if isinstance(item, SignInEvidence):
            findings.extend(
                reason_about_signin(item)
            )
            continue

        #
        # Dictionary-based evidence.
        #
        if not isinstance(item, dict):
            continue

        category = item.get("category")

        if not isinstance(category, str):
            continue

        handler = REASONING_ROUTES.get(
            category
        )

        if handler is None:
            continue

        finding = handler(item)

        if finding is not None:
            findings.append(finding)

    return findings
