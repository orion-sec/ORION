from factories.finding_factory import create_finding
from models.signin_evidence import SignInEvidence

"""
Sign-In Evidence Reasoner

Responsible for reasoning about Microsoft Entra sign-in evidence.

Reasoners analyze evidence.
They do not create models directly.
"""


def reason_about_signin(event: SignInEvidence):
    """
    Produces investigation findings from Microsoft Entra sign-in evidence.
    """

    findings = []

    # Failed authentication
    if event.result_type and event.result_type != "0":
        findings.append(
            create_finding(
                "Authentication",
                (
                    f"Failed Microsoft Entra sign-in observed for "
                    f"{event.user_principal_name} from IP "
                    f"{event.ip_address}."
                ),
            )
        )

    # Risk detected by Microsoft Entra
    if event.risk_level.lower() in {
        "low",
        "medium",
        "high",
        "atRisk".lower(),
    }:
        findings.append(
            create_finding(
                "Identity Risk",
                (
                    f"Microsoft Entra reported sign-in risk "
                    f"'{event.risk_level}' for "
                    f"{event.user_principal_name}."
                ),
            )
        )

    # Conditional Access not applied
    if event.conditional_access_status.lower() == "notapplied":
        findings.append(
            create_finding(
                "Conditional Access",
                (
                    f"Conditional Access was not applied to the "
                    f"sign-in for {event.user_principal_name}."
                ),
            )
        )

    # Unmanaged device
    if event.device_detail:
        is_managed = event.device_detail.get("isManaged")
        is_compliant = event.device_detail.get("isCompliant")

        if is_managed is False:
            findings.append(
                create_finding(
                    "Device Trust",
                    (
                        f"Sign-in for {event.user_principal_name} "
                        f"originated from an unmanaged device."
                    ),
                )
            )

        if is_compliant is False:
            findings.append(
                create_finding(
                    "Device Compliance",
                    (
                        f"Sign-in for {event.user_principal_name} "
                        f"originated from a non-compliant device."
                    ),
                )
            )

    return findings