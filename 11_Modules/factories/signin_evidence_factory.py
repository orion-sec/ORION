from typing import Any

from models.signin_evidence import SignInEvidence


def create_signin_evidence(
    raw_event: dict[str, Any],
) -> SignInEvidence:
    """
    Converts a raw Microsoft Entra SigninLogs row
    into an ORION SignInEvidence model.
    """

    device_detail = raw_event.get("DeviceDetail", {})

    if not isinstance(device_detail, dict):
        device_detail = {}

    autonomous_system_number = raw_event.get(
        "AutonomousSystemNumber"
    )

    if not isinstance(autonomous_system_number, int):
        autonomous_system_number = None

    return SignInEvidence(
        time_generated=str(
            raw_event.get("TimeGenerated", "")
        ),
        user_principal_name=str(
            raw_event.get("UserPrincipalName", "")
        ),
        user_id=str(
            raw_event.get("UserId", "")
        ),
        ip_address=str(
            raw_event.get("IPAddress", "")
        ),
        autonomous_system_number=autonomous_system_number,
        application=str(
            raw_event.get("AppDisplayName", "")
        ),
        result_type=str(
            raw_event.get("ResultType", "")
        ),
        result_description=str(
            raw_event.get("ResultDescription", "")
        ),
        client_app=str(
            raw_event.get("ClientAppUsed", "")
        ),
        user_agent=str(
            raw_event.get("UserAgent", "")
        ),
        conditional_access_status=str(
            raw_event.get("ConditionalAccessStatus", "")
        ),
        risk_level=str(
            raw_event.get("RiskLevelDuringSignIn", "")
        ),
        location=str(
            raw_event.get("Location", "")
        ),
        device_detail=device_detail,
        correlation_id=str(
            raw_event.get("CorrelationId", "")
        ),
        raw_metadata=raw_event,
    )