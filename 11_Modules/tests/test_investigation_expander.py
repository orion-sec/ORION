from correlation.investigation_expander import (
    expand_investigation,
)
from models.signin_evidence import SignInEvidence


def test_expand_investigation_summarises_related_entities() -> None:
    sign_in = SignInEvidence(
        time_generated="2026-08-11T10:00:00Z",
        user_principal_name="user@oriondefense.ai",
        user_id="user-001",
        ip_address="185.10.20.30",
        device_detail={
            "displayName": "ORION-LAPTOP-01",
        },
    )

    environment_evidence = [
        sign_in,
        {
            "DeviceName": "ORION-SERVER-01",
            "RemoteIP": "185.10.20.31",
            "SHA256": "a" * 64,
            "Domain": "malicious-example.com",
            "RemoteUrl": (
                "https://malicious-example.com/login"
            ),
        },
        {
            "UserPrincipalName":
                "user@oriondefense.ai",
            "IPAddress": "185.10.20.30",
        },
    ]

    result = expand_investigation(
        environment_evidence
    )

    assert result["expanded"] is True
    assert result["evidence_count"] == 3

    assert result["entities"]["users"] == [
        "user@oriondefense.ai"
    ]

    assert result["entities"]["ips"] == [
        "185.10.20.30",
        "185.10.20.31",
    ]

    assert result["entities"]["devices"] == [
        "ORION-LAPTOP-01",
        "ORION-SERVER-01",
    ]

    assert result["entities"]["file_hashes"] == [
        "a" * 64
    ]

    assert result["entities"]["domains"] == [
        "malicious-example.com"
    ]

    assert result["entities"]["urls"] == [
        "https://malicious-example.com/login"
    ]

    assert result["affected_entity_count"] == 8