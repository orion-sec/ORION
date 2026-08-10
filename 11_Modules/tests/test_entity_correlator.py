from correlation.entity_correlator import correlate_entities
from models.security_incident import SecurityIncident
from models.signin_evidence import SignInEvidence


def test_correlate_entities_extracts_shared_entities() -> None:
    incident = SecurityIncident(
        incident_id="incident-001",
        title="Suspicious Sign-In",
        severity="Medium",
        status="New",
        created_time_utc="2026-08-10T09:00:00Z",
        source_provider="Microsoft",
        source_product="Microsoft Sentinel",
        entities=[
            {
                "kind": "Account",
                "properties": {
                    "userPrincipalName": "samuel@oriondefense.ai",
                },
            },
            {
                "kind": "Ip",
                "properties": {
                    "address": "185.10.20.30",
                },
            },
            {
                "kind": "Host",
                "properties": {
                    "hostName": "ORION-LAPTOP-01",
                },
            },
        ],
    )

    sign_in = SignInEvidence(
        time_generated="2026-08-10T09:01:00Z",
        user_principal_name="samuel@oriondefense.ai",
        user_id="user-001",
        ip_address="185.10.20.30",
        device_detail={
            "deviceId": "device-001",
            "displayName": "ORION-LAPTOP-01",
        },
    )

    hash_evidence = {
        "sha256": (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
    }

    domain_evidence = {
        "domain": "malicious-example.com",
    }

    url_evidence = {
        "url": "https://malicious-example.com/login/verify",
    }

    result = correlate_entities(
        [
            incident,
            sign_in,
            hash_evidence,
            domain_evidence,
            url_evidence,
        ]
    )

    assert result["search_required"] is True

    assert result["entities"]["user"] == [
        "samuel@oriondefense.ai"
    ]

    assert result["entities"]["ip"] == [
        "185.10.20.30"
    ]

    assert result["entities"]["device"] == [
        "ORION-LAPTOP-01",
        "device-001",
    ]

    assert result["entities"]["file_hash"] == [
    (
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
]

    assert result["entities"]["domain"] == [
    "malicious-example.com"
]

    assert result["entities"]["url"] == [
    "https://malicious-example.com/login/verify"
]

    assert result["entity_count"] == 7

    assert {
        "type": "user",
        "value": "samuel@oriondefense.ai",
    } in result["correlation_keys"]

    assert {
        "type": "ip",
        "value": "185.10.20.30",
    } in result["correlation_keys"]

    assert {
        "type": "device",
        "value": "ORION-LAPTOP-01",
    } in result["correlation_keys"]

    assert {
        "type": "file_hash",
        "value": (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
    } in result["correlation_keys"]

    assert {
        "type": "domain",
        "value": "malicious-example.com",
    } in result["correlation_keys"]

    assert {
        "type": "url",
        "value": (
            "https://malicious-example.com/login/verify"
        ),
    } in result["correlation_keys"]
