from correlation.entity_correlator import correlate_entities
from models.security_incident import SecurityIncident


def test_independent_incidents_do_not_share_correlation_entities() -> None:
    incident_one = SecurityIncident(
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
                    "userPrincipalName": "user1@oriondefense.ai",
                },
            },
            {
                "kind": "Ip",
                "properties": {
                    "address": "185.10.20.30",
                },
            },
        ],
    )

    incident_two = SecurityIncident(
        incident_id="incident-002",
        title="Malware Detection",
        severity="High",
        status="New",
        created_time_utc="2026-08-10T09:05:00Z",
        source_provider="Microsoft",
        source_product="Microsoft Sentinel",
        entities=[
            {
                "kind": "Account",
                "properties": {
                    "userPrincipalName": "user2@oriondefense.ai",
                },
            },
            {
                "kind": "Ip",
                "properties": {
                    "address": "203.0.113.55",
                },
            },
        ],
    )

    result_one = correlate_entities(
        [incident_one]
    )

    result_two = correlate_entities(
        [incident_two]
    )

    assert result_one["entities"]["user"] == [
        "user1@oriondefense.ai"
    ]

    assert result_one["entities"]["ip"] == [
        "185.10.20.30"
    ]

    assert "user2@oriondefense.ai" not in (
        result_one["entities"]["user"]
    )

    assert "203.0.113.55" not in (
        result_one["entities"]["ip"]
    )

    assert result_two["entities"]["user"] == [
        "user2@oriondefense.ai"
    ]

    assert result_two["entities"]["ip"] == [
        "203.0.113.55"
    ]

    assert "user1@oriondefense.ai" not in (
        result_two["entities"]["user"]
    )

    assert "185.10.20.30" not in (
        result_two["entities"]["ip"]
    )