from unittest.mock import MagicMock

from models.security_incident import SecurityIncident
from pipeline import (
    entity_correlation_stage,
    environment_search_stage,
)


def test_pipeline_correlates_and_searches_environment() -> None:
    """
    Verify that an independent security incident can produce
    correlation pivots which are then passed to environment search.
    """

    incident = SecurityIncident(
        incident_id="INC-1001",
        title="Suspicious identity activity",
        severity="High",
        status="New",
        created_time_utc="2026-08-10T10:00:00Z",
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

    results = {
        "Security Incidents": [incident],
        "Sign-In Evidence": [],
        "Evidence": [],
    }

    results = entity_correlation_stage(
        "",
        results,
    )

    correlation = results[
        "Entity Correlation"
    ]

    assert correlation["entity_count"] == 3

    provider = MagicMock()

    provider.search.return_value = {
        "workspace_id": "workspace-001",
        "timespan": "P7D",
        "search_count": 3,
        "results": [
            {
                "entity_type": "user",
                "value": "samuel@oriondefense.ai",
                "source": "Microsoft Entra SigninLogs",
                "match_count": 1,
                "matches": [
                    {
                        "UserPrincipalName":
                            "samuel@oriondefense.ai",
                        "IPAddress":
                            "185.10.20.30",
                    }
                ],
            }
        ],
    }

    results[
        "Environment Search Provider"
    ] = provider

    results = environment_search_stage(
        "",
        results,
    )

    provider.search.assert_called_once()

    call_arguments = (
        provider.search.call_args.kwargs
    )

    correlation_keys = call_arguments[
        "correlation_keys"
    ]

    assert {
        "type": "user",
        "value": "samuel@oriondefense.ai",
    } in correlation_keys

    assert {
        "type": "ip",
        "value": "185.10.20.30",
    } in correlation_keys

    assert {
        "type": "device",
        "value": "ORION-LAPTOP-01",
    } in correlation_keys

    assert (
        call_arguments["timespan"]
        == "P7D"
    )

    assert (
        len(results["Environment Evidence"])
        == 1
    )

    assert (
        results["Environment Evidence"][0][
            "IPAddress"
        ]
        == "185.10.20.30"
    )