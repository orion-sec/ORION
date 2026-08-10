from unittest.mock import MagicMock

from correlation.entity_correlator import correlate_entities
from models.security_incident import SecurityIncident
from models.signin_evidence import SignInEvidence
from providers.environment_search_provider import (
    EnvironmentSearchProvider,
)


def test_correlation_environment_chain() -> None:
    """
    Prove that ORION can extract correlation pivots from one
    investigation and route them into environment searching
    without merging unrelated incidents.
    """

    test_hash = "a" * 64

    test_domain = "malicious-example.com"
    test_url = "https://malicious-example.com/login"

    incident = SecurityIncident(
        incident_id="incident-001",
        title="Suspicious execution with related indicators",
        severity="High",
        status="New",
        created_time_utc="2026-08-10T10:00:00Z",
        source_provider="Microsoft",
        source_product="Microsoft Sentinel",
        entities=[
            {
                "kind": "Account",
                "properties": {
                    "userPrincipalName": (
                        "samuel@oriondefense.ai"
                    ),
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
        time_generated="2026-08-10T10:01:00Z",
        user_principal_name="samuel@oriondefense.ai",
        user_id="user-001",
        ip_address="185.10.20.30",
        device_detail={
            "deviceId": "device-001",
            "displayName": "ORION-LAPTOP-01",
        },
    )

    hash_evidence = {
        "sha256": test_hash,
    }

    domain_evidence = {
        "domain": test_domain,
    }

    url_evidence = {
        "url": test_url,
    }

    correlation = correlate_entities(
        [
            incident,
            sign_in,
            hash_evidence,
            domain_evidence,
            url_evidence,
        ]
    )

    assert correlation["search_required"] is True

    assert {
        "type": "user",
        "value": "samuel@oriondefense.ai",
    } in correlation["correlation_keys"]

    assert {
        "type": "ip",
        "value": "185.10.20.30",
    } in correlation["correlation_keys"]

    assert {
        "type": "device",
        "value": "ORION-LAPTOP-01",
    } in correlation["correlation_keys"]

    assert {
        "type": "file_hash",
        "value": test_hash,
    } in correlation["correlation_keys"]

    assert {
        "type": "domain",
        "value": test_domain,
    } in correlation["correlation_keys"]

    assert {
    "type": "url",
    "value": test_url,
} in correlation["correlation_keys"]

    provider = object.__new__(
        EnvironmentSearchProvider
    )

    provider.search_user_signins = MagicMock(
        return_value=[]
    )

    provider.search_ip_signins = MagicMock(
        return_value=[]
    )

    provider.search_device_activity = MagicMock(
        return_value=[]
    )

    provider.search_file_hash_activity = MagicMock(
        return_value=[]
    )

    provider.search_domain_activity = MagicMock(
        return_value=[]
    )

    provider.search_url_activity = MagicMock(
    return_value=[]
)

    environment_results = provider.search(
        correlation_keys=correlation["correlation_keys"],
        timespan="P7D",
    )

    result_types = {
        result["type"]
        for result in environment_results["results"]
    }

    assert "user" in result_types
    assert "ip" in result_types
    assert "device" in result_types
    assert "file_hash" in result_types
    assert "domain" in result_types
    assert "url" in result_types

    provider.search_user_signins.assert_called_once_with(
        user_principal_name="samuel@oriondefense.ai",
        timespan="P7D",
    )

    provider.search_ip_signins.assert_called_once_with(
        ip_address="185.10.20.30",
        timespan="P7D",
    )

    provider.search_device_activity.assert_any_call(
        device_name="ORION-LAPTOP-01",
        timespan="P7D",
    )

    provider.search_file_hash_activity.assert_called_once_with(
        file_hash=test_hash,
        timespan="P7D",
    )

    provider.search_domain_activity.assert_called_once_with(
        domain=test_domain,
        timespan="P7D",
    )

    provider.search_url_activity.assert_called_once_with(
    url=test_url,
    timespan="P7D",
)