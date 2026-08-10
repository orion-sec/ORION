from unittest.mock import MagicMock

from providers.environment_search_provider import (
    EnvironmentSearchProvider,
)


def test_environment_search_routes_domain() -> None:
    """
    Prove that a domain correlation pivot is routed
    to Microsoft domain activity searching.
    """

    provider = object.__new__(
        EnvironmentSearchProvider
    )

    provider.search_domain_activity = MagicMock(
        return_value=[
            {
                "RemoteUrl": "malicious-example.com",
                "DeviceName": "ORION-LAPTOP-01",
            }
        ]
    )

    results = provider.search(
        correlation_keys=[
            {
                "type": "domain",
                "value": "malicious-example.com",
            }
        ],
        timespan="P7D",
    )

    assert results["search_count"] == 1
    assert len(results["results"]) == 1

    domain_result = results["results"][0]

    assert domain_result["type"] == "domain"
    assert (
        domain_result["value"]
        == "malicious-example.com"
    )
    assert domain_result["match_count"] == 1

    provider.search_domain_activity.assert_called_once_with(
        domain="malicious-example.com",
        timespan="P7D",
    )