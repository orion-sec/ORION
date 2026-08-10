from unittest.mock import MagicMock

from providers.environment_search_provider import (
    EnvironmentSearchProvider,
)


def test_environment_search_routes_url() -> None:
    """
    Prove that ORION routes a URL correlation pivot
    into Microsoft Defender network telemetry.
    """

    provider = object.__new__(EnvironmentSearchProvider)

    provider.search_url_activity = MagicMock(
        return_value=[
            {
                "Timestamp": "2026-08-10T10:05:00Z",
                "DeviceName": "ORION-LAPTOP-01",
                "RemoteUrl": "https://malicious-example.com/login",
                "InitiatingProcessFileName": "msedge.exe",
            }
        ]
    )

    test_url = "https://malicious-example.com/login"

    results = provider.search(
        correlation_keys=[
            {
                "type": "url",
                "value": test_url,
            }
        ],
        timespan="P7D",
    )

    assert results["search_count"] == 1
    assert len(results["results"]) == 1

    url_result = results["results"][0]

    assert url_result["type"] == "url"
    assert url_result["value"] == test_url

    assert (
        url_result["source"]
        == "Microsoft Defender Network Telemetry"
    )

    assert url_result["match_count"] == 1

    assert (
        url_result["matches"][0]["RemoteUrl"]
        == test_url
    )

    provider.search_url_activity.assert_called_once_with(
        url=test_url,
        timespan="P7D",
    )