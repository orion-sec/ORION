from unittest.mock import MagicMock

from providers.environment_search_provider import (
    EnvironmentSearchProvider,
)


def test_environment_search_routes_file_hash() -> None:
    """
    Verify that an ORION file_hash correlation pivot is
    routed automatically to endpoint hash hunting.
    """

    provider = object.__new__(
        EnvironmentSearchProvider
    )

    test_hash = "a" * 64

    provider.search_file_hash_activity = MagicMock(
        return_value=[
            {
                "Timestamp": "2026-08-10T10:00:00Z",
                "DeviceName": "ORION-LAPTOP-01",
                "SHA256": test_hash,
                "FileName": "suspicious.exe",
            }
        ]
    )

    results = provider.search(
        correlation_keys=[
            {
                "type": "file_hash",
                "value": test_hash,
            }
        ],
        timespan="P7D",
    )

    assert results["search_count"] == 1

    assert len(results["results"]) == 1

    hash_result = results["results"][0]

    assert hash_result["type"] == "file_hash"

    assert hash_result["value"] == test_hash

    assert (
        hash_result["source"]
        == "Microsoft Defender Endpoint Telemetry"
    )

    assert hash_result["match_count"] == 1

    assert (
        hash_result["matches"][0]["FileName"]
        == "suspicious.exe"
    )

    provider.search_file_hash_activity.assert_called_once_with(
        file_hash=test_hash,
        timespan="P7D",
    )