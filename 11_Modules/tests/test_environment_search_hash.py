from unittest.mock import MagicMock

import pytest

from providers.environment_search_provider import (
    EnvironmentSearchProvider,
)


@pytest.mark.parametrize(
    ("file_hash", "expected_field"),
    [
        ("a" * 64, "SHA256"),
        ("b" * 40, "SHA1"),
        ("c" * 32, "MD5"),
    ],
)
def test_search_file_hash_activity(
    file_hash: str,
    expected_field: str,
) -> None:
    """
    Verify that ORION maps SHA256, SHA1 and MD5 hashes
    to the correct Defender telemetry field.
    """

    provider = object.__new__(
        EnvironmentSearchProvider
    )

    provider.get_workspace_id = MagicMock(
        return_value="test-workspace-id"
    )

    provider.client = MagicMock()

    provider.client.run_kql.return_value = {
        "tables": [
            {
                "columns": [
                    {
                        "name": "Timestamp",
                        "type": "datetime",
                    },
                    {
                        "name": "DeviceName",
                        "type": "string",
                    },
                    {
                        "name": expected_field,
                        "type": "string",
                    },
                ],
                "rows": [
                    [
                        "2026-08-10T10:00:00Z",
                        "ORION-LAPTOP-01",
                        file_hash,
                    ]
                ],
            }
        ]
    }

    results = provider.search_file_hash_activity(
        file_hash=file_hash,
        timespan="P7D",
        limit=25,
    )

    assert len(results) == 1

    assert (
        results[0]["DeviceName"]
        == "ORION-LAPTOP-01"
    )

    assert (
        results[0][expected_field]
        == file_hash
    )

    call_arguments = (
        provider.client.run_kql.call_args.kwargs
    )

    assert (
        call_arguments["workspace_id"]
        == "test-workspace-id"
    )

    assert (
        f'{expected_field} =~ "{file_hash}"'
        in call_arguments["query"]
    )

    assert (
        "DeviceFileEvents"
        in call_arguments["query"]
    )

    assert (
        "DeviceProcessEvents"
        in call_arguments["query"]
    )

    assert call_arguments["timespan"] == "P7D"


def test_search_file_hash_rejects_invalid_hash_length() -> None:
    """
    Verify that ORION rejects values that cannot represent
    MD5, SHA1 or SHA256 hashes.
    """

    provider = object.__new__(
        EnvironmentSearchProvider
    )

    provider.get_workspace_id = MagicMock(
        return_value="test-workspace-id"
    )

    provider.client = MagicMock()

    with pytest.raises(
        ValueError,
        match="Unsupported file hash length",
    ):
        provider.search_file_hash_activity(
            file_hash="not-a-valid-hash",
        )