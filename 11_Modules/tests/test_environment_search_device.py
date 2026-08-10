from unittest.mock import MagicMock, patch

from providers.environment_search_provider import EnvironmentSearchProvider


def test_environment_search_provider_searches_device_activity() -> None:
    config = MagicMock()

    with patch(
        "providers.environment_search_provider.AzureMonitorClient"
    ) as mock_client_class:
        mock_client = MagicMock()

        mock_client.get_log_analytics_workspace_id.return_value = (
            "test-workspace-id"
        )

        mock_client.run_kql.return_value = {
            "tables": [
                {
                    "columns": [
                        {"name": "Timestamp"},
                        {"name": "DeviceName"},
                        {"name": "ActionType"},
                        {"name": "FileName"},
                    ],
                    "rows": [
                        [
                            "2026-08-10T10:00:00Z",
                            "ORION-LAPTOP-01",
                            "ProcessCreated",
                            "powershell.exe",
                        ]
                    ],
                }
            ]
        }

        mock_client_class.return_value = mock_client

        provider = EnvironmentSearchProvider(
            config=config,
            subscription_id="test-subscription",
            resource_group="test-resource-group",
            workspace_name="test-workspace",
        )

        result = provider.search(
            correlation_keys=[
                {
                    "type": "device",
                    "value": "ORION-LAPTOP-01",
                }
            ],
            timespan="P7D",
        )

        assert result["search_count"] == 1
        assert len(result["results"]) == 1

        search_result = result["results"][0]

        assert search_result["type"] == "device"
        assert (
            search_result["value"]
            == "ORION-LAPTOP-01"
        )

        assert search_result["match_count"] == 1

        activity = search_result["matches"][0]

        assert (
            activity["DeviceName"]
            == "ORION-LAPTOP-01"
        )

        assert (
            activity["FileName"]
            == "powershell.exe"
        )

        mock_client.run_kql.assert_called_once()

        call_arguments = (
            mock_client.run_kql.call_args.kwargs
        )

        assert (
            'DeviceName =~ "ORION-LAPTOP-01"'
            in call_arguments["query"]
        )

        assert (
            "DeviceProcessEvents"
            in call_arguments["query"]
        )

        assert (
            "DeviceNetworkEvents"
            in call_arguments["query"]
        )

        assert call_arguments["timespan"] == "P7D"