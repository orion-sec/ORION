from unittest.mock import MagicMock, patch

from models.signin_evidence import SignInEvidence
from providers.environment_search_provider import EnvironmentSearchProvider


def test_environment_search_provider_searches_user_signins() -> None:
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
                        {"name": "TimeGenerated"},
                        {"name": "UserPrincipalName"},
                        {"name": "UserId"},
                        {"name": "IPAddress"},
                        {"name": "AutonomousSystemNumber"},
                        {"name": "AppDisplayName"},
                        {"name": "ResultType"},
                        {"name": "ResultDescription"},
                        {"name": "ClientAppUsed"},
                        {"name": "UserAgent"},
                        {"name": "ConditionalAccessStatus"},
                        {"name": "RiskLevelDuringSignIn"},
                        {"name": "Location"},
                        {"name": "DeviceDetail"},
                        {"name": "CorrelationId"},
                    ],
                    "rows": [
                        [
                            "2026-08-10T10:00:00Z",
                            "samuel@oriondefense.ai",
                            "user-001",
                            "185.10.20.30",
                            64500,
                            "Microsoft 365",
                            "0",
                            "Success",
                            "Browser",
                            "Mozilla/5.0",
                            "success",
                            "none",
                            "GB",
                            (
                                '{"deviceId":"device-001",'
                                '"displayName":"ORION-LAPTOP-01"}'
                            ),
                            "correlation-001",
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
                    "type": "user",
                    "value": "samuel@oriondefense.ai",
                }
            ],
            timespan="P1D",
        )

        assert result["search_count"] == 1
        assert len(result["results"]) == 1

        search_result = result["results"][0]

        assert search_result["type"] == "user"
        assert search_result["match_count"] == 1

        signin = search_result["matches"][0]

        assert isinstance(signin, SignInEvidence)

        assert (
            signin.user_principal_name
            == "samuel@oriondefense.ai"
        )

        assert signin.ip_address == "185.10.20.30"

        assert (
            signin.device_detail["displayName"]
            == "ORION-LAPTOP-01"
        )

        mock_client.run_kql.assert_called_once()

        call_arguments = (
            mock_client.run_kql.call_args.kwargs
        )

        assert (
            call_arguments["workspace_id"]
            == "test-workspace-id"
        )

        assert (
            'UserPrincipalName =~ '
            '"samuel@oriondefense.ai"'
            in call_arguments["query"]
        )

        assert call_arguments["timespan"] == "P1D"