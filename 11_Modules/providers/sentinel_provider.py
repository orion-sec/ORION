from dataclasses import dataclass, field
from typing import Any

import requests
from msal import ConfidentialClientApplication

from connectors.config import GraphConfig


@dataclass
class SentinelProviderResult:
    provider: str
    status: str
    incidents: list[dict[str, Any]] = field(
        default_factory=list
    )
    error: str | None = None


class SentinelProvider:
    PROVIDER_NAME = "Microsoft Sentinel"
    API_VERSION = "2025-09-01"
    MANAGEMENT_SCOPE = (
        "https://management.azure.com/.default"
    )

    def __init__(
        self,
        config: GraphConfig,
        subscription_id: str,
        resource_group: str,
        workspace_name: str,
    ) -> None:
        self.config = config
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.workspace_name = workspace_name

        self.application = ConfidentialClientApplication(
            client_id=config.client_id,
            authority=config.authority,
            client_credential=config.client_secret,
        )

    def _access_token(self) -> str:
        result = self.application.acquire_token_for_client(
            scopes=[self.MANAGEMENT_SCOPE]
        )

        if not isinstance(result, dict):
            raise TypeError(
                "Azure management authentication failed. "
                "No token response was returned."
            )

        token = result.get("access_token")

        if not token:
            error_description = result.get(
                "error_description",
                result,
            )

            raise RuntimeError(
                "Azure management authentication failed. "
                f"{error_description}"
            )

        return str(token)

    def get_recent_incidents(
        self,
        top: int = 10,
    ) -> SentinelProviderResult:
        safe_top = max(1, min(top, 100))

        url = (
            "https://management.azure.com/subscriptions/"
            f"{self.subscription_id}/resourceGroups/"
            f"{self.resource_group}/providers/"
            "Microsoft.OperationalInsights/workspaces/"
            f"{self.workspace_name}/providers/"
            "Microsoft.SecurityInsights/incidents"
        )

        try:
            response = requests.get(
                url,
                headers={
                    "Authorization": (
                        f"Bearer {self._access_token()}"
                    ),
                    "Accept": "application/json",
                },
                params={
                    "api-version": self.API_VERSION,
                    "$top": safe_top,
                    "$orderby": (
                        "properties/lastModifiedTimeUtc desc"
                    ),
                },
                timeout=30,
            )

            if not response.ok:
                return SentinelProviderResult(
                    provider=self.PROVIDER_NAME,
                    status="Unavailable",
                    error=(
                        "Sentinel request failed. "
                        f"HTTP {response.status_code}. "
                        f"Response: {response.text}"
                    ),
                )

            payload = response.json()
            incidents = payload.get("value", [])

            if not isinstance(incidents, list):
                incidents = []

            return SentinelProviderResult(
                provider=self.PROVIDER_NAME,
                status="Available",
                incidents=incidents,
            )

        except requests.RequestException as error:
            return SentinelProviderResult(
                provider=self.PROVIDER_NAME,
                status="Unavailable",
                error=str(error),
            )

        except (RuntimeError, ValueError) as error:
            return SentinelProviderResult(
                provider=self.PROVIDER_NAME,
                status="Unavailable",
                error=str(error),
            )