from __future__ import annotations

from typing import Any

import requests

from connectors.auth import GraphAuthenticator
from connectors.config import GraphConfig


class AzureMonitorError(RuntimeError):
    """Raised when Azure Monitor returns an error."""


class AzureMonitorClient:
    """
    Client for Azure Management and Log Analytics APIs.
    """

    def __init__(
        self,
        config: GraphConfig,
    ) -> None:
        self.config = config
        self.auth = GraphAuthenticator(config)

    def list_subscriptions(self) -> list[dict[str, Any]]:
        """
        Lists subscriptions available to the ORION service principal.
        """

        token = self.auth.acquire_token(
            scope="https://management.azure.com/.default"
        )

        try:
            response = requests.get(
                "https://management.azure.com/subscriptions",
                headers={
                    **token.authorization_header,
                    "Accept": "application/json",
                },
                params={
                    "api-version": "2022-12-01",
                },
                timeout=30,
            )

        except requests.RequestException as error:
            raise AzureMonitorError(
                f"Azure Management request failed: {error}"
            ) from error

        if not response.ok:
            raise AzureMonitorError(
                "Azure Management rejected the request. "
                f"HTTP {response.status_code}. "
                f"Response: {response.text}"
            )

        payload = response.json()
        subscriptions = payload.get("value", [])

        if not isinstance(subscriptions, list):
            raise AzureMonitorError(
                "Azure returned an invalid subscription collection."
            )

        return subscriptions

    def run_kql(
        self,
        workspace_id: str,
        query: str,
        timespan: str = "P1D",
    ) -> dict[str, Any]:
        """
        Runs a KQL query against an Azure Log Analytics workspace.
        """

        cleaned_workspace_id = workspace_id.strip()
        cleaned_query = query.strip()

        if not cleaned_workspace_id:
            raise ValueError("Workspace ID cannot be empty.")

        if not cleaned_query:
            raise ValueError("KQL query cannot be empty.")

        token = self.auth.acquire_token(
            scope="https://api.loganalytics.io/.default"
        )

        url = (
            "https://api.loganalytics.io/v1/workspaces/"
            f"{cleaned_workspace_id}/query"
        )

        try:
            response = requests.post(
                url=url,
                headers={
                    **token.authorization_header,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                json={
                    "query": cleaned_query,
                    "timespan": timespan,
                },
                timeout=30,
            )

        except requests.RequestException as error:
            raise AzureMonitorError(
                f"Log Analytics request failed: {error}"
            ) from error

        if not response.ok:
            raise AzureMonitorError(
                "Log Analytics rejected the request. "
                f"HTTP {response.status_code}. "
                f"Response: {response.text}"
            )

        payload = response.json()

        if not isinstance(payload, dict):
            raise AzureMonitorError(
                "Log Analytics returned an invalid response."
            )

        return payload