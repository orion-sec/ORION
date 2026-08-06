from typing import Any

import requests

from connectors.auth import GraphAuthenticator
from connectors.config import GraphConfig

GRAPH_INCIDENTS_URL = (
    "https://graph.microsoft.com/v1.0/security/incidents"
)


def list_defender_incidents(
    config: GraphConfig,
    top: int = 10,
    expand_alerts: bool = True,
) -> list[dict[str, Any]]:
    """
    Retrieve recent Microsoft Defender XDR incidents through
    the Microsoft Graph Security API.
    """

    if not 1 <= top <= 100:
        raise ValueError("top must be between 1 and 100.")

    authenticator = GraphAuthenticator(config)
    token = authenticator.acquire_token()

    headers = {
        **token.authorization_header,
        "Accept": "application/json",
    }

    params: dict[str, str | int] = {
        "$top": top,
        "$orderby": "lastUpdateDateTime desc",
    }

    if expand_alerts:
        params["$expand"] = "alerts"

    response = requests.get(
        GRAPH_INCIDENTS_URL,
        headers=headers,
        params=params,
        timeout=30,
    )

    if response.status_code == 401:
        raise PermissionError(
            "Microsoft Graph rejected the access token."
        )

    if response.status_code == 403:
        try:
            error_details = response.json()
        except ValueError:
            error_details = response.text

        raise PermissionError(
            "Microsoft Graph denied Defender incident access.\n"
            f"Response: {error_details}\n"
            f"Request ID: {response.headers.get('request-id', 'Unavailable')}\n"
            f"Client Request ID: "
            f"{response.headers.get('client-request-id', 'Unavailable')}"
        )

    response.raise_for_status()

    payload = response.json()
    incidents = payload.get("value", [])

    if not isinstance(incidents, list):
        raise TypeError(
            "Microsoft Graph returned an unexpected incidents payload."
        )

    return incidents