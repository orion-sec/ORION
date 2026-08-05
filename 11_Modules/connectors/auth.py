from dataclasses import dataclass
from typing import Any

from msal import ConfidentialClientApplication

from connectors.config import GraphConfig


"""
ORION Microsoft Graph Authentication

Uses the OAuth 2.0 client-credentials flow to obtain an
application access token without an interactive user sign-in.
"""


@dataclass(frozen=True)
class GraphAccessToken:
    """
    Represents a successfully acquired Microsoft Graph token.
    """

    access_token: str
    token_type: str
    expires_in: int

    @property
    def authorization_header(self) -> dict[str, str]:
        """
        Returns the HTTP Authorization header.
        """

        return {
            "Authorization": (
                f"{self.token_type} {self.access_token}"
            )
        }


class GraphAuthenticator:
    """
    Acquires Microsoft Graph application access tokens.
    """

    def __init__(self, config: GraphConfig) -> None:
        self.config = config

        self._application = ConfidentialClientApplication(
            client_id=config.client_id,
            authority=config.authority,
            client_credential=config.client_secret,
        )

    def acquire_token(self) -> GraphAccessToken:
        """
        Obtains a Microsoft Graph access token.

        Raises:
            RuntimeError:
                When Microsoft Entra ID rejects the token request.
        """

        result: Any = (
            self._application.acquire_token_silent(
                scopes=[self.config.scope],
                account=None,
            )
            or self._application.acquire_token_for_client(
                scopes=[self.config.scope]
            )
        )

        access_token = result.get("access_token")

        if not access_token:
            error = result.get(
                "error",
                "unknown_authentication_error",
            )

            description = result.get(
                "error_description",
                "Microsoft Entra ID did not return a token.",
            )

            correlation_id = result.get(
                "correlation_id",
                "Unavailable",
            )

            raise RuntimeError(
                "Microsoft Graph authentication failed. "
                f"Error: {error}. "
                f"Description: {description} "
                f"Correlation ID: {correlation_id}"
            )

        return GraphAccessToken(
            access_token=str(access_token),
            token_type=str(
                result.get("token_type", "Bearer")
            ),
            expires_in=int(
                result.get("expires_in", 0)
            ),
        )