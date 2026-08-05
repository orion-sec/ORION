from typing import Any

import requests

from connectors.auth import GraphAuthenticator
from connectors.config import GraphConfig


"""
ORION Microsoft Graph Client

Executes authenticated, read-only Microsoft Graph requests
and returns normalized Python dictionaries.
"""


class GraphRequestError(RuntimeError):
    """
    Raised when Microsoft Graph rejects or cannot complete a request.
    """


class GraphClient:
    """
    Read-only Microsoft Graph API client.
    """

    def __init__(
        self,
        config: GraphConfig,
        timeout_seconds: int = 30,
    ) -> None:
        self.config = config
        self.timeout_seconds = timeout_seconds
        self.authenticator = GraphAuthenticator(config)

    def _headers(self) -> dict[str, str]:
        """
        Builds authenticated Microsoft Graph request headers.
        """

        token = self.authenticator.acquire_token()

        return {
            **token.authorization_header,
            "Accept": "application/json",
        }

    def get(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Executes an authenticated GET request.
        """

        cleaned_endpoint = endpoint.strip()

        if not cleaned_endpoint:
            raise ValueError("Graph endpoint cannot be empty.")

        if not cleaned_endpoint.startswith("/"):
            cleaned_endpoint = f"/{cleaned_endpoint}"

        url = f"{self.config.base_url}{cleaned_endpoint}"

        try:
            response = requests.get(
                url=url,
                headers=self._headers(),
                params=params,
                timeout=self.timeout_seconds,
            )

        except requests.RequestException as error:
            raise GraphRequestError(
                "Microsoft Graph request could not be completed. "
                f"Endpoint: {cleaned_endpoint}. Error: {error}"
            ) from error

        if not response.ok:
            request_id = response.headers.get(
                "request-id",
                "Unavailable",
            )

            client_request_id = response.headers.get(
                "client-request-id",
                "Unavailable",
            )

            try:
                error_payload = response.json()
            except ValueError:
                error_payload = {
                    "error": {
                        "message": response.text
                        or "No response body returned."
                    }
                }

            graph_error = error_payload.get("error", {})
            error_code = graph_error.get(
                "code",
                "UnknownGraphError",
            )
            error_message = graph_error.get(
                "message",
                "Microsoft Graph rejected the request.",
            )

            raise GraphRequestError(
                "Microsoft Graph request failed. "
                f"HTTP status: {response.status_code}. "
                f"Code: {error_code}. "
                f"Message: {error_message}. "
                f"Request ID: {request_id}. "
                f"Client request ID: {client_request_id}."
            )

        try:
            return response.json()

        except ValueError as error:
            raise GraphRequestError(
                "Microsoft Graph returned a non-JSON response."
            ) from error

    def get_users(
        self,
        maximum_users: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Retrieves a limited collection of Microsoft Entra users.
        """

        safe_limit = max(1, min(maximum_users, 100))

        payload = self.get(
            endpoint="/users",
            params={
                "$top": safe_limit,
                "$select": (
                    "id,displayName,userPrincipalName,"
                    "mail,jobTitle,department,"
                    "officeLocation,accountEnabled"
                ),
                "$orderby": "displayName",
            },
        )

        users = payload.get("value", [])

        if not isinstance(users, list):
            raise GraphRequestError(
                "Microsoft Graph returned an invalid users collection."
            )

        return users

    def get_user(
        self,
        user_identifier: str,
    ) -> dict[str, Any]:
        """
        Retrieves one Microsoft Entra user by object ID or UPN.
        """

        identifier = user_identifier.strip()

        if not identifier:
            raise ValueError("User identifier cannot be empty.")

        return self.get(
            endpoint=f"/users/{identifier}",
            params={
                "$select": (
                    "id,displayName,userPrincipalName,mail,"
                    "jobTitle,department,officeLocation,"
                    "accountEnabled,userType"
                )
            },
        )

    def get_user_manager(
        self,
        user_identifier: str,
    ) -> dict[str, Any] | None:
        """
        Retrieves the user's manager.

        Returns None when no manager has been assigned.
        """

        identifier = user_identifier.strip()

        try:
            return self.get(
                endpoint=f"/users/{identifier}/manager",
                params={
                    "$select": (
                        "id,displayName,userPrincipalName,mail"
                    )
                },
            )

        except GraphRequestError as error:
            message = str(error)

            if "HTTP status: 404" in message:
                return None

            raise

    def get_user_groups(
        self,
        user_identifier: str,
    ) -> list[dict[str, Any]]:
        """
        Retrieves direct directory memberships for a user.
        """

        identifier = user_identifier.strip()

        payload = self.get(
            endpoint=f"/users/{identifier}/memberOf",
            params={
                "$select": "id,displayName",
                "$top": 100,
            },
        )

        memberships = payload.get("value", [])

        if not isinstance(memberships, list):
            raise GraphRequestError(
                "Microsoft Graph returned an invalid membership collection."
            )

        return memberships

    def get_user_registered_devices(
        self,
        user_identifier: str,
    ) -> list[dict[str, Any]]:
        """
        Retrieves devices registered to the user.
        """

        identifier = user_identifier.strip()

        payload = self.get(
            endpoint=f"/users/{identifier}/registeredDevices",
            params={
                "$select": (
                    "id,displayName,operatingSystem,"
                    "operatingSystemVersion,accountEnabled"
                ),
                "$top": 100,
            },
        )

        devices = payload.get("value", [])

        if not isinstance(devices, list):
            raise GraphRequestError(
                "Microsoft Graph returned an invalid device collection."
            )

        return devices

    def get_risky_user(
        self,
        user_object_id: str,
    ) -> dict[str, Any] | None:
        """
        Retrieves Microsoft Entra ID Protection risk information.

        Returns None when the user has no risk record.
        """

        object_id = user_object_id.strip()

        try:
            return self.get(
                endpoint=(
                    "/identityProtection/riskyUsers/"
                    f"{object_id}"
                ),
                params={
                    "$select": (
                        "id,userDisplayName,userPrincipalName,"
                        "riskDetail,riskLevel,riskState,"
                        "riskLastUpdatedDateTime"
                    )
                },
            )

        except GraphRequestError as error:
            message = str(error)

            if "HTTP status: 404" in message:
                return None

            raise