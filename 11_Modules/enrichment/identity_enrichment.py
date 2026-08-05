from typing import Any

from connectors.graph_client import (
    GraphClient,
    GraphRequestError,
)
from factories.identity_factory import create_identity_profile
from models.identity_profile import IdentityProfile


class IdentityEnrichmentEngine:
    """
    Enriches Microsoft Entra identities using Microsoft Graph.
    """

    def __init__(self, graph_client: GraphClient) -> None:
        self.graph_client = graph_client

    @staticmethod
    def _safe_text(
        payload: dict[str, Any] | None,
        field_name: str,
    ) -> str:
        """
        Safely extracts a text field from a Graph response.
        """

        if not payload:
            return ""

        value = payload.get(field_name)

        if value is None:
            return ""

        return str(value)

    def enrich_user(
        self,
        user_identifier: str,
    ) -> IdentityProfile:
        """
        Produces a normalized, analyst-ready identity profile.
        """

        status: dict[str, str] = {}

        user = self.graph_client.get_user(user_identifier)
        status["profile"] = "Retrieved"

        object_id = self._safe_text(user, "id")

        manager: dict[str, Any] | None = None
        groups: list[dict[str, Any]] = []
        devices: list[dict[str, Any]] = []
        risk: dict[str, Any] | None = None

        try:
            manager = self.graph_client.get_user_manager(
                object_id
            )

            status["manager"] = (
                "Retrieved"
                if manager
                else "Not assigned"
            )

        except GraphRequestError as error:
            status["manager"] = f"Unavailable: {error}"

        try:
            groups = self.graph_client.get_user_groups(
                object_id
            )

            status["groups"] = (
                f"Retrieved {len(groups)}"
            )

        except GraphRequestError as error:
            status["groups"] = f"Unavailable: {error}"

        try:
            devices = (
                self.graph_client.get_user_registered_devices(
                    object_id
                )
            )

            status["devices"] = (
                f"Retrieved {len(devices)}"
            )

        except GraphRequestError as error:
            status["devices"] = f"Unavailable: {error}"

        try:
            risk = self.graph_client.get_risky_user(
                object_id
            )

            status["risk"] = (
                "Retrieved"
                if risk
                else "No risk record"
            )

        except GraphRequestError as error:
            status["risk"] = (
                "Unavailable in this tenant or licence: "
                f"{error}"
            )

        group_names = sorted(
            {
                str(group.get("displayName"))
                for group in groups
                if group.get("displayName")
            }
        )

        device_names = sorted(
            {
                str(
                    device.get("displayName")
                    or device.get("id")
                )
                for device in devices
                if device.get("displayName")
                or device.get("id")
            }
        )

        return create_identity_profile(
            object_id=object_id,
            user_principal_name=self._safe_text(
                user,
                "userPrincipalName",
            ),
            display_name=self._safe_text(
                user,
                "displayName",
            ),
            email=self._safe_text(user, "mail"),
            job_title=self._safe_text(
                user,
                "jobTitle",
            ),
            department=self._safe_text(
                user,
                "department",
            ),
            office_location=self._safe_text(
                user,
                "officeLocation",
            ),
            account_enabled=bool(
                user.get("accountEnabled", False)
            ),
            manager_name=self._safe_text(
                manager,
                "displayName",
            ),
            manager_upn=self._safe_text(
                manager,
                "userPrincipalName",
            ),
            groups=group_names,
            registered_devices=device_names,
            risk_level=(
                self._safe_text(risk, "riskLevel")
                or "None"
            ),
            risk_state=(
                self._safe_text(risk, "riskState")
                or "None"
            ),
            risk_detail=(
                self._safe_text(risk, "riskDetail")
                or "None"
            ),
            enrichment_status=status,
            raw_metadata={
                "user_type": user.get("userType"),
                "risk_last_updated": (
                    risk.get("riskLastUpdatedDateTime")
                    if risk
                    else None
                ),
            },
        )