import json
from typing import Any

from connectors.azure_monitor import AzureMonitorClient
from connectors.config import GraphConfig
from factories.signin_evidence_factory import create_signin_evidence
from models.signin_evidence import SignInEvidence


class EnvironmentSearchProvider:
    """
    Searches the customer environment for activity related
    to entities discovered during an ORION investigation.

    The provider converts vendor-neutral ORION correlation
    entities into provider-specific searches.
    """

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

        self.client = AzureMonitorClient(config)

    def get_workspace_id(self) -> str:
        """
        Resolve the configured Log Analytics workspace name
        to its customer/workspace ID.
        """

        return self.client.get_log_analytics_workspace_id(
            subscription_id=self.subscription_id,
            resource_group=self.resource_group,
            workspace_name=self.workspace_name,
        )

    @staticmethod
    def _escape_kql_string(value: str) -> str:
        """
        Escape a value before placing it inside a quoted
        KQL string literal.
        """

        return value.replace("\\", "\\\\").replace('"', '\\"')

    @staticmethod
    def _extract_rows(
        payload: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Convert the standard Log Analytics table response
        into dictionaries keyed by column name.
        """

        tables = payload.get("tables", [])

        if not isinstance(tables, list) or not tables:
            return []

        table = tables[0]

        if not isinstance(table, dict):
            return []

        columns = table.get("columns", [])
        rows = table.get("rows", [])

        if not isinstance(columns, list):
            return []

        if not isinstance(rows, list):
            return []

        column_names = []

        for column in columns:
            if not isinstance(column, dict):
                continue

            name = column.get("name")

            if isinstance(name, str) and name:
                column_names.append(name)

        if not column_names:
            return []

        normalised_rows = []

        for row in rows:
            if not isinstance(row, list):
                continue

            record = dict(
                zip(
                    column_names,
                    row,
                    strict=False,
                )
            )

            device_detail = record.get("DeviceDetail")

            if isinstance(device_detail, str):
                try:
                    parsed_device_detail = json.loads(
                        device_detail
                    )

                    if isinstance(
                        parsed_device_detail,
                        dict,
                    ):
                        record["DeviceDetail"] = (
                            parsed_device_detail
                        )

                except json.JSONDecodeError:
                    record["DeviceDetail"] = {}

            normalised_rows.append(record)

        return normalised_rows

    def search_user_signins(
        self,
        user_principal_name: str,
        timespan: str = "P1D",
        limit: int = 50,
    ) -> list[SignInEvidence]:
        """
        Search Microsoft Entra SigninLogs for activity
        associated with one user identity.
        """

        cleaned_user = user_principal_name.strip()

        if not cleaned_user:
            return []

        if limit <= 0:
            raise ValueError(
                "Search result limit must be greater than zero."
            )

        workspace_id = self.get_workspace_id()

        escaped_user = self._escape_kql_string(
            cleaned_user
        )

        query = f"""
        SigninLogs
        | where UserPrincipalName =~ "{escaped_user}"
        | order by TimeGenerated desc
        | project
            TimeGenerated,
            UserPrincipalName,
            UserId,
            IPAddress,
            AutonomousSystemNumber,
            AppDisplayName,
            ResultType,
            ResultDescription,
            ClientAppUsed,
            UserAgent,
            ConditionalAccessStatus,
            RiskLevelDuringSignIn,
            Location,
            DeviceDetail,
            CorrelationId
        | take {limit}
        """

        payload = self.client.run_kql(
            workspace_id=workspace_id,
            query=query,
            timespan=timespan,
        )

        rows = self._extract_rows(payload)

        return [
            create_signin_evidence(row)
            for row in rows
        ]

    def search_ip_signins(
        self,
        ip_address: str,
        timespan: str = "P1D",
        limit: int = 50,
    ) -> list[SignInEvidence]:
        """
        Search Microsoft Entra SigninLogs for activity
        associated with one IP address.
        """

        cleaned_ip = ip_address.strip()

        if not cleaned_ip:
            return []

        if limit <= 0:
            raise ValueError(
                "Search result limit must be greater than zero."
            )

        workspace_id = self.get_workspace_id()

        escaped_ip = self._escape_kql_string(
            cleaned_ip
        )

        query = f"""
        SigninLogs
        | where IPAddress == "{escaped_ip}"
        | order by TimeGenerated desc
        | project
            TimeGenerated,
            UserPrincipalName,
            UserId,
            IPAddress,
            AutonomousSystemNumber,
            AppDisplayName,
            ResultType,
            ResultDescription,
            ClientAppUsed,
            UserAgent,
            ConditionalAccessStatus,
            RiskLevelDuringSignIn,
            Location,
            DeviceDetail,
            CorrelationId
        | take {limit}
        """

        payload = self.client.run_kql(
            workspace_id=workspace_id,
            query=query,
            timespan=timespan,
        )

        rows = self._extract_rows(payload)

        return [
            create_signin_evidence(row)
            for row in rows
        ]

    def search_device_activity(
        self,
        device_name: str,
        timespan: str = "P1D",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Search Microsoft security telemetry for activity
        associated with one device name.

        This method is designed for Defender endpoint tables
        when those tables are available in the workspace.
        """

        cleaned_device = device_name.strip()

        if not cleaned_device:
            return []

        if limit <= 0:
            raise ValueError(
                "Search result limit must be greater than zero."
            )

        workspace_id = self.get_workspace_id()

        escaped_device = self._escape_kql_string(
            cleaned_device
        )

        query = f"""
        union isfuzzy=true
            DeviceInfo,
            DeviceProcessEvents,
            DeviceNetworkEvents,
            DeviceFileEvents
        | where DeviceName =~ "{escaped_device}"
        | order by Timestamp desc
        | take {limit}
        """

        payload = self.client.run_kql(
            workspace_id=workspace_id,
            query=query,
            timespan=timespan,
        )

        return self._extract_rows(payload)

    def search_file_hash_activity(
        self,
        file_hash: str,
        timespan: str = "P1D",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Search Microsoft Defender endpoint telemetry for
        activity associated with a file hash.

        Supports SHA256, SHA1 and MD5 correlation pivots.
        """

        cleaned_hash = file_hash.strip().lower()

        if not cleaned_hash:
            return []

        if limit <= 0:
            raise ValueError(
                "Search result limit must be greater than zero."
            )

        hash_length = len(cleaned_hash)

        if hash_length == 64:
            hash_field = "SHA256"

        elif hash_length == 40:
            hash_field = "SHA1"

        elif hash_length == 32:
            hash_field = "MD5"

        else:
            raise ValueError(
                "Unsupported file hash length. "
                "Expected MD5, SHA1 or SHA256."
            )

        workspace_id = self.get_workspace_id()

        escaped_hash = self._escape_kql_string(
            cleaned_hash
        )

        query = f"""
        union isfuzzy=true
            DeviceFileEvents,
            DeviceProcessEvents
        | where {hash_field} =~ "{escaped_hash}"
        | order by Timestamp desc
        | take {limit}
        """

        payload = self.client.run_kql(
            workspace_id=workspace_id,
            query=query,
            timespan=timespan,
        )

        return self._extract_rows(payload)

    def search_domain_activity(
        self,
        domain: str,
        timespan: str = "P1D",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Search Microsoft security telemetry for activity
        associated with one domain.
        """

        cleaned_domain = domain.strip().lower()

        if not cleaned_domain:
            return []

        if limit <= 0:
            raise ValueError(
                "Search result limit must be greater than zero."
            )

        workspace_id = self.get_workspace_id()

        escaped_domain = self._escape_kql_string(
            cleaned_domain
        )

        query = f"""
        union isfuzzy=true
            DeviceNetworkEvents,
            DnsEvents
        | where RemoteUrl =~ "{escaped_domain}"
            or Name =~ "{escaped_domain}"
        | order by Timestamp desc
        | take {limit}
        """

        payload = self.client.run_kql(
            workspace_id=workspace_id,
            query=query,
            timespan=timespan,
        )

        return self._extract_rows(payload)

    def search_url_activity(
        self,
        url: str,
        timespan: str = "P1D",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Search Microsoft security telemetry for activity
        associated with one URL.
        """

        cleaned_url = url.strip()

        if not cleaned_url:
            return []

        if limit <= 0:
            raise ValueError(
                "Search result limit must be greater than zero."
            )

        workspace_id = self.get_workspace_id()

        escaped_url = self._escape_kql_string(
            cleaned_url
        )

        query = f"""
        DeviceNetworkEvents
        | where RemoteUrl =~ "{escaped_url}"
        | order by Timestamp desc
        | take {limit}
        """

        payload = self.client.run_kql(
            workspace_id=workspace_id,
            query=query,
            timespan=timespan,
        )

        return self._extract_rows(payload)

    def search(
        self,
        correlation_keys: list[dict[str, Any]],
        timespan: str = "P1D",
    ) -> dict[str, Any]:
        """
        Search the wider environment using correlation
        pivots from one independent ORION investigation.

        Current implementation supports user, IP, device,
        file-hash, domain and URL pivots across Microsoft
        security telemetry.
        """

        results = []

        for correlation_key in correlation_keys:
            if not isinstance(correlation_key, dict):
                continue

            entity_type = str(
                correlation_key.get("type", "")
            ).strip().lower()

            value = str(
                correlation_key.get("value", "")
            ).strip()

            if not value:
                continue

            if entity_type == "user":
                signins = self.search_user_signins(
                    user_principal_name=value,
                    timespan=timespan,
                )

                results.append(
                    {
                        "type": "user",
                        "value": value,
                        "source": "Microsoft Entra SigninLogs",
                        "matches": signins,
                        "match_count": len(signins),
                    }
                )

            elif entity_type == "ip":
                signins = self.search_ip_signins(
                    ip_address=value,
                    timespan=timespan,
                )

                results.append(
                    {
                        "type": "ip",
                        "value": value,
                        "source": "Microsoft Entra SigninLogs",
                        "matches": signins,
                        "match_count": len(signins),
                    }
                )

            elif entity_type == "device":
                device_activity = self.search_device_activity(
                    device_name=value,
                    timespan=timespan,
                )

                results.append(
                    {
                        "type": "device",
                        "value": value,
                        "source": (
                            "Microsoft Defender Endpoint Telemetry"
                        ),
                        "matches": device_activity,
                        "match_count": len(device_activity),
                    }
                )

            elif entity_type == "file_hash":
                file_activity = self.search_file_hash_activity(
                    file_hash=value,
                    timespan=timespan,
                )

                results.append(
                    {
                        "type": "file_hash",
                        "value": value,
                        "source": (
                            "Microsoft Defender Endpoint Telemetry"
                        ),
                        "matches": file_activity,
                        "match_count": len(file_activity),
                    }
                )

            elif entity_type == "domain":
                domain_activity = self.search_domain_activity(
                    domain=value,
                    timespan=timespan,
                )

                results.append(
                    {
                        "type": "domain",
                        "value": value,
                        "source": (
                            "Microsoft Network and DNS Telemetry"
                        ),
                        "matches": domain_activity,
                        "match_count": len(domain_activity),
                    }
                )

            elif entity_type == "url":
                url_activity = self.search_url_activity(
                    url=value,
                    timespan=timespan,
                )

                results.append(
                    {
                        "type": "url",
                        "value": value,
                        "source": (
                            "Microsoft Defender Network Telemetry"
                        ),
                        "matches": url_activity,
                        "match_count": len(url_activity),
                    }
                )

        return {
            "timespan": timespan,
            "correlation_keys": correlation_keys,
            "search_count": len(correlation_keys),
            "results": results,
        }