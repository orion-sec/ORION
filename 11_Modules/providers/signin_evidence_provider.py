from typing import Any

from connectors.azure_monitor import AzureMonitorClient
from factories.signin_evidence_factory import create_signin_evidence
from models.signin_evidence import SignInEvidence


class SignInEvidenceProvider:
    """
    Retrieves Microsoft Entra sign-in telemetry from Azure Monitor
    and converts it into normalized ORION evidence objects.
    """

    def __init__(
        self,
        client: AzureMonitorClient,
        workspace_id: str,
    ) -> None:
        self.client = client
        self.workspace_id = workspace_id

    def collect(
        self,
        timespan: str = "P1D",
        limit: int = 50,
    ) -> list[SignInEvidence]:

        result = self.client.get_signin_evidence(
            workspace_id=self.workspace_id,
            timespan=timespan,
            limit=limit,
        )

        tables = result.get("tables", [])

        if not tables:
            return []

        table = tables[0]

        columns = [
            column["name"]
            for column in table.get("columns", [])
        ]

        rows = table.get("rows", [])

        evidence: list[SignInEvidence] = []

        for row in rows:
            raw_event: dict[str, Any] = dict(
                zip(columns, row)
            )

            evidence.append(
                create_signin_evidence(raw_event)
            )

        return evidence