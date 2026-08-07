from dataclasses import dataclass, field
from typing import Any

from connectors.config import GraphConfig
from connectors.graph_defender_incidents import list_defender_incidents


@dataclass
class DefenderProviderResult:
    """
    Standard result returned by the ORION Defender provider.
    """

    status: str
    provider: str = "Microsoft Defender XDR"
    incidents: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    @property
    def available(self) -> bool:
        return self.status == "Available"


class DefenderProvider:
    """
    Retrieves Microsoft Defender XDR investigation data.

    The provider prevents tenant or API failures from crashing
    the wider ORION investigation pipeline.
    """

    def __init__(self, config: GraphConfig) -> None:
        self.config = config

    def get_recent_incidents(
        self,
        top: int = 10,
        expand_alerts: bool = False,
    ) -> DefenderProviderResult:
        """
        Retrieve recent Defender XDR incidents.
        """

        try:
            incidents = list_defender_incidents(
                config=self.config,
                top=top,
                expand_alerts=expand_alerts,
            )

            return DefenderProviderResult(
                status="Available",
                incidents=incidents,
            )

        except PermissionError as exc:
            return DefenderProviderResult(
                status="Unavailable",
                error=str(exc),
            )

        except Exception as exc:  # noqa: BLE001
            return DefenderProviderResult(
                status="Error",
                error=str(exc),
            )