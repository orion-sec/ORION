import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

"""
ORION Connector Configuration

Loads Microsoft Graph and external provider configuration
securely from environment variables rather than hardcoding
credentials in source code.
"""

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = REPOSITORY_ROOT / ".env"

load_dotenv(ENV_FILE)


@dataclass(frozen=True)
class GraphConfig:
    """
    Immutable Microsoft Graph connector configuration.
    """

    tenant_id: str
    client_id: str
    client_secret: str
    scope: str = "https://graph.microsoft.com/.default"
    base_url: str = "https://graph.microsoft.com/v1.0"

    @property
    def authority(self) -> str:
        """
        Returns the Microsoft Entra authority URL.
        """

        return (
            "https://login.microsoftonline.com/"
            f"{self.tenant_id}"
        )


@dataclass(frozen=True)
class VirusTotalConfig:
    """
    Immutable VirusTotal API configuration.
    """

    api_key: str
    base_url: str = "https://www.virustotal.com/api/v3"
    timeout: int = 15


def _required_environment_value(name: str) -> str:
    """
    Reads and validates a required environment variable.
    """

    value = os.getenv(name, "").strip()

    if not value:
        raise ValueError(
            f"Required environment variable is missing: {name}"
        )

    return value


def load_graph_config() -> GraphConfig:
    """
    Loads validated Microsoft Graph configuration.
    """

    return GraphConfig(
        tenant_id=_required_environment_value(
            "ORION_GRAPH_TENANT_ID"
        ),
        client_id=_required_environment_value(
            "ORION_GRAPH_CLIENT_ID"
        ),
        client_secret=_required_environment_value(
            "ORION_GRAPH_CLIENT_SECRET"
        ),
        scope=os.getenv(
            "ORION_GRAPH_SCOPE",
            "https://graph.microsoft.com/.default",
        ).strip(),
        base_url=os.getenv(
            "ORION_GRAPH_BASE_URL",
            "https://graph.microsoft.com/v1.0",
        ).strip().rstrip("/"),
    )


def load_virustotal_config() -> VirusTotalConfig:
    """
    Loads validated VirusTotal API configuration.
    """

    timeout_value = os.getenv(
        "ORION_VIRUSTOTAL_TIMEOUT",
        "15",
    ).strip()

    try:
        timeout = int(timeout_value)
    except ValueError as error:
        raise ValueError(
            "ORION_VIRUSTOTAL_TIMEOUT must be an integer."
        ) from error

    if timeout <= 0:
        raise ValueError(
            "ORION_VIRUSTOTAL_TIMEOUT must be greater than zero."
        )

    return VirusTotalConfig(
        api_key=_required_environment_value(
            "ORION_VIRUSTOTAL_API_KEY"
        ),
        base_url=os.getenv(
            "ORION_VIRUSTOTAL_BASE_URL",
            "https://www.virustotal.com/api/v3",
        ).strip().rstrip("/"),
        timeout=timeout,
    )