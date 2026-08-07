from dataclasses import dataclass

from connectors.config import GraphConfig
from connectors.graph_client import GraphClient
from enrichment.identity_enrichment import IdentityEnrichmentEngine
from models.identity_profile import IdentityProfile


@dataclass
class EntraProviderResult:
    provider: str
    status: str
    identity: IdentityProfile | None = None
    error: str | None = None


class EntraProvider:
    PROVIDER_NAME = "Microsoft Entra ID"

    def __init__(self, config: GraphConfig) -> None:
        self.config = config
        self.graph_client = GraphClient(config)
        self.engine = IdentityEnrichmentEngine(
            self.graph_client
        )

    def enrich_user(
        self,
        user_identifier: str,
    ) -> EntraProviderResult:
        try:
            identity = self.engine.enrich_user(
                user_identifier
            )

            return EntraProviderResult(
                provider=self.PROVIDER_NAME,
                status="Available",
                identity=identity,
            )

        except Exception as exc:  # noqa: BLE001
            return EntraProviderResult(
                provider=self.PROVIDER_NAME,
                status="Unavailable",
                error=str(exc),
            )