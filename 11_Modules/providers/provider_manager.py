from connectors.config import GraphConfig
from providers.defender_provider import DefenderProvider
from providers.entra_provider import EntraProvider
from providers.environment_search_provider import EnvironmentSearchProvider
from providers.exchange_provider import ExchangeProvider
from providers.sentinel_provider import SentinelProvider


class ProviderManager:
    """
    Central access point for all ORION providers.
    """

    def __init__(
        self,
        config: GraphConfig,
        subscription_id: str,
        resource_group: str,
        workspace_name: str,
    ):
        self.config = config
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.workspace_name = workspace_name

    @property
    def defender(self) -> DefenderProvider:
        return DefenderProvider(self.config)

    @property
    def entra(self) -> EntraProvider:
        return EntraProvider(self.config)

    @property
    def exchange(self) -> ExchangeProvider:
        return ExchangeProvider(self.config)

    @property
    def sentinel(self) -> SentinelProvider:
        return SentinelProvider(
            config=self.config,
            subscription_id=self.subscription_id,
            resource_group=self.resource_group,
            workspace_name=self.workspace_name,
        )

    @property
    def environment_search(self) -> EnvironmentSearchProvider:
        return EnvironmentSearchProvider(
            config=self.config,
            subscription_id=self.subscription_id,
            resource_group=self.resource_group,
            workspace_name=self.workspace_name,
        )