from connectors.config import GraphConfig

from providers.defender_provider import DefenderProvider
from providers.entra_provider import EntraProvider
from providers.exchange_provider import ExchangeProvider


class ProviderManager:
    """
    Central access point for all ORION providers.
    """

    def __init__(self, config: GraphConfig):
        self.config = config

    @property
    def defender(self) -> DefenderProvider:
        return DefenderProvider(self.config)

    @property
    def entra(self) -> EntraProvider:
        return EntraProvider(self.config)

    @property
    def exchange(self) -> ExchangeProvider:
        return ExchangeProvider(self.config)