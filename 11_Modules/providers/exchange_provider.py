from dataclasses import dataclass
from typing import Any

from connectors.config import GraphConfig
from connectors.graph_client import (
    GraphClient,
    GraphRequestError,
)


@dataclass
class ExchangeProviderResult:
    provider: str
    status: str
    mailbox: dict[str, Any] | None = None
    messages: list[dict[str, Any]] | None = None
    error: str | None = None


class ExchangeProvider:

    PROVIDER_NAME = "Microsoft Exchange Online"

    def __init__(
        self,
        config: GraphConfig,
    ):
        self.client = GraphClient(config)

    def get_recent_messages(
        self,
        user_principal_name: str,
        top: int = 10,
    ) -> ExchangeProviderResult:

        try:

            mailbox = self.client.get_mailbox_settings(
                user_principal_name
            )

            messages = self.client.get_recent_messages(
                user_principal_name,
                top=top,
            )

            return ExchangeProviderResult(
                provider=self.PROVIDER_NAME,
                status="Available",
                mailbox=mailbox,
                messages=messages,
            )

        except GraphRequestError as error:

            return ExchangeProviderResult(
                provider=self.PROVIDER_NAME,
                status="Unavailable",
                error=str(error),
            )