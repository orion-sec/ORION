from connectors.config import load_graph_config
from providers.exchange_provider import ExchangeProvider


def test_exchange_provider():

    provider = ExchangeProvider(
        load_graph_config()
    )

    result = provider.get_recent_messages(
        "orion.sec_outlook.com#EXT#@orionsecoutlook.onmicrosoft.com",
        top=5,
    )

    print()
    print("=" * 40)
    print("ORION EXCHANGE PROVIDER")
    print("=" * 40)
    print("Provider:", result.provider)
    print("Status:", result.status)

    if result.error:
        print("Reason:", result.error)
    else:
        print()
        print("Mailbox Settings")
        print(result.mailbox)

        print()
        print("Recent Messages")

        messages = result.messages or []

        for message in messages:
            print(
                "-",
                message.get("receivedDateTime"),
                "|",
                message.get("subject"),
            )


if __name__ == "__main__":
    test_exchange_provider()