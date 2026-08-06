from connectors.azure_monitor import AzureMonitorClient
from connectors.config import load_graph_config


def test_azure_management() -> None:
    print("=" * 70)
    print("ORION AZURE MANAGEMENT API")
    print("=" * 70)

    client = AzureMonitorClient(load_graph_config())

    subscriptions = client.list_subscriptions()

    print(f"\nFound {len(subscriptions)} subscription(s)\n")

    for subscription in subscriptions:
        print(
            f"Name : {subscription.get('displayName')}"
        )
        print(
            f"ID   : {subscription.get('subscriptionId')}"
        )
        print(
            f"State: {subscription.get('state')}"
        )
        print("-" * 70)


if __name__ == "__main__":
    test_azure_management()