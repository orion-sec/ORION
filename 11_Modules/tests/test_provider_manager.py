from connectors.azure_monitor import AzureMonitorClient
from connectors.config import load_graph_config
from providers.provider_manager import ProviderManager


def test_provider_manager() -> None:
    config = load_graph_config()

    azure = AzureMonitorClient(config)
    subscriptions = azure.list_subscriptions()
    subscription_id = subscriptions[0]["subscriptionId"]

    manager = ProviderManager(
        config=config,
        subscription_id=subscription_id,
        resource_group="orion-rg",
        workspace_name="orion-law",
    )

    sentinel = manager.sentinel

    result = sentinel.get_recent_incidents(top=10)

    print("\nSentinel Incident Retrieval")
    print(f"Status         : {result.status}")
    print(f"Incident Count : {len(result.incidents)}")

    if result.error:
        print(f"Error          : {result.error}")

    print("\nProviderManager Sentinel Test")
    print(f"Provider       : {sentinel.PROVIDER_NAME}")
    print(f"Subscription   : {sentinel.subscription_id}")
    print(f"Resource Group : {sentinel.resource_group}")
    print(f"Workspace      : {sentinel.workspace_name}")


if __name__ == "__main__":
    test_provider_manager()