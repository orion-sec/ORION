from connectors.azure_monitor import AzureMonitorClient
from connectors.config import load_graph_config


def test_sentinel_live() -> None:
    print("=" * 70)
    print("ORION MICROSOFT SENTINEL LIVE TEST")
    print("=" * 70)

    config = load_graph_config()
    client = AzureMonitorClient(config)

    subscriptions = client.list_subscriptions()

    if not subscriptions:
        raise RuntimeError("No Azure subscriptions were returned.")

    subscription_id = subscriptions[0]["subscriptionId"]

    resource_group = "orion-rg"
    workspace_name = "orion-law"

    incidents = client.list_sentinel_incidents(
        subscription_id=subscription_id,
        resource_group=resource_group,
        workspace_name=workspace_name,
    )

    print()
    print(f"Subscription ID : {subscription_id}")
    print(f"Resource Group  : {resource_group}")
    print(f"Workspace       : {workspace_name}")
    print(f"Incident Count  : {len(incidents)}")
    print()

    if not incidents:
        print("No Microsoft Sentinel incidents found.")
        return

    for incident in incidents:
        properties = incident.get("properties", {})

        print("-" * 70)
        print(f"Incident ID     : {incident.get('name', 'Unknown')}")
        print(f"Title           : {properties.get('title', 'Unknown')}")
        print(f"Severity        : {properties.get('severity', 'Unknown')}")
        print(f"Status          : {properties.get('status', 'Unknown')}")
        print(
            f"Created Time    : "
            f"{properties.get('createdTimeUtc', 'Unknown')}"
        )


if __name__ == "__main__":
    test_sentinel_live()