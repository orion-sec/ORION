from connectors.azure_monitor import AzureMonitorClient
from connectors.config import load_graph_config
from factories.sentinel_incident_factory import create_sentinel_incident


def test_sentinel_incident_factory_live() -> None:
    config = load_graph_config()
    client = AzureMonitorClient(config)

    subscriptions = client.list_subscriptions()

    if not subscriptions:
        raise RuntimeError("No Azure subscriptions were returned.")

    subscription_id = subscriptions[0]["subscriptionId"]

    incidents = client.list_sentinel_incidents(
        subscription_id=subscription_id,
        resource_group="orion-rg",
        workspace_name="orion-law",
    )

    if not incidents:
        print("No Sentinel incidents available for live normalization test.")
        return

    raw_incident = incidents[0]
    incident = create_sentinel_incident(raw_incident)

    print()
    print("ORION SENTINEL INCIDENT NORMALIZATION")
    print("=" * 60)
    print(f"Incident ID : {incident.incident_id}")
    print(f"Title       : {incident.title}")
    print(f"Severity    : {incident.severity}")
    print(f"Status      : {incident.status}")
    print(f"Created     : {incident.created_time_utc}")

    assert incident.incident_id
    assert incident.raw_metadata == raw_incident


if __name__ == "__main__":
    test_sentinel_incident_factory_live()