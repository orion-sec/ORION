import json

from connectors.azure_monitor import AzureMonitorClient
from connectors.config import load_graph_config
from factories.sentinel_incident_factory import create_sentinel_incident


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

    normalized_incidents = []

    for incident in incidents:
        properties = incident.get("properties", {})

        if not isinstance(properties, dict):
            properties = {}

        print("-" * 70)
        print(f"Incident ID     : {incident.get('name', 'Unknown')}")
        print(f"Title           : {properties.get('title', 'Unknown')}")
        print(f"Severity        : {properties.get('severity', 'Unknown')}")
        print(f"Status          : {properties.get('status', 'Unknown')}")
        print(
            f"Created Time    : "
            f"{properties.get('createdTimeUtc', 'Unknown')}"
        )

        incident_id = incident.get("name")

        if not isinstance(incident_id, str) or not incident_id.strip():
            print("Incident skipped: valid Incident ID unavailable.")
            continue

        entities = client.list_sentinel_incident_entities(
            subscription_id=subscription_id,
            resource_group=resource_group,
            workspace_name=workspace_name,
            incident_id=incident_id,
        )

        alerts = client.list_sentinel_incident_alerts(
            subscription_id=subscription_id,
            resource_group=resource_group,
            workspace_name=workspace_name,
            incident_id=incident_id,
        )

        print(f"Entity Count    : {len(entities)}")
        print(f"Alert Count     : {len(alerts)}")

        security_incident = create_sentinel_incident(
            raw_incident=incident,
            entities=entities,
            alerts=alerts,
        )

        normalized_incidents.append(security_incident)

        print()
        print("ORION NORMALIZED SECURITY INCIDENT")
        print(f"  Incident ID   : {security_incident.incident_id}")
        print(f"  Provider      : {security_incident.source_provider}")
        print(f"  Product       : {security_incident.source_product}")
        print(f"  Title         : {security_incident.title}")
        print(f"  Severity      : {security_incident.severity}")
        print(f"  Status        : {security_incident.status}")
        print(f"  Tactics       : {security_incident.tactics}")
        print(f"  Techniques    : {security_incident.techniques}")
        print(f"  Entities      : {len(security_incident.entities)}")
        print(f"  Alerts        : {len(security_incident.alerts)}")

        if security_incident.entities:
            print()
            print("NORMALIZED INCIDENT ENTITIES")

            for entity in security_incident.entities:
                kind = entity.get("kind", "Unknown")
                entity_properties = entity.get("properties", {})

                print(f"  Kind          : {kind}")
                print(f"  Properties    : {entity_properties}")
                print()

        print()
        print("RAW INCIDENT JSON")
        print(json.dumps(incident, indent=2, default=str))
        print()

    assert normalized_incidents
    assert len(normalized_incidents) == len(incidents)

    print("=" * 70)
    print("ORION SENTINEL NORMALIZATION TEST PASSED")
    print(f"Normalized incidents: {len(normalized_incidents)}")
    print("=" * 70)


if __name__ == "__main__":
    test_sentinel_live()
