from typing import Any

from connectors.azure_monitor import AzureMonitorClient


def collect_sentinel_incidents(
    client: AzureMonitorClient,
    subscription_id: str,
    resource_group: str,
    workspace_name: str,
) -> list[dict[str, Any]]:
    """
    Collect Microsoft Sentinel incidents together with their
    associated entities and alerts for ORION ingestion.
    """

    incidents = client.list_sentinel_incidents(
        subscription_id=subscription_id,
        resource_group=resource_group,
        workspace_name=workspace_name,
    )

    collected_incidents: list[dict[str, Any]] = []

    for incident in incidents:
        incident_id = incident.get("name")

        if not isinstance(incident_id, str) or not incident_id.strip():
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

        collected_incidents.append(
            {
                "source_provider": "Microsoft Sentinel",
                "raw": incident,
                "entities": entities,
                "alerts": alerts,
            }
        )

    return collected_incidents
