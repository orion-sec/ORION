from typing import Any

from models.security_incident import SecurityIncident


def create_sentinel_incident(
    raw_incident: dict[str, Any],
    entities: list[dict[str, Any]] | None = None,
    alerts: list[dict[str, Any]] | None = None,
) -> SecurityIncident:
    """
    Convert a raw Microsoft Sentinel incident into ORION's
    vendor-neutral SecurityIncident model.
    """

    properties = raw_incident.get("properties", {})

    if not isinstance(properties, dict):
        properties = {}

    additional_data = properties.get("additionalData", {})

    if not isinstance(additional_data, dict):
        additional_data = {}

    tactics = additional_data.get("tactics", [])
    techniques = additional_data.get("techniques", [])

    if not isinstance(tactics, list):
        tactics = []

    if not isinstance(techniques, list):
        techniques = []

    return SecurityIncident(
        incident_id=str(raw_incident.get("name", "")),
        title=str(properties.get("title", "")),
        severity=str(properties.get("severity", "")),
        status=str(properties.get("status", "")),
        created_time_utc=str(properties.get("createdTimeUtc", "")),
        source_provider="Microsoft",
        source_product="Microsoft Sentinel",
        tactics=[str(item) for item in tactics],
        techniques=[str(item) for item in techniques],
        entities=entities or [],
        alerts=alerts or [],
        raw_metadata=raw_incident,
    )
