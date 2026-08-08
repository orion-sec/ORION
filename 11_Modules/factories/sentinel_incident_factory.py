from typing import Any

from models.security_incident import SecurityIncident


def create_sentinel_incident(
    raw_incident: dict[str, Any],
) -> SecurityIncident:
    """
    Convert a raw Microsoft Sentinel incident into ORION's
    vendor-neutral SecurityIncident model.
    """

    properties = raw_incident.get("properties", {})

    if not isinstance(properties, dict):
        properties = {}

    return SecurityIncident(
        incident_id=str(
            raw_incident.get("name", "")
        ),
        title=str(
            properties.get("title", "")
        ),
        severity=str(
            properties.get("severity", "")
        ),
        status=str(
            properties.get("status", "")
        ),
        created_time_utc=str(
            properties.get("createdTimeUtc", "")
        ),
        source_provider="Microsoft",
        source_product="Microsoft Sentinel",
        raw_metadata=raw_incident,
    )