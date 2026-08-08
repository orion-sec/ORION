from factories.sentinel_incident_factory import create_sentinel_incident
from models.security_incident import SecurityIncident


def test_create_sentinel_incident() -> None:
    raw_incident = {
        "name": "incident-001",
        "properties": {
            "title": "Suspicious Sign-in Activity",
            "severity": "High",
            "status": "New",
            "createdTimeUtc": "2026-08-08T10:00:00Z",
        },
    }

    incident = create_sentinel_incident(raw_incident)

    # ORION common security incident model
    assert isinstance(incident, SecurityIncident)

    # Normalized common fields
    assert incident.incident_id == "incident-001"
    assert incident.title == "Suspicious Sign-in Activity"
    assert incident.severity == "High"
    assert incident.status == "New"
    assert incident.created_time_utc == "2026-08-08T10:00:00Z"

    # Preserve vendor provenance
    assert incident.source_provider == "Microsoft"
    assert incident.source_product == "Microsoft Sentinel"

    # Preserve original vendor payload
    assert incident.raw_metadata == raw_incident