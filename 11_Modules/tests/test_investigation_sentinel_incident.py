from factories.sentinel_incident_factory import create_sentinel_incident
from models.investigation import Investigation


def test_investigation_accepts_sentinel_incident() -> None:
    raw_incident = {
        "name": "incident-001",
        "properties": {
            "title": "Suspicious Sign-in Activity",
            "severity": "High",
            "status": "New",
            "createdTimeUtc": "2026-08-08T10:00:00Z",
        },
    }

    sentinel_incident = create_sentinel_incident(raw_incident)

    investigation = Investigation()
    investigation.security_incidents.append(sentinel_incident)

    assert len(investigation.security_incidents) == 1
    assert investigation.security_incidents[0].incident_id == "incident-001"
    assert investigation.security_incidents[0].severity == "High"