from models.investigation import Investigation
from pipeline import security_incident_stage


def test_security_incident_stage_normalises_sentinel_incident() -> None:
    investigation = Investigation()

    raw_sentinel_incident = {
        "name": "incident-001",
        "properties": {
            "title": "Suspicious Sign-In Activity",
            "severity": "High",
            "status": "New",
            "createdTimeUtc": "2026-08-08T10:00:00Z",
        },
    }

    results = {
        "Investigation Aggregate": investigation,
        "Raw Security Incidents": [
            {
                "source_provider": "Microsoft Sentinel",
                "raw": raw_sentinel_incident,
            }
        ],
    }

    updated_results = security_incident_stage(
        investigation,
        results,
    )

    security_incidents = updated_results[
        "Security Incidents"
    ]

    assert len(security_incidents) == 1

    incident = security_incidents[0]

    assert incident.incident_id == "incident-001"
    assert incident.title == "Suspicious Sign-In Activity"
    assert incident.severity == "High"
    assert incident.status == "New"
    assert incident.source_provider == "Microsoft"
    assert incident.source_product == "Microsoft Sentinel"

    assert len(investigation.security_incidents) == 1
    assert investigation.security_incidents[0] == incident