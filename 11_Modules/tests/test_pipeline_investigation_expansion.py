from typing import Any

from pipeline import investigation_expansion_stage


def test_pipeline_expands_environment_evidence() -> None:
    results: dict[str, Any] = {
        "Environment Evidence": [
            {
                "UserPrincipalName":
                    "user@oriondefense.ai",
                "IPAddress": "185.10.20.30",
                "DeviceName": "ORION-LAPTOP-01",
            },
            {
                "IPAddress": "185.10.20.31",
                "Domain": "malicious-example.com",
                "RemoteUrl": (
                    "https://malicious-example.com/login"
                ),
            },
        ]
    }

    results = investigation_expansion_stage(
        "",
        results,
    )

    expansion = results[
        "Investigation Expansion"
    ]

    assert expansion["expanded"] is True
    assert expansion["evidence_count"] == 2

    entities = expansion["entities"]

    assert entities["users"] == [
        "user@oriondefense.ai"
    ]

    assert entities["ips"] == [
        "185.10.20.30",
        "185.10.20.31",
    ]

    assert entities["devices"] == [
        "ORION-LAPTOP-01"
    ]

    assert entities["domains"] == [
        "malicious-example.com"
    ]

    assert entities["urls"] == [
        "https://malicious-example.com/login"
    ]

    assert expansion["affected_entity_count"] == 6