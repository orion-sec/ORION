from typing import Any

from pipeline import (
    blast_radius_stage,
    investigation_expansion_stage,
)


def test_pipeline_expansion_produces_blast_radius() -> None:
    results: dict[str, Any] = {
        "Environment Evidence": [
            {
                "UserPrincipalName":
                    "user@oriondefense.ai",
                "IPAddress":
                    "185.10.20.30",
                "DeviceName":
                    "ORION-LAPTOP-01",
            },
            {
                "IPAddress":
                    "185.10.20.31",
                "DeviceName":
                    "ORION-SERVER-01",
                "Domain":
                    "malicious-example.com",
            },
        ]
    }

    results = investigation_expansion_stage(
        "",
        results,
    )

    results = blast_radius_stage(
        "",
        results,
    )

    expansion = results[
        "Investigation Expansion"
    ]

    blast_radius = results[
        "Blast Radius"
    ]

    assert expansion["expanded"] is True

    assert (
        blast_radius["affected_entity_count"]
        == expansion["affected_entity_count"]
    )

    assert blast_radius["expanded"] is True
    assert blast_radius["scope"] == "Multi-Entity"

    assert blast_radius["counts"]["users"] == 1
    assert blast_radius["counts"]["ips"] == 2
    assert blast_radius["counts"]["devices"] == 2
    assert blast_radius["counts"]["domains"] == 1