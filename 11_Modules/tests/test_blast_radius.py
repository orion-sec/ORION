from correlation.blast_radius import (
    assess_blast_radius,
)


def test_assess_blast_radius_summarises_expansion() -> None:
    expansion = {
        "entities": {
            "users": [
                "user@oriondefense.ai",
            ],
            "ips": [
                "185.10.20.30",
                "185.10.20.31",
            ],
            "devices": [
                "ORION-LAPTOP-01",
                "ORION-SERVER-01",
            ],
            "file_hashes": [
                "a" * 64,
            ],
            "domains": [
                "malicious-example.com",
            ],
            "urls": [
                "https://malicious-example.com/login",
            ],
        }
    }

    result = assess_blast_radius(
        expansion
    )

    assert result["expanded"] is True
    assert result["affected_entity_count"] == 8
    assert result["active_categories"] == 6
    assert result["scope"] == "Multi-Entity"

    assert result["counts"]["users"] == 1
    assert result["counts"]["ips"] == 2
    assert result["counts"]["devices"] == 2
    assert result["counts"]["file_hashes"] == 1
    assert result["counts"]["domains"] == 1
    assert result["counts"]["urls"] == 1