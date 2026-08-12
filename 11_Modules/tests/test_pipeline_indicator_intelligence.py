from unittest.mock import MagicMock

from pipeline import indicator_intelligence_stage


def test_pipeline_indicator_intelligence_routes_supported_iocs() -> None:
    provider = MagicMock()

    provider.lookup_file_hash.return_value = {
        "type": "file_hash",
        "verdict": "malicious",
    }

    provider.lookup_domain.return_value = {
        "type": "domain",
        "verdict": "malicious",
    }

    provider.lookup_url.return_value = {
        "type": "url",
        "verdict": "suspicious",
    }

    provider.lookup_ip.return_value = {
        "type": "ip",
        "verdict": "suspicious",
    }

    test_hash = "a" * 64

    results = {
        "VirusTotal Provider": provider,
        "Entity Correlation": {
            "correlation_keys": [
                {
                    "type": "file_hash",
                    "value": test_hash,
                },
                {
                    "type": "domain",
                    "value": "malicious-example.com",
                },
                {
                    "type": "url",
                    "value": (
                        "https://malicious-example.com/login"
                    ),
                },
                {
                    "type": "ip",
                    "value": "185.10.20.30",
                },
                {
                    "type": "device",
                    "value": "ORION-LAPTOP-01",
                },
            ]
        },
    }

    updated = indicator_intelligence_stage(
        "",
        results,
    )

    provider.lookup_file_hash.assert_called_once_with(
        test_hash
    )

    provider.lookup_domain.assert_called_once_with(
        "malicious-example.com"
    )

    provider.lookup_url.assert_called_once_with(
        "https://malicious-example.com/login"
    )

    provider.lookup_ip.assert_called_once_with(
        "185.10.20.30"
    )

    assert len(
        updated["Indicator Intelligence"]
    ) == 4