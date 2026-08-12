from typing import Any
from unittest.mock import MagicMock

from connectors.config import VirusTotalConfig
from connectors.virustotal_client import VirusTotalClient
from models.indicator_profile import (
    IndicatorClassification,
    IndicatorType,
)
from providers.virustotal_provider import (
    VirusTotalProvider,
)


def _malicious_payload() -> dict[str, Any]:
    return {
        "data": {
            "type": "file",
            "id": "test-indicator",
            "attributes": {
                "type_description": "Win32 EXE",
                "reputation": -30,
                "tags": [
                    "malware",
                    "peexe",
                ],
                "meaningful_name": "payload.exe",
                "last_analysis_stats": {
                    "malicious": 45,
                    "suspicious": 2,
                    "harmless": 0,
                    "undetected": 23,
                    "timeout": 0,
                },
            },
        }
    }


def _create_provider() -> tuple[
    VirusTotalProvider,
    MagicMock,
]:
    config = VirusTotalConfig(
        api_key="test-api-key"
    )

    provider = VirusTotalProvider(
        config
    )

    mocked_client = MagicMock(
        spec=VirusTotalClient
    )

    provider.client = mocked_client

    return provider, mocked_client


def test_lookup_file_hash_returns_indicator_profile() -> None:
    provider, mocked_client = _create_provider()

    mocked_client.lookup_file_hash.return_value = (
        _malicious_payload()
    )

    test_hash = "a" * 64

    profile = provider.lookup_file_hash(
        test_hash
    )

    mocked_client.lookup_file_hash.assert_called_once_with(
        test_hash
    )

    assert (
        profile.indicator_type
        == IndicatorType.FILE_HASH
    )

    assert (
        profile.classification
        == IndicatorClassification.CONFIRMED_MALICIOUS
    )

    assert profile.provider == "VirusTotal"
    assert profile.value == test_hash

    assert profile.risk_level in {
        "High",
        "Critical",
    }


def test_lookup_domain_returns_indicator_profile() -> None:
    provider, mocked_client = _create_provider()

    mocked_client.lookup_domain.return_value = (
        _malicious_payload()
    )

    domain = "malicious-example.com"

    profile = provider.lookup_domain(
        domain
    )

    mocked_client.lookup_domain.assert_called_once_with(
        domain
    )

    assert (
        profile.indicator_type
        == IndicatorType.DOMAIN
    )

    assert profile.provider == "VirusTotal"

    assert (
        profile.classification
        == IndicatorClassification.CONFIRMED_MALICIOUS
    )


def test_lookup_url_returns_indicator_profile() -> None:
    provider, mocked_client = _create_provider()

    mocked_client.lookup_url.return_value = (
        _malicious_payload()
    )

    url = "https://malicious-example.com/login"

    profile = provider.lookup_url(
        url
    )

    mocked_client.lookup_url.assert_called_once_with(
        url
    )

    assert (
        profile.indicator_type
        == IndicatorType.URL
    )

    assert profile.provider == "VirusTotal"


def test_lookup_ip_returns_indicator_profile() -> None:
    provider, mocked_client = _create_provider()

    mocked_client.lookup_ip.return_value = (
        _malicious_payload()
    )

    ip_address = "185.10.20.30"

    profile = provider.lookup_ip(
        ip_address
    )

    mocked_client.lookup_ip.assert_called_once_with(
        ip_address
    )

    assert (
        profile.indicator_type
        == IndicatorType.IP_ADDRESS
    )

    assert profile.provider == "VirusTotal"