from typing import Any

from connectors.config import VirusTotalConfig
from connectors.virustotal_client import VirusTotalClient
from intelligence.indicator_engine import enrich_indicator
from intelligence.virustotal_normalizer import (
    normalise_virustotal_result,
)
from models.indicator_profile import IndicatorProfile


class VirusTotalProvider:
    """
    ORION provider for VirusTotal IOC intelligence.
    """

    def __init__(
        self,
        config: VirusTotalConfig,
    ) -> None:
        self.config = config
        self.client = VirusTotalClient(config)

    def _build_profile(
        self,
        indicator_type: str,
        value: str,
        payload: dict[str, Any],
    ) -> IndicatorProfile:
        enrichment = normalise_virustotal_result(
            payload
        )

        return enrich_indicator(
            indicator_type=indicator_type,
            value=value,
            enrichment=enrichment,
        )

    def lookup_file_hash(
        self,
        file_hash: str,
    ) -> IndicatorProfile:
        payload = self.client.lookup_file_hash(
            file_hash
        )

        return self._build_profile(
            indicator_type="file_hash",
            value=file_hash,
            payload=payload,
        )

    def lookup_domain(
        self,
        domain: str,
    ) -> IndicatorProfile:
        payload = self.client.lookup_domain(
            domain
        )

        return self._build_profile(
            indicator_type="domain",
            value=domain,
            payload=payload,
        )

    def lookup_url(
        self,
        url: str,
    ) -> IndicatorProfile:
        payload = self.client.lookup_url(
            url
        )

        return self._build_profile(
            indicator_type="url",
            value=url,
            payload=payload,
        )

    def lookup_ip(
        self,
        ip_address: str,
    ) -> IndicatorProfile:
        payload = self.client.lookup_ip(
            ip_address
        )

        return self._build_profile(
            indicator_type="ip",
            value=ip_address,
            payload=payload,
        )