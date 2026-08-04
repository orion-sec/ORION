from typing import Any

from factories.indicator_factory import create_indicator_profile
from models.indicator_profile import (
    IndicatorClassification,
    IndicatorProfile,
    IndicatorType,
)


"""
ORION IOC Intelligence Engine

Transforms normalized indicator enrichment into consistent,
explainable IndicatorProfile objects.
"""


SUPPORTED_TYPES = {
    "url": IndicatorType.URL,
    "ip": IndicatorType.IP_ADDRESS,
    "ip_address": IndicatorType.IP_ADDRESS,
    "domain": IndicatorType.DOMAIN,
    "hash": IndicatorType.FILE_HASH,
    "file_hash": IndicatorType.FILE_HASH,
    "email": IndicatorType.EMAIL,
    "user": IndicatorType.USER,
    "device": IndicatorType.DEVICE,
}


DEFAULT_RECOMMENDATIONS = {
    IndicatorType.URL: [
        "Block the URL and associated domain where approved.",
        "Search the environment for historical URL access.",
        "Identify users and devices that accessed the URL.",
        "Review related downloads and process execution.",
    ],
    IndicatorType.IP_ADDRESS: [
        "Block the IP address where approved.",
        "Search network telemetry for related connections.",
        "Identify communicating users and devices.",
        "Investigate associated domains and infrastructure.",
    ],
    IndicatorType.DOMAIN: [
        "Block or monitor the domain where approved.",
        "Review passive DNS and related IP addresses.",
        "Search email, proxy and endpoint telemetry.",
        "Investigate related subdomains and certificates.",
    ],
    IndicatorType.FILE_HASH: [
        "Block or quarantine the file hash where approved.",
        "Search all endpoints for file prevalence.",
        "Review parent and child process relationships.",
        "Collect the file safely for malware analysis.",
    ],
    IndicatorType.EMAIL: [
        "Review SPF, DKIM and DMARC results.",
        "Search for additional messages from the sender.",
        "Identify recipients, clicks and credential submissions.",
        "Block the sender or domain where appropriate.",
    ],
    IndicatorType.USER: [
        "Review recent authentication activity.",
        "Validate MFA status and registered devices.",
        "Review privilege, role and group membership.",
        "Revoke sessions if compromise is confirmed.",
    ],
    IndicatorType.DEVICE: [
        "Review endpoint alerts and process telemetry.",
        "Confirm EDR health and isolation status.",
        "Assess asset criticality and business ownership.",
        "Isolate the device if compromise is confirmed.",
    ],
}


def _normalise_indicator_type(indicator_type: str) -> IndicatorType:
    """
    Converts a string indicator type into IndicatorType.
    """

    normalised = indicator_type.strip().lower().replace("-", "_")

    resolved = SUPPORTED_TYPES.get(normalised)

    if resolved is None:
        raise ValueError(
            f"Unsupported indicator type: {indicator_type}"
        )

    return resolved


def _clamp_score(value: Any) -> int:
    """
    Safely constrains a confidence score to 0-100.
    """

    try:
        score = int(value)
    except (TypeError, ValueError):
        return 0

    return max(0, min(score, 100))


def _determine_classification(
    enrichment: dict[str, Any],
) -> IndicatorClassification:
    """
    Assigns a deterministic intelligence classification.
    """

    reputation = str(
        enrichment.get("reputation", "")
    ).strip().lower()

    confirmed_malicious = enrichment.get(
        "confirmed_malicious"
    ) is True

    known_benign = enrichment.get(
        "known_benign"
    ) is True

    suspicious = enrichment.get(
        "suspicious"
    ) is True

    if confirmed_malicious or reputation in {
        "malicious",
        "confirmed malicious",
        "known malicious",
    }:
        return IndicatorClassification.CONFIRMED_MALICIOUS

    if suspicious or reputation in {
        "suspicious",
        "potentially malicious",
        "high risk",
    }:
        return IndicatorClassification.SUSPICIOUS

    if known_benign or reputation in {
        "benign",
        "clean",
        "trusted",
    }:
        return IndicatorClassification.BENIGN

    return IndicatorClassification.UNKNOWN


def _determine_risk_level(
    classification: IndicatorClassification,
    confidence: int,
    enrichment: dict[str, Any],
) -> str:
    """
    Determines the indicator risk level.
    """

    explicit_risk = enrichment.get("risk_level")

    if explicit_risk:
        return str(explicit_risk).title()

    if classification == IndicatorClassification.CONFIRMED_MALICIOUS:
        if confidence >= 90:
            return "Critical"

        return "High"

    if classification == IndicatorClassification.SUSPICIOUS:
        if confidence >= 70:
            return "High"

        return "Medium"

    if classification == IndicatorClassification.BENIGN:
        return "Low"

    return "Unknown"


def _build_recommendations(
    indicator_type: IndicatorType,
    enrichment: dict[str, Any],
) -> list[str]:
    """
    Returns custom recommendations or type-specific defaults.
    """

    supplied = enrichment.get("recommendations")

    if isinstance(supplied, list) and supplied:
        return [
            str(item)
            for item in supplied
        ]

    return list(
        DEFAULT_RECOMMENDATIONS.get(
            indicator_type,
            [],
        )
    )


def enrich_indicator(
    indicator_type: str,
    value: str,
    enrichment: dict[str, Any] | None = None,
) -> IndicatorProfile:
    """
    Creates an enriched ORION indicator profile.

    The enrichment dictionary will later be populated by
    live intelligence providers and security APIs.
    """

    if not value or not value.strip():
        raise ValueError("Indicator value cannot be empty.")

    enrichment = enrichment or {}

    resolved_type = _normalise_indicator_type(
        indicator_type
    )

    confidence = _clamp_score(
        enrichment.get("confidence", 0)
    )

    classification = _determine_classification(
        enrichment
    )

    risk_level = _determine_risk_level(
        classification=classification,
        confidence=confidence,
        enrichment=enrichment,
    )

    return create_indicator_profile(
        indicator_type=resolved_type,
        value=value.strip(),
        classification=classification,
        risk_level=risk_level,
        confidence=confidence,
        category=str(
            enrichment.get("category", "Unknown")
        ),
        threat_family=str(
            enrichment.get("threat_family", "Unknown")
        ),
        first_seen=str(
            enrichment.get("first_seen", "Unknown")
        ),
        last_seen=str(
            enrichment.get("last_seen", "Unknown")
        ),
        country=str(
            enrichment.get("country", "Unknown")
        ),
        asn=str(
            enrichment.get("asn", "Unknown")
        ),
        provider=str(
            enrichment.get("provider", "Unknown")
        ),
        internal_prevalence=max(
            0,
            int(enrichment.get("internal_prevalence", 0)),
        ),
        intelligence_sources=list(
            enrichment.get("intelligence_sources", [])
        ),
        related_entities=list(
            enrichment.get("related_entities", [])
        ),
        mitre_techniques=list(
            enrichment.get("mitre_techniques", [])
        ),
        recommendations=_build_recommendations(
            resolved_type,
            enrichment,
        ),
        metadata=dict(
            enrichment.get("metadata", {})
        ),
    )


def enrich_indicators(
    indicators: list[dict[str, Any]],
) -> list[IndicatorProfile]:
    """
    Enriches multiple indicators through the same engine.
    """

    profiles = []

    for indicator in indicators:
        profiles.append(
            enrich_indicator(
                indicator_type=str(
                    indicator.get("indicator_type", "")
                ),
                value=str(
                    indicator.get("value", "")
                ),
                enrichment=dict(
                    indicator.get("enrichment", {})
                ),
            )
        )

    return profiles