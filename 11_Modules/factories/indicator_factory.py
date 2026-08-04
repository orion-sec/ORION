from typing import Any

from models.indicator_profile import (
    IndicatorClassification,
    IndicatorProfile,
    IndicatorType,
)


def create_indicator_profile(
    indicator_type: IndicatorType,
    value: str,
    classification: IndicatorClassification,
    risk_level: str,
    confidence: int,
    category: str = "Unknown",
    threat_family: str = "Unknown",
    first_seen: str = "Unknown",
    last_seen: str = "Unknown",
    country: str = "Unknown",
    asn: str = "Unknown",
    provider: str = "Unknown",
    internal_prevalence: int = 0,
    intelligence_sources: list[str] | None = None,
    related_entities: list[str] | None = None,
    mitre_techniques: list[str] | None = None,
    recommendations: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> IndicatorProfile:
    """
    Creates a standardized IndicatorProfile object.
    """

    return IndicatorProfile(
        indicator_type=indicator_type,
        value=value,
        classification=classification,
        risk_level=risk_level,
        confidence=confidence,
        category=category,
        threat_family=threat_family,
        first_seen=first_seen,
        last_seen=last_seen,
        country=country,
        asn=asn,
        provider=provider,
        internal_prevalence=internal_prevalence,
        intelligence_sources=intelligence_sources or [],
        related_entities=related_entities or [],
        mitre_techniques=mitre_techniques or [],
        recommendations=recommendations or [],
        metadata=metadata or {},
    )