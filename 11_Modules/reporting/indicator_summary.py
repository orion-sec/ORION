from models.indicator_profile import IndicatorProfile


def _render_list(
    heading: str,
    values: list[str],
) -> list[str]:
    """
    Renders a readable list section.
    """

    lines = [heading]

    if not values:
        lines.append("  - None")
        return lines

    for value in values:
        lines.append(f"  - {value}")

    return lines


def generate_indicator_summary(
    profile: IndicatorProfile,
) -> str:
    """
    Generates an analyst-ready IOC intelligence summary.
    """

    lines = [
        "=" * 72,
        "ORION IOC INTELLIGENCE SUMMARY",
        "=" * 72,
        f"Type:                 {profile.indicator_type.value}",
        f"Indicator:            {profile.value}",
        f"Classification:       {profile.classification.value}",
        f"Risk Level:           {profile.risk_level}",
        f"Confidence:           {profile.confidence}%",
        f"Category:             {profile.category}",
        f"Threat Family:        {profile.threat_family}",
        f"First Seen:           {profile.first_seen}",
        f"Last Seen:            {profile.last_seen}",
        f"Country:              {profile.country}",
        f"ASN:                  {profile.asn}",
        f"Provider:             {profile.provider}",
        f"Internal Prevalence:  {profile.internal_prevalence}",
        "",
    ]

    lines.extend(
        _render_list(
            "Intelligence Sources:",
            profile.intelligence_sources,
        )
    )

    lines.append("")

    lines.extend(
        _render_list(
            "Related Entities:",
            profile.related_entities,
        )
    )

    lines.append("")

    lines.extend(
        _render_list(
            "MITRE ATT&CK:",
            profile.mitre_techniques,
        )
    )

    lines.append("")

    lines.extend(
        _render_list(
            "Recommended Actions:",
            profile.recommendations,
        )
    )

    lines.append("=" * 72)

    return "\n".join(lines)