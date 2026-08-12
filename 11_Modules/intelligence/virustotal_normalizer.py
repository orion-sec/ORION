from typing import Any


def _get_attributes(
    payload: dict[str, Any],
) -> dict[str, Any]:
    """
    Extract VirusTotal object attributes safely.
    """

    data = payload.get("data", {})

    if not isinstance(data, dict):
        return {}

    attributes = data.get("attributes", {})

    if not isinstance(attributes, dict):
        return {}

    return attributes


def _get_analysis_stats(
    attributes: dict[str, Any],
) -> dict[str, int]:
    """
    Extract VirusTotal analysis statistics.
    """

    raw_stats = attributes.get(
        "last_analysis_stats",
        {},
    )

    if not isinstance(raw_stats, dict):
        raw_stats = {}

    stats = {}

    for name in (
        "malicious",
        "suspicious",
        "harmless",
        "undetected",
        "timeout",
    ):
        try:
            stats[name] = int(
                raw_stats.get(name, 0)
            )
        except (TypeError, ValueError):
            stats[name] = 0

    return stats


def _calculate_confidence(
    stats: dict[str, int],
) -> int:
    """
    Produce a deterministic 0-100 confidence score
    from VirusTotal engine verdicts.
    """

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    total = (
        malicious
        + suspicious
        + harmless
        + undetected
    )

    if total <= 0:
        return 0

    weighted_detections = (
        malicious
        + (suspicious * 0.5)
    )

    return min(
        100,
        round(
            (weighted_detections / total) * 100
        ),
    )


def _determine_reputation(
    stats: dict[str, int],
) -> str:
    """
    Convert VirusTotal detections into an ORION
    reputation verdict.
    """

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious >= 3:
        return "Malicious"

    if malicious > 0 or suspicious > 0:
        return "Suspicious"

    return "Clean"


def normalise_virustotal_result(
    payload: dict[str, Any],
) -> dict[str, Any]:
    """
    Convert a VirusTotal API response into ORION's
    provider-neutral indicator enrichment format.
    """

    attributes = _get_attributes(payload)

    stats = _get_analysis_stats(
        attributes
    )

    reputation = _determine_reputation(
        stats
    )

    confidence = _calculate_confidence(
        stats
    )

    return {
        "reputation": reputation,
        "confirmed_malicious": (
            reputation == "Malicious"
        ),
        "suspicious": (
            reputation == "Suspicious"
        ),
        "known_benign": (
            reputation == "Clean"
        ),
        "confidence": confidence,
        "category": str(
            attributes.get(
                "type_description",
                "Unknown",
            )
        ),
        "threat_family": "Unknown",
        "first_seen": str(
            attributes.get(
                "first_submission_date",
                "Unknown",
            )
        ),
        "last_seen": str(
            attributes.get(
                "last_analysis_date",
                "Unknown",
            )
        ),
        "country": str(
            attributes.get(
                "country",
                "Unknown",
            )
        ),
        "asn": str(
            attributes.get(
                "asn",
                "Unknown",
            )
        ),
        "provider": "VirusTotal",
        "intelligence_sources": [
            "VirusTotal"
        ],
        "metadata": {
            "virustotal": {
                "analysis_stats": stats,
                "reputation": attributes.get(
                    "reputation"
                ),
                "tags": attributes.get(
                    "tags",
                    [],
                ),
                "meaningful_name": (
                    attributes.get(
                        "meaningful_name"
                    )
                ),
            }
        },
    }