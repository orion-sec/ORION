THREAT_SOURCES = {
    "AbuseIPDB": {
        "display_name": "AbuseIPDB",
        "category": "Community",
        "confidence": "Medium",
        "weight": 15,
        "description": (
            "Community-driven abuse reporting platform focused on malicious IP "
            "addresses and abusive network activity."
        )
    }
}

def get_threat_source(source_name):
    """
    Returns metadata for a registered threat-intelligence provider.

    Args:
        source_name: Provider name used in normalized threat intelligence.

    Returns:
        Provider metadata dictionary.
    """

    return THREAT_SOURCES.get(
        source_name,
        {
            "display_name": source_name or "Unknown",
            "category": "Unknown",
            "confidence": "Unknown",
            "weight": 0,
            "description": "Threat-intelligence provider is not registered."
        }
    )