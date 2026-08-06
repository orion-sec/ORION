from intelligence.indicator_engine import enrich_indicators
from models.indicator_profile import (
    IndicatorClassification,
    IndicatorType,
)
from reporting.indicator_summary import generate_indicator_summary

"""
ORION IOC Intelligence Validation

Uses synthetic and documentation-safe indicators.
No live malicious infrastructure is contacted.
"""


indicators = [
    {
        "indicator_type": "url",
        "value": "hxxps://secure-update-check[.]example/payload",
        "enrichment": {
            "reputation": "Malicious",
            "confirmed_malicious": True,
            "confidence": 98,
            "category": "Command and Control",
            "threat_family": "SyntheticLoader",
            "first_seen": "2026-07-28",
            "last_seen": "2026-08-04",
            "internal_prevalence": 3,
            "intelligence_sources": [
                "Synthetic Threat Intelligence",
                "Endpoint Telemetry",
                "Proxy Telemetry",
            ],
            "related_entities": [
                "FINANCE-WS-001",
                "finance.admin@orion.local",
                "203.0.113.66",
            ],
            "mitre_techniques": [
                "T1071.001 - Web Protocols",
                "T1105 - Ingress Tool Transfer",
            ],
        },
    },
    {
        "indicator_type": "ip",
        "value": "203.0.113.66",
        "enrichment": {
            "reputation": "Confirmed Malicious",
            "confidence": 100,
            "category": "Command-and-Control Infrastructure",
            "threat_family": "SyntheticLoader",
            "country": "Synthetic High-Risk Region",
            "asn": "AS64500",
            "provider": "Synthetic Hosting Provider",
            "first_seen": "2026-07-20",
            "last_seen": "2026-08-04",
            "internal_prevalence": 2,
            "intelligence_sources": [
                "Synthetic Threat Intelligence",
                "Firewall Telemetry",
            ],
            "related_entities": [
                "FINANCE-WS-001",
                "secure-update-check.example",
            ],
            "mitre_techniques": [
                "T1071.001 - Web Protocols",
            ],
        },
    },
    {
        "indicator_type": "file_hash",
        "value": (
            "9f86d081884c7d659a2feaa0c55ad015"
            "a3bf4f1b2b0b822cd15d6c15b0f00a08"
        ),
        "enrichment": {
            "reputation": "Malicious",
            "confidence": 99,
            "category": "Malware",
            "threat_family": "SyntheticLoader",
            "first_seen": "2026-07-25",
            "last_seen": "2026-08-04",
            "internal_prevalence": 1,
            "intelligence_sources": [
                "Synthetic Malware Intelligence",
                "Endpoint Detection",
            ],
            "related_entities": [
                "invoice_review.docm",
                "powershell.exe",
                "rundll32.exe",
            ],
            "mitre_techniques": [
                "T1204.002 - Malicious File",
                "T1059.001 - PowerShell",
                "T1218.011 - Rundll32",
            ],
        },
    },
]


profiles = enrich_indicators(indicators)


for profile in profiles:
    print()
    print(generate_indicator_summary(profile))


url_profile = profiles[0]
ip_profile = profiles[1]
hash_profile = profiles[2]


assert url_profile.indicator_type == IndicatorType.URL
assert (
    url_profile.classification
    == IndicatorClassification.CONFIRMED_MALICIOUS
)
assert url_profile.risk_level == "Critical"
assert url_profile.confidence == 98
assert url_profile.internal_prevalence == 3

assert ip_profile.indicator_type == IndicatorType.IP_ADDRESS
assert ip_profile.country == "Synthetic High-Risk Region"
assert ip_profile.confidence == 100
assert ip_profile.risk_level == "Critical"

assert hash_profile.indicator_type == IndicatorType.FILE_HASH
assert hash_profile.threat_family == "SyntheticLoader"
assert len(hash_profile.mitre_techniques) == 3
assert len(hash_profile.recommendations) >= 3


print()
print("VALIDATION PASSED")
print(
    "ORION successfully enriched and summarized URL, IP and "
    "file-hash indicators."
)