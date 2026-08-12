import os

import pytest

from connectors.config import load_virustotal_config
from models.indicator_profile import IndicatorType
from providers.virustotal_provider import VirusTotalProvider

#
# SHA256 observed in our Sentinel malware test incident.
#
TEST_FILE_HASH = (
    "275a021bbfb6489e54d471899f7db9d1663fc695"
    "ec2fe2a2c4538aabf651fd0f"
)


def test_virustotal_live_file_hash_lookup() -> None:
    """
    Perform an explicit live VirusTotal lookup and verify
    that the response reaches ORION as an IndicatorProfile.

    This test is disabled during ordinary regression runs.
    Set ORION_RUN_LIVE_VIRUSTOTAL=1 to enable it.
    """

    if os.getenv(
        "ORION_RUN_LIVE_VIRUSTOTAL",
        "",
    ).strip() != "1":
        pytest.skip(
            "Live VirusTotal testing is disabled."
        )

    config = load_virustotal_config()

    provider = VirusTotalProvider(
        config
    )

    profile = provider.lookup_file_hash(
        TEST_FILE_HASH
    )

    assert (
        profile.indicator_type
        == IndicatorType.FILE_HASH
    )

    assert profile.value == TEST_FILE_HASH
    assert profile.provider == "VirusTotal"

    vt_metadata = profile.metadata.get(
        "virustotal",
        {},
    )

    analysis_stats = vt_metadata.get(
        "analysis_stats",
        {},
    )

    print()
    print("=" * 70)
    print("ORION LIVE VIRUSTOTAL INTELLIGENCE")
    print("=" * 70)

    print(
        f"Indicator      : {profile.value}"
    )

    print(
        f"Type           : {profile.indicator_type}"
    )

    print(
        f"Provider       : {profile.provider}"
    )

    print(
        f"Classification : {profile.classification}"
    )

    print(
        f"Risk Level     : {profile.risk_level}"
    )

    print(
        f"Confidence     : {profile.confidence}%"
    )

    print()
    print("VIRUSTOTAL ENGINE RESULTS")
    print("-" * 70)

    print(
        "Malicious      : "
        f"{analysis_stats.get('malicious', 0)}"
    )

    print(
        "Suspicious     : "
        f"{analysis_stats.get('suspicious', 0)}"
    )

    print(
        "Harmless       : "
        f"{analysis_stats.get('harmless', 0)}"
    )

    print(
        "Undetected     : "
        f"{analysis_stats.get('undetected', 0)}"
    )

    print()
    print("ORION VERDICT")
    print("-" * 70)

    print(
        f"{profile.classification} "
        f"| Risk: {profile.risk_level} "
        f"| Confidence: {profile.confidence}%"
    )

    print("=" * 70)