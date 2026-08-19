from models.indicator_profile import (
    IndicatorClassification,
    IndicatorProfile,
    IndicatorType,
)
from pipeline import cognitive_reasoning_stage


def test_cognitive_reasoning_consumes_indicator_intelligence() -> None:
    """
    Confirm that structured indicator intelligence is promoted into
    cognitive evidence before ORION generates investigation questions.
    """

    profile = IndicatorProfile(
        indicator_type=IndicatorType.FILE_HASH,
        value="a" * 64,
        classification=(
            IndicatorClassification.CONFIRMED_MALICIOUS
        ),
        risk_level="High",
        confidence=95,
        category="Malware",
        threat_family="TestRansomware",
        provider="VirusTotal",
        internal_prevalence=1,
        intelligence_sources=["VirusTotal"],
        mitre_techniques=["T1204.002"],
        recommendations=[
            "Validate execution on affected endpoint",
        ],
    )

    results = {
        "Security Incidents": [],
        "Sign-In Evidence": [],
        "Evidence": [],
        "Findings": [],
        "Indicator Intelligence": [profile],
        "Contextual Risk": {},
        "Business Impact": {},
    }

    updated_results = cognitive_reasoning_stage(
        {},
        results,
    )

    findings = updated_results["Findings"]

    combined_findings = " ".join(
        str(finding)
        for finding in findings
    )

    assert "Confirmed Malicious" in combined_findings
    assert "TestRansomware" in combined_findings
    assert "VirusTotal" in combined_findings