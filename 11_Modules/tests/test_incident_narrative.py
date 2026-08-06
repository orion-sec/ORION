from decision_engine.investigation_decision import determine_outcome
from models.hypothesis import Hypothesis
from reporting.incident_narrative import generate_incident_narrative

alert_details = {
    "alert_id": "ORION-CRITICAL-0001",
    "title": "Malicious document execution with command-and-control activity",
    "severity": "Critical",
    "hostname": "FINANCE-WS-001",
    "user": "finance.admin@orion.local",
    "department": "Finance",
    "asset_criticality": "Critical",
    "parent_process": "WINWORD.EXE",
    "child_process": "powershell.exe",
    "grandchild_process": "rundll32.exe"
}


hypotheses = [
    Hypothesis(
        title="Confirmed endpoint compromise",
        explanation=(
            "A malicious document spawned PowerShell, downloaded a payload "
            "and communicated with command-and-control infrastructure."
        ),
        confidence=97
    )
]


signals = {
    "evidence_strength": 98,
    "identity_risk": 92,
    "threat_intelligence_risk": 100,
    "hypothesis_support": 97,
    "business_context_risk": 95,
    "historical_behavior_risk": 98,
    "detection_quality": 99
}


decision_context = {
    "confirmed_malicious": True,
    "supporting_evidence": [
        "The URL was confirmed malicious.",
        "The external IP was associated with command-and-control activity.",
        "The file hash matched a known malicious file.",
        "WINWORD.EXE spawned PowerShell.",
        "PowerShell launched rundll32.exe.",
        "Credential-access behaviour was detected."
    ]
}


outcome = determine_outcome(
    hypotheses=hypotheses,
    signals=signals,
    decision_context=decision_context
)


narrative = generate_incident_narrative(
    alert_details=alert_details,
    outcome=outcome
)


print("\n" + "=" * 75)
print("ORION INCIDENT NARRATIVE")
print("=" * 75)

print("\nExecutive Summary:")
print(narrative.executive_summary)

print("\nAnalyst Verdict:")
print(narrative.analyst_verdict)

print(f"\nSeverity:    {narrative.severity}")
print(f"Disposition: {narrative.disposition}")
print(f"Confidence:  {narrative.confidence}%")

print("\nKey Evidence:")
for item in narrative.key_evidence:
    print(f"  - {item}")

print("=" * 75)


assert narrative.disposition == "True Positive"
assert narrative.confidence >= 90
assert narrative.severity == "Critical"
assert "FINANCE-WS-001" in narrative.executive_summary
assert "finance.admin@orion.local" in narrative.executive_summary
assert "WINWORD.EXE -> powershell.exe -> rundll32.exe" in narrative.executive_summary
assert len(narrative.key_evidence) > 0

print("\nVALIDATION PASSED")
print("ORION successfully generated an analyst-ready incident narrative.")