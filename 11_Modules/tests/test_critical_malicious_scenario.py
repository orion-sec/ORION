import sys
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parents[1]

if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

from decision_engine.investigation_decision import determine_outcome
from models.hypothesis import Hypothesis
from models.investigation_outcome import Disposition


"""
Critical Malicious Scenario Test

Simulates a high-severity endpoint compromise involving:

- Malicious URL access
- Threat-intelligence-listed IP
- Malicious file hash
- Suspicious process execution
- Credential theft indicators
- Command-and-control communication
"""


alert_details = {
    "alert_id": "ORION-CRITICAL-0001",
    "severity": "Critical",
    "title": "Malicious document execution with command-and-control activity",

    "user": "finance.admin@orion.local",
    "hostname": "FINANCE-WS-001",
    "asset_criticality": "Critical",
    "department": "Finance",

    # Safe documentation IP range
    "source_ip": "203.0.113.66",
    "source_country": "Synthetic High-Risk Region",
    "source_ip_reputation": "Malicious",
    "source_ip_confidence": 100,

    # Defanged synthetic URL
    "malicious_url": (
        "hxxps://secure-update-check[.]example/"
        "download/invoice_update.ps1"
    ),
    "url_reputation": "Malicious",
    "url_confidence": 100,

    # Synthetic SHA-256
    "file_name": "invoice_review.docm",
    "file_hash_sha256": (
        "9f86d081884c7d659a2feaa0c55ad015"
        "a3bf4f1b2b0b822cd15d6c15b0f00a08"
    ),
    "file_hash_reputation": "Malicious",

    "parent_process": "WINWORD.EXE",
    "child_process": "powershell.exe",
    "child_command_line": (
        "powershell.exe -NoProfile -EncodedCommand <REDACTED>"
    ),
    "grandchild_process": "rundll32.exe",

    "observed_behaviours": [
        "Microsoft Word spawned PowerShell.",
        "PowerShell downloaded content from a malicious URL.",
        "The downloaded file hash matched threat intelligence.",
        "The endpoint connected to a malicious external IP.",
        "Credential-access behaviour was detected.",
        "The activity occurred outside the user's normal baseline.",
        "No approved change or security-testing record was found."
    ],

    "mitre_attack": [
        "T1204.002 - Malicious File",
        "T1059.001 - PowerShell",
        "T1105 - Ingress Tool Transfer",
        "T1218.011 - Rundll32",
        "T1003 - OS Credential Dumping",
        "T1071.001 - Web Protocols"
    ]
}


hypotheses = [
    Hypothesis(
        title="Confirmed endpoint compromise and command-and-control activity",
        explanation=(
            "A malicious document spawned PowerShell, downloaded a payload "
            "from a confirmed malicious URL, executed a threat-listed file, "
            "and communicated with a malicious external IP. Credential-access "
            "behaviour and an abnormal process chain were also observed."
        ),
        confidence=97
    ),
    Hypothesis(
        title="Authorised administrative activity",
        explanation=(
            "The execution may have resulted from an approved administrator "
            "or software-deployment action."
        ),
        confidence=8
    ),
    Hypothesis(
        title="False-positive process correlation",
        explanation=(
            "The process relationship may have been incorrectly correlated "
            "by the detection platform."
        ),
        confidence=4
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
        (
            "The URL hxxps://secure-update-check[.]example was classified "
            "as malicious by threat intelligence."
        ),
        (
            "The external IP 203.0.113.66 was classified as malicious and "
            "associated with command-and-control infrastructure."
        ),
        (
            "The downloaded SHA-256 hash matched a known malicious-file record."
        ),
        (
            "WINWORD.EXE spawned powershell.exe with an encoded command."
        ),
        (
            "PowerShell subsequently launched rundll32.exe."
        ),
        (
            "Credential-access behaviour was detected on the endpoint."
        ),
        (
            "The affected device belongs to the Finance department and is "
            "classified as a critical business asset."
        ),
        (
            "No authorised change, administration activity, penetration test "
            "or vulnerability scan matched the event."
        )
    ],

    "contradicting_evidence": [],

    "unresolved_questions": [
        "Were any credentials successfully extracted?",
        "Did the account authenticate to additional systems?",
        "Did the same indicators appear on other endpoints?"
    ],

    "recommended_actions": [
        "Immediately isolate FINANCE-WS-001 from the network.",
        "Disable or temporarily suspend finance.admin@orion.local.",
        "Revoke active identity sessions and authentication tokens.",
        "Reset the affected user's password using the approved process.",
        "Block the malicious URL, domain, IP address and file hash.",
        "Collect endpoint forensic evidence and volatile data.",
        "Search the environment for the same hash, URL, IP and process chain.",
        "Investigate potential credential theft and lateral movement.",
        "Escalate as a critical incident.",
        "Preserve all evidence for incident response and regulatory review."
    ]
}


outcome = determine_outcome(
    hypotheses=hypotheses,
    signals=signals,
    decision_context=decision_context
)


print("\n" + "=" * 75)
print("ORION CRITICAL INCIDENT DECISION")
print("=" * 75)

print(f"Alert ID:    {alert_details['alert_id']}")
print(f"Title:       {alert_details['title']}")
print(f"Severity:    {alert_details['severity']}")
print(f"Host:        {alert_details['hostname']}")
print(f"User:        {alert_details['user']}")

print("\nObserved process chain:")
print(
    f"{alert_details['parent_process']} -> "
    f"{alert_details['child_process']} -> "
    f"{alert_details['grandchild_process']}"
)

print(f"\nDisposition: {outcome.disposition.value}")
print(f"Confidence:  {outcome.confidence}%")
print(f"Reason:      {outcome.reason}")

print("\nSupporting evidence:")
for item in outcome.supporting_evidence:
    print(f"  - {item}")

print("\nUnresolved questions:")
for item in outcome.unresolved_questions:
    print(f"  - {item}")

print("\nRecommended actions:")
for item in outcome.recommended_actions:
    print(f"  - {item}")

print("\nMITRE ATT&CK mapping:")
for technique in alert_details["mitre_attack"]:
    print(f"  - {technique}")

print("=" * 75)


assert outcome.disposition == Disposition.TRUE_POSITIVE, (
    f"Expected TRUE_POSITIVE but received {outcome.disposition}"
)

assert outcome.confidence >= 90, (
    f"Expected confidence of at least 90 but received {outcome.confidence}"
)

assert len(outcome.supporting_evidence) > 5, (
    "Expected the outcome to preserve detailed supporting evidence."
)

assert len(outcome.recommended_actions) >= 5, (
    "Expected critical incident-response recommendations."
)

print("\nVALIDATION PASSED")
print("ORION correctly classified the scenario as a critical True Positive.")