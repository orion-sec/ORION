from factories.case_factory import create_investigation_case
from models.investigation_case import (
    CaseSeverity,
    CaseStatus,
)

"""
ORION Investigation Case Model Validation

Builds a critical synthetic case and confirms that evidence,
MITRE techniques, actions and timeline events are unified.
"""


case = create_investigation_case(
    case_id="ORION-CASE-000001",
    title=(
        "Malicious document execution with "
        "command-and-control activity"
    ),
    alert_id="ORION-CRITICAL-0001",
    alert_source="Microsoft Defender XDR",
    alert_type="Malware and Command and Control",
    severity=CaseSeverity.CRITICAL,
    status=CaseStatus.INVESTIGATING,
    affected_user="finance.admin@orion.local",
    affected_host="FINANCE-WS-001",
    tenant_id="synthetic-tenant",
    assigned_to="Tier 2 SOC Analyst",
    raw_alert={
        "process_chain": (
            "WINWORD.EXE -> powershell.exe -> rundll32.exe"
        ),
        "malicious_ip": "203.0.113.66",
        "malicious_url": (
            "hxxps://secure-update-check[.]example"
        ),
    },
)


case.confidence = 97
case.business_impact_score = 95
case.business_impact_level = "Critical"


case.add_evidence(
    "WINWORD.EXE spawned PowerShell with an encoded command."
)

case.add_evidence(
    "PowerShell downloaded a payload from a malicious URL."
)

case.add_evidence(
    "The endpoint connected to confirmed command-and-control "
    "infrastructure."
)


case.add_mitre_technique(
    "T1204.002 - Malicious File"
)

case.add_mitre_technique(
    "T1059.001 - PowerShell"
)

case.add_mitre_technique(
    "T1105 - Ingress Tool Transfer"
)

case.add_mitre_technique(
    "T1218.011 - Rundll32"
)


case.add_recommended_action(
    "Immediately isolate FINANCE-WS-001."
)

case.add_recommended_action(
    "Revoke active sessions for "
    "finance.admin@orion.local."
)

case.add_recommended_action(
    "Block the malicious URL, IP address and file hash."
)


case.add_timeline_event(
    timestamp="2026-08-05T09:31:00+00:00",
    event_type="Process Execution",
    description="WINWORD.EXE launched powershell.exe.",
    source="Endpoint Telemetry",
    entity="FINANCE-WS-001",
)

case.add_timeline_event(
    timestamp="2026-08-05T09:32:10+00:00",
    event_type="Network Connection",
    description=(
        "PowerShell connected to malicious "
        "command-and-control infrastructure."
    ),
    source="Firewall Telemetry",
    entity="203.0.113.66",
)


case.change_status(
    CaseStatus.CONTAINMENT_PENDING
)


print("\n" + "=" * 76)
print("ORION INVESTIGATION CASE")
print("=" * 76)

print(f"Case ID:             {case.case_id}")
print(f"Title:               {case.title}")
print(f"Alert ID:            {case.alert_id}")
print(f"Source:              {case.alert_source}")
print(f"Status:              {case.status.value}")
print(f"Severity:            {case.severity.value}")
print(f"Confidence:          {case.confidence}%")
print(
    f"Business Impact:     "
    f"{case.business_impact_level} "
    f"({case.business_impact_score}/100)"
)
print(f"Affected User:       {case.affected_user}")
print(f"Affected Host:       {case.affected_host}")
print(f"Assigned To:         {case.assigned_to}")


print("\nEvidence")
print("-" * 76)

for item in case.evidence:
    print(f"  - {item}")


print("\nMITRE ATT&CK")
print("-" * 76)

for technique in case.mitre_techniques:
    print(f"  - {technique}")


print("\nRecommended Actions")
print("-" * 76)

for action in case.recommended_actions:
    print(f"  - {action}")


print("\nTimeline")
print("-" * 76)

for event in case.timeline:
    print(
        f"  - {event.timestamp} | "
        f"{event.event_type} | "
        f"{event.description}"
    )


print("=" * 76)


assert case.case_id == "ORION-CASE-000001"
assert case.severity == CaseSeverity.CRITICAL
assert case.status == CaseStatus.CONTAINMENT_PENDING
assert case.confidence == 97
assert case.business_impact_score == 95
assert len(case.evidence) == 3
assert len(case.mitre_techniques) == 4
assert len(case.recommended_actions) == 3
assert len(case.timeline) >= 4


print("\nVALIDATION PASSED")
print(
    "ORION successfully unified alert metadata, evidence, "
    "MITRE techniques, actions and timeline events into one case."
)