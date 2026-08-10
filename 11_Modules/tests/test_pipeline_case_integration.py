from factories.identity_factory import create_identity_profile
from models.investigation_case import InvestigationCase
from pipeline import OrionPipeline

"""
ORION Pipeline and Case Management Integration Validation

Uses a normalized Microsoft identity profile and confirms that
the existing investigation pipeline can produce one unified case.
"""


investigation = {
    "alert_id": "ORION-INTEGRATION-0001",
    "title": (
        "Suspicious privileged identity activity "
        "from malicious infrastructure"
    ),
    "source": "Microsoft Defender XDR",
    "alert_type": "Identity and Network Threat",
    "user": (
        "orion.sec_outlook.com#EXT#"
        "@orionsecoutlook.onmicrosoft.com"
    ),
    "host": "ORION-ADMIN-WS-001",
    "description": (
        "A privileged Microsoft Entra identity communicated "
        "with suspicious external infrastructure."
    ),
    "ip_address": "203.0.113.66",
}


live_identity_profile = create_identity_profile(
    object_id="fabc03d6-de48-4714-821c-f14e31555acc",
    user_principal_name=(
        "orion.sec_outlook.com#EXT#"
        "@orionsecoutlook.onmicrosoft.com"
    ),
    display_name="ORION Security",
    account_enabled=True,
    groups=[
        "Global Administrator",
    ],
    registered_devices=[],
    risk_level="None",
    risk_state="None",
    risk_detail="None",
    enrichment_status={
        "profile": "Retrieved",
        "manager": "Not assigned",
        "groups": "Retrieved 1",
        "devices": "Retrieved 0",
        "risk": "Unavailable due to tenant licensing",
    },
)


pipeline = OrionPipeline()
pipeline.load_default_pipeline()


results = pipeline.run(
    investigation=investigation,
    results={
        "Live Identity Profile": live_identity_profile,
    },
)


case = results["Investigation Case"]

identity_profile = case.identity_profile

assert identity_profile is not None


print("\n" + "=" * 76)
print("ORION PIPELINE AND CASE INTEGRATION")
print("=" * 76)

print(f"Case ID:             {case.case_id}")
print(f"Title:               {case.title}")
print(f"Status:              {case.status.value}")
print(f"Severity:            {case.severity.value}")
print(f"Affected User:       {case.affected_user}")
print(f"Affected Host:       {case.affected_host}")
print(f"Identity Name:       {identity_profile.display_name}")
print(
    f"Identity Groups:     "
    f"{', '.join(identity_profile.groups)}"
)
print(f"Evidence Count:      {len(case.evidence)}")
print(f"Action Count:        {len(case.recommended_actions)}")
print(f"Timeline Events:     {len(case.timeline)}")
print(f"Tags:                {', '.join(case.tags)}")

print("\nEvidence")
print("-" * 76)

for item in case.evidence:
    print(f"  - {item}")

print("\nTimeline")
print("-" * 76)

for event in case.timeline:
    print(
        f"  - {event.timestamp} | "
        f"{event.event_type} | "
        f"{event.description}"
    )

print("=" * 76)


assert isinstance(case, InvestigationCase)

identity_profile = case.identity_profile

assert identity_profile is not None
assert identity_profile is live_identity_profile
assert identity_profile.display_name == "ORION Security"
assert "Global Administrator" in identity_profile.groups
assert "Privileged Identity" in case.tags
assert case.affected_user
assert len(case.timeline) >= 2

    
from models.investigation import Investigation

investigation_aggregate = results.get("Investigation Aggregate")

assert isinstance(investigation_aggregate, Investigation)
assert investigation_aggregate.investigation_case is case
assert investigation_aggregate.identity_profile is live_identity_profile
assert investigation_aggregate.threat_intelligence
assert investigation_aggregate.threat_correlation
assert investigation_aggregate.business_impact
assert investigation_aggregate.contextual_risk
assert investigation_aggregate.operational_decision
assert investigation_aggregate.metadata["legacy_pipeline"] is True
assert investigation_aggregate.metadata["pipeline_version"] == "Day39"
assert investigation_aggregate.identity_entities
assert investigation_aggregate.identity_enrichment == {}

print("\nInvestigation Aggregate Validation")
print("----------------------------------")

print(f"Type:                {type(investigation_aggregate).__name__}")
print(f"Identity Attached:   {investigation_aggregate.identity_profile is not None}")
print(f"Case Attached:       {investigation_aggregate.investigation_case is not None}")
print(f"Threat Correlation:  {bool(investigation_aggregate.threat_correlation)}")
print(f"Business Impact:     {bool(investigation_aggregate.business_impact)}")

print(
    f"Identity Entities:   "
    f"{bool(investigation_aggregate.identity_entities)}"
)

print(
    f"Legacy Enrichment:   "
    f"{'Available' if investigation_aggregate.identity_enrichment else 'Not available'}"
)

print("✓ Root aggregate created and populated")

print("\nVALIDATION PASSED")
print(
    "ORION successfully integrated identity enrichment, "
    "investigation results and case management."
)