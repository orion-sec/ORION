from models.investigation import Investigation


def test_investigation_model():
    investigation = Investigation()

    assert investigation.narrative is None
    assert investigation.indicators == {}
    assert investigation.identity_entities == {}
    assert investigation.identity_enrichment == {}
    assert investigation.identity_profile is None

    assert investigation.enriched_ips == []
    assert investigation.threat_intelligence == []
    assert investigation.threat_correlation == {}

    assert investigation.business_impact == {}
    assert investigation.contextual_risk == {}
    assert investigation.operational_decision == {}

    assert investigation.attack_patterns == []
    assert investigation.response_playbooks == []

    assert investigation.hypotheses == []
    assert investigation.findings == []
    assert investigation.questions == []

    assert investigation.confidence_assessment is None
    assert investigation.investigation_outcome is None
    assert investigation.investigation_case is None

    assert investigation.metadata == {}

    print("\n===================================")
    print("INVESTIGATION MODEL VALIDATION")
    print("===================================")
    print("✓ Investigation object created")
    print("✓ Default values validated")
    print("✓ Root aggregate ready")
    print("===================================")


if __name__ == "__main__":
    test_investigation_model()