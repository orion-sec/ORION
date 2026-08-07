from evidence_reasoning import reason_over_evidence
from models.signin_evidence import SignInEvidence


def test_evidence_reasoning_signin() -> None:
    event = SignInEvidence(
        time_generated="2026-08-07T13:58:44Z",
        user_principal_name="test.user@example.com",
        user_id="user-123",
        ip_address="203.0.113.10",
        autonomous_system_number=5378,
        application="Azure Portal",
        result_type="50074",
        result_description="Strong authentication required.",
        client_app="Browser",
        user_agent="Mozilla/5.0 Test",
        conditional_access_status="notApplied",
        risk_level="high",
        location="GB",
        device_detail={
            "isManaged": False,
            "isCompliant": False,
        },
        correlation_id="correlation-123",
    )

    evidence = [
        event,
        {
            "category": "Network",
            "finding": "Suspicious network evidence.",
        },
    ]

    findings = reason_over_evidence(evidence)

    print(f"Unified findings generated: {len(findings)}")

    for finding in findings:
        print(f"- {finding}")

    assert len(findings) >= 5

    print("EVIDENCE REASONING SIGN-IN TEST PASSED")


if __name__ == "__main__":
    test_evidence_reasoning_signin()