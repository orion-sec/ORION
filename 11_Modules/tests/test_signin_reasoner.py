from models.signin_evidence import SignInEvidence
from reasoners.signin_reasoner import reason_about_signin


def test_signin_reasoner() -> None:
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
            "operatingSystem": "Windows 10",
            "browser": "Edge",
        },
        correlation_id="correlation-123",
    )

    findings = reason_about_signin(event)

    print(f"Findings generated: {len(findings)}")

    for finding in findings:
        print(f"- {finding}")

    assert len(findings) >= 4

    print("SIGN-IN REASONER TEST PASSED")


if __name__ == "__main__":
    test_signin_reasoner()