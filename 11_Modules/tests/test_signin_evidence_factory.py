from factories.signin_evidence_factory import create_signin_evidence


def test_create_signin_evidence() -> None:
    raw_event = {
        "TimeGenerated": "2026-08-07T13:58:44Z",
        "UserPrincipalName": "test.user@example.com",
        "UserId": "user-123",
        "IPAddress": "203.0.113.10",
        "AutonomousSystemNumber": 5378,
        "AppDisplayName": "Azure Portal",
        "ResultType": "0",
        "ResultDescription": "",
        "ClientAppUsed": "Browser",
        "UserAgent": "Mozilla/5.0 Test",
        "ConditionalAccessStatus": "notApplied",
        "RiskLevelDuringSignIn": "hidden",
        "Location": "GB",
        "DeviceDetail": {
            "operatingSystem": "Windows 10",
            "browser": "Edge",
        },
        "CorrelationId": "correlation-123",
    }

    evidence = create_signin_evidence(raw_event)

    assert evidence.user_principal_name == "test.user@example.com"
    assert evidence.ip_address == "203.0.113.10"
    assert evidence.autonomous_system_number == 5378
    assert evidence.application == "Azure Portal"
    assert evidence.client_app == "Browser"
    assert evidence.user_agent == "Mozilla/5.0 Test"
    assert evidence.location == "GB"
    assert evidence.correlation_id == "correlation-123"

    print("SignInEvidence factory test passed.")


if __name__ == "__main__":
    test_create_signin_evidence()