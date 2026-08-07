from connectors.azure_monitor import AzureMonitorClient
from connectors.config import load_graph_config
from providers.signin_evidence_provider import SignInEvidenceProvider
from reasoners.signin_reasoner import reason_about_signin


def test_signin_reasoner_live() -> None:
    print("=" * 70)
    print("ORION LIVE SIGN-IN REASONER TEST")
    print("=" * 70)

    config = load_graph_config()
    client = AzureMonitorClient(config)

    subscriptions = client.list_subscriptions()

    if not subscriptions:
        raise RuntimeError("No Azure subscriptions were returned.")

    subscription_id = subscriptions[0]["subscriptionId"]

    workspace_id = client.get_log_analytics_workspace_id(
        subscription_id=subscription_id,
        resource_group="orion-rg",
        workspace_name="orion-law",
    )

    provider = SignInEvidenceProvider(
        client=client,
        workspace_id=workspace_id,
    )

    evidence = provider.collect(
        timespan="P1D",
        limit=10,
    )

    print(f"\nLive sign-in events collected: {len(evidence)}")

    all_findings = []

    for index, event in enumerate(evidence, start=1):
        print("\n" + "-" * 70)
        print(f"SIGN-IN EVENT #{index}")
        print("-" * 70)

        print(f"User               : {event.user_principal_name}")
        print(f"IP Address         : {event.ip_address}")
        print(f"Application        : {event.application}")
        print(f"Location           : {event.location}")
        print(f"Conditional Access : {event.conditional_access_status}")
        print(f"Risk Level         : {event.risk_level}")
        print(f"User Agent         : {event.user_agent}")

        findings = reason_about_signin(event)

        all_findings.extend(findings)

        print(f"Findings generated : {len(findings)}")

        for finding in findings:
            print(
                f"  - [{finding.category}] "
                f"{finding.finding}"
            )

    assert evidence, "No live Entra sign-in evidence was returned."

    print()
    print(f"Total findings generated: {len(all_findings)}")
    print("LIVE SIGN-IN REASONER TEST PASSED")


if __name__ == "__main__":
    test_signin_reasoner_live()