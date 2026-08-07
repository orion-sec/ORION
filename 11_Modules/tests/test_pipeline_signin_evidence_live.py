from connectors.azure_monitor import AzureMonitorClient
from connectors.config import load_graph_config
from pipeline import OrionPipeline, signin_evidence_stage
from providers.signin_evidence_provider import SignInEvidenceProvider


def test_pipeline_signin_evidence_live() -> None:
    print("=" * 70)
    print("ORION PIPELINE LIVE SIGN-IN EVIDENCE TEST")
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

    pipeline = OrionPipeline()

    # Run only the new authentication-evidence stage for this test.
    pipeline.add_stage(signin_evidence_stage)

    results = {
        "Sign-In Evidence Provider": provider,
    }

    investigation = {
        "title": "Live Entra Sign-In Evidence Test",
        "source": "Microsoft Entra ID",
    }

    results = pipeline.run(
        investigation=investigation,
        results=results,
    )

    aggregate = results["Investigation Aggregate"]

    print()
    print(
        f"Sign-in evidence attached: "
        f"{len(aggregate.signin_evidence)}"
    )

    for event in aggregate.signin_evidence:
        print("-" * 70)
        print(f"User        : {event.user_principal_name}")
        print(f"IP Address  : {event.ip_address}")
        print(f"Application : {event.application}")
        print(f"Location    : {event.location}")
        print(f"User Agent  : {event.user_agent}")

    assert aggregate.signin_evidence

    print()
    print("PIPELINE LIVE SIGN-IN EVIDENCE TEST PASSED")


if __name__ == "__main__":
    test_pipeline_signin_evidence_live()