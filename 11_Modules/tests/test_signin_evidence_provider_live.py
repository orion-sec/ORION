import pytest

from connectors.azure_monitor import AzureMonitorClient
from connectors.config import load_graph_config
from providers.signin_evidence_provider import SignInEvidenceProvider


def test_signin_evidence_provider_live() -> None:
    print("=" * 70)
    print("ORION LIVE SIGN-IN EVIDENCE PROVIDER TEST")
    print("=" * 70)

    config = load_graph_config()
    client = AzureMonitorClient(config)

    subscriptions = client.list_subscriptions()

    if not subscriptions:
        raise RuntimeError("No Azure subscriptions were returned.")

    subscription_id = subscriptions[0]["subscriptionId"]

    resource_group = "orion-rg"
    workspace_name = "orion-law"

    workspace_id = client.get_log_analytics_workspace_id(
        subscription_id=subscription_id,
        resource_group=resource_group,
        workspace_name=workspace_name,
    )

    provider = SignInEvidenceProvider(
        client=client,
        workspace_id=workspace_id,
    )

    evidence = provider.collect(
        timespan="P1D",
        limit=10,
    )

    print(f"\nEvidence records collected: {len(evidence)}")

    for index, event in enumerate(evidence, start=1):
        print("\n" + "-" * 70)
        print(f"EVIDENCE #{index}")
        print("-" * 70)

        print(f"Time               : {event.time_generated}")
        print(f"User               : {event.user_principal_name}")
        print(f"User ID            : {event.user_id}")
        print(f"IP Address         : {event.ip_address}")
        print(f"ASN                : {event.autonomous_system_number}")
        print(f"Application        : {event.application}")
        print(f"Result             : {event.result_type}")
        print(f"Description        : {event.result_description}")
        print(f"Client App         : {event.client_app}")
        print(f"User Agent         : {event.user_agent}")
        print(
            f"Conditional Access : "
            f"{event.conditional_access_status}"
        )
        print(f"Risk Level         : {event.risk_level}")
        print(f"Location           : {event.location}")
        print(f"Device             : {event.device_detail}")
        print(f"Correlation ID     : {event.correlation_id}")

    if not evidence:
        pytest.skip(
            "No live Entra sign-in evidence available in the current test window."
        )

    print("\nLIVE SIGN-IN EVIDENCE PROVIDER TEST PASSED")


if __name__ == "__main__":
    test_signin_evidence_provider_live()