from connectors.azure_monitor import AzureMonitorClient
from connectors.config import load_graph_config


def test_signin_evidence_live() -> None:
    print("=" * 70)
    print("ORION LIVE ENTRA SIGN-IN EVIDENCE")
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

    result = client.get_signin_evidence(
        workspace_id=workspace_id,
        timespan="P7D",
        limit=10,
    )

    tables = result.get("tables", [])

    if not tables:
        print("\nNo sign-in evidence returned.")
        return

    table = tables[0]

    columns = [
        column["name"]
        for column in table.get("columns", [])
    ]

    rows = table.get("rows", [])

    print(f"\nWorkspace ID : {workspace_id}")
    print(f"Evidence Rows: {len(rows)}")

    for row in rows:
        evidence = dict(zip(columns, row))

        print("\n" + "-" * 70)
        print(f"Time             : {evidence.get('TimeGenerated')}")
        print(f"User             : {evidence.get('UserPrincipalName')}")
        print(f"User ID          : {evidence.get('UserId')}")
        print(f"IP Address       : {evidence.get('IPAddress')}")
        print(
            f"ASN              : "
            f"{evidence.get('AutonomousSystemNumber')}"
        )
        print(f"Application      : {evidence.get('AppDisplayName')}")
        print(f"Result           : {evidence.get('ResultType')}")
        print(f"Description      : {evidence.get('ResultDescription')}")
        print(f"Client App       : {evidence.get('ClientAppUsed')}")
        print(f"User Agent       : {evidence.get('UserAgent')}")
        print(
            "Conditional Access: "
            f"{evidence.get('ConditionalAccessStatus')}"
        )
        print(
            "Risk Level       : "
            f"{evidence.get('RiskLevelDuringSignIn')}"
        )
        print(f"Location         : {evidence.get('Location')}")
        print(f"Device           : {evidence.get('DeviceDetail')}")
        print(f"Correlation ID   : {evidence.get('CorrelationId')}")


if __name__ == "__main__":
    test_signin_evidence_live()