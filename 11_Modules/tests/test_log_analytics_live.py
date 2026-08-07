from connectors.azure_monitor import AzureMonitorClient
from connectors.config import load_graph_config


def test_log_analytics_live() -> None:
    print("=" * 70)
    print("ORION LOG ANALYTICS TELEMETRY DISCOVERY")
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

    print()
    print(f"Subscription ID : {subscription_id}")
    print(f"Resource Group  : {resource_group}")
    print(f"Workspace       : {workspace_name}")
    print(f"Workspace ID    : {workspace_id}")
    print()

    query = """
    search *
    | summarize RecordCount=count() by $table
    | order by RecordCount desc
    """

    result = client.run_kql(
        workspace_id=workspace_id,
        query=query,
        timespan="P30D",
    )

    tables = result.get("tables", [])

    if not tables:
        print("No Log Analytics results returned.")
        return

    for table in tables:
        columns = [
            column.get("name", "Unknown")
            for column in table.get("columns", [])
        ]

        rows = table.get("rows", [])

        print(f"Result Table : {table.get('name', 'Unknown')}")
        print(f"Columns      : {columns}")
        print(f"Rows         : {len(rows)}")
        print()

        for row in rows:
            print(row)


if __name__ == "__main__":
    test_log_analytics_live()