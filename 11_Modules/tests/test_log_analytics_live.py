from connectors.azure_monitor import AzureMonitorClient
from connectors.config import load_graph_config

WORKSPACE_ID = "ba4ddd85-02e0-4006-99d2-f4b61a1983cf"


def test_log_analytics() -> None:
    print("=" * 70)
    print("ORION LOG ANALYTICS LIVE TEST")
    print("=" * 70)

    client = AzureMonitorClient(load_graph_config())

    result = client.run_kql(
        workspace_id=WORKSPACE_ID,
        query="""
Heartbeat
| take 5
""",
    )

    print(result)


if __name__ == "__main__":
    test_log_analytics()