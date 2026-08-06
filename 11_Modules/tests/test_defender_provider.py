from connectors.config import load_graph_config
from providers.defender_provider import DefenderProvider


def test_defender_provider():
    config = load_graph_config()
    provider = DefenderProvider(config)

    result = provider.get_recent_incidents(
        top=5,
        expand_alerts=False,
    )

    assert result.provider == "Microsoft Defender XDR"
    assert result.status in {
        "Available",
        "Unavailable",
        "Error",
    }

    if result.available:
        assert isinstance(result.incidents, list)

    print("\n========================================")
    print("ORION DEFENDER PROVIDER")
    print("========================================")
    print(f"Provider:  {result.provider}")
    print(f"Status:    {result.status}")
    print(f"Incidents: {len(result.incidents)}")

    if result.error:
        print(f"Reason:    {result.error}")

    print("========================================")
    print("✓ Defender provider handled response successfully")
    print("========================================")


if __name__ == "__main__":
    test_defender_provider()