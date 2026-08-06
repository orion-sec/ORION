from connectors.config import load_graph_config
from connectors.graph_defender_incidents import list_defender_incidents


def test_graph_defender_incidents_live():
    config = load_graph_config()

    incidents = list_defender_incidents(
        config=config,
        top=5,
        expand_alerts=True,
    )

    print("\n========================================")
    print("MICROSOFT DEFENDER XDR INCIDENTS")
    print("========================================")
    print(f"Incidents returned: {len(incidents)}")

    for incident in incidents:
        print("----------------------------------------")
        print(f"Incident ID: {incident.get('id')}")
        print(f"Title:       {incident.get('displayName')}")
        print(f"Severity:    {incident.get('severity')}")
        print(f"Status:      {incident.get('status')}")
        print(f"Updated:     {incident.get('lastUpdateDateTime')}")

        alerts = incident.get("alerts", [])
        print(f"Alerts:      {len(alerts)}")

    print("========================================")
    print("✓ Defender XDR incident connection successful")
    print("========================================")


if __name__ == "__main__":
    test_graph_defender_incidents_live()