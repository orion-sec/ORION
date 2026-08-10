from connectors.azure_monitor import AzureMonitorClient
from connectors.config import load_graph_config
from providers.environment_search_provider import (
    EnvironmentSearchProvider,
)


def test_live_environment_search_user_signins() -> None:
    """
    Prove that ORION can take a user identity and search
    the live Microsoft environment for related sign-in activity.
    """

    config = load_graph_config()

    client = AzureMonitorClient(config)

    subscriptions = client.list_subscriptions()

    if not subscriptions:
        raise RuntimeError(
            "No Azure subscriptions were returned."
        )

    subscription_id = subscriptions[0]["subscriptionId"]

    resource_group = "orion-rg"
    workspace_name = "orion-law"

    provider = EnvironmentSearchProvider(
        config=config,
        subscription_id=subscription_id,
        resource_group=resource_group,
        workspace_name=workspace_name,
    )

    #
    # First retrieve recent sign-ins so that we can use
    # an identity we know actually exists in the workspace.
    #
    workspace_id = provider.get_workspace_id()

    recent_payload = client.get_signin_evidence(
        workspace_id=workspace_id,
        timespan="P7D",
        limit=20,
    )

    tables = recent_payload.get("tables", [])

    if not tables:
        raise RuntimeError(
            "No SigninLogs table was returned."
        )

    table = tables[0]

    columns = table.get("columns", [])
    rows = table.get("rows", [])

    if not rows:
        raise RuntimeError(
            "No Microsoft Entra sign-in events were returned."
        )

    column_names = [
        column.get("name")
        for column in columns
        if isinstance(column, dict)
    ]

    try:
        upn_index = column_names.index(
            "UserPrincipalName"
        )
    except ValueError as error:
        raise RuntimeError(
            "UserPrincipalName was not returned "
            "by the SigninLogs query."
        ) from error

    user_principal_name = ""

    for row in rows:
        if not isinstance(row, list):
            continue

        if upn_index >= len(row):
            continue

        value = str(row[upn_index] or "").strip()

        if value:
            user_principal_name = value
            break

    if not user_principal_name:
        raise RuntimeError(
            "No usable user identity was found "
            "in recent SigninLogs."
        )

    print()
    print("=" * 70)
    print("ORION LIVE ENVIRONMENT SEARCH")
    print("=" * 70)

    print(
        f"Subscription : {subscription_id}"
    )

    print(
        f"Workspace    : {workspace_name}"
    )

    print(
        f"Workspace ID : {workspace_id}"
    )

    print(
        f"Pivot User   : {user_principal_name}"
    )

    #
    # This is the important part:
    #
    # ORION now uses the discovered identity as an
    # investigation pivot and searches the wider environment.
    #
    results = provider.search(
        correlation_keys=[
            {
                "type": "user",
                "value": user_principal_name,
            }
        ],
        timespan="P7D",
    )

    print()
    print("ENVIRONMENT SEARCH RESULTS")
    print("-" * 70)

    print(
        f"Search Count : "
        f"{results['search_count']}"
    )

    for result in results["results"]:
        print()
        print(
            f"Entity Type : {result['type']}"
        )

        print(
            f"Entity Value: {result['value']}"
        )

        print(
            f"Source      : {result['source']}"
        )

        print(
            f"Matches     : {result['match_count']}"
        )

        for signin in result["matches"][:5]:
            print()
            print(
                f"  Time       : "
                f"{signin.time_generated}"
            )

            print(
                f"  User       : "
                f"{signin.user_principal_name}"
            )

            print(
                f"  IP         : "
                f"{signin.ip_address}"
            )

            print(
                f"  App        : "
                f"{signin.application}"
            )

            print(
                f"  Result     : "
                f"{signin.result_type}"
            )

            print(
                f"  Risk       : "
                f"{signin.risk_level}"
            )

            print(
                f"  Location   : "
                f"{signin.location}"
            )

            print(
                f"  User Agent : "
                f"{signin.user_agent}"
            )

            print(
                f"  Device     : "
                f"{signin.device_detail}"
            )

    assert results["search_count"] == 1

    assert results["results"]

    assert (
        results["results"][0]["value"]
        == user_principal_name
    )

    assert (
        results["results"][0]["match_count"]
        >= 1
    )


def test_live_environment_search_ip_signins() -> None:
    """
    Prove that ORION can take a real IP address discovered
    in Microsoft Entra telemetry and pivot across the live
    environment for related sign-in activity.
    """

    config = load_graph_config()

    client = AzureMonitorClient(config)

    subscriptions = client.list_subscriptions()

    if not subscriptions:
        raise RuntimeError(
            "No Azure subscriptions were returned."
        )

    subscription_id = subscriptions[0]["subscriptionId"]

    resource_group = "orion-rg"
    workspace_name = "orion-law"

    provider = EnvironmentSearchProvider(
        config=config,
        subscription_id=subscription_id,
        resource_group=resource_group,
        workspace_name=workspace_name,
    )

    workspace_id = provider.get_workspace_id()

    #
    # Retrieve recent sign-ins first so ORION can obtain
    # an IP address that genuinely exists in the workspace.
    #
    recent_payload = client.get_signin_evidence(
        workspace_id=workspace_id,
        timespan="P7D",
        limit=20,
    )

    tables = recent_payload.get("tables", [])

    if not tables:
        raise RuntimeError(
            "No SigninLogs table was returned."
        )

    table = tables[0]

    columns = table.get("columns", [])
    rows = table.get("rows", [])

    if not rows:
        raise RuntimeError(
            "No Microsoft Entra sign-in events were returned."
        )

    column_names = [
        column.get("name")
        for column in columns
        if isinstance(column, dict)
    ]

    try:
        ip_index = column_names.index(
            "IPAddress"
        )
    except ValueError as error:
        raise RuntimeError(
            "IPAddress was not returned "
            "by the SigninLogs query."
        ) from error

    ip_address = ""

    for row in rows:
        if not isinstance(row, list):
            continue

        if ip_index >= len(row):
            continue

        value = str(
            row[ip_index] or ""
        ).strip()

        if value:
            ip_address = value
            break

    if not ip_address:
        raise RuntimeError(
            "No usable IP address was found "
            "in recent SigninLogs."
        )

    print()
    print("=" * 70)
    print("ORION LIVE IP ENVIRONMENT SEARCH")
    print("=" * 70)

    print(
        f"Subscription : {subscription_id}"
    )

    print(
        f"Workspace    : {workspace_name}"
    )

    print(
        f"Workspace ID : {workspace_id}"
    )

    print(
        f"Pivot IP     : {ip_address}"
    )

    #
    # ORION now takes the discovered IP as a pivot
    # and searches the wider environment.
    #
    results = provider.search(
        correlation_keys=[
            {
                "type": "ip",
                "value": ip_address,
            }
        ],
        timespan="P7D",
    )

    print()
    print("IP ENVIRONMENT SEARCH RESULTS")
    print("-" * 70)

    print(
        f"Search Count : "
        f"{results['search_count']}"
    )

    for result in results["results"]:
        print()
        print(
            f"Entity Type : {result['type']}"
        )

        print(
            f"Entity Value: {result['value']}"
        )

        print(
            f"Source      : {result['source']}"
        )

        print(
            f"Matches     : {result['match_count']}"
        )

        for signin in result["matches"][:10]:
            print()
            print(
                f"  Time       : "
                f"{signin.time_generated}"
            )

            print(
                f"  User       : "
                f"{signin.user_principal_name}"
            )

            print(
                f"  IP         : "
                f"{signin.ip_address}"
            )

            print(
                f"  App        : "
                f"{signin.application}"
            )

            print(
                f"  Result     : "
                f"{signin.result_type}"
            )

            print(
                f"  Risk       : "
                f"{signin.risk_level}"
            )

            print(
                f"  Location   : "
                f"{signin.location}"
            )

            print(
                f"  User Agent : "
                f"{signin.user_agent}"
            )

            print(
                f"  Device     : "
                f"{signin.device_detail}"
            )

    assert results["search_count"] == 1

    assert results["results"]

    ip_result = results["results"][0]

    assert ip_result["type"] == "ip"

    assert (
        ip_result["value"]
        == ip_address
    )

    assert (
        ip_result["match_count"]
        >= 1
    )

    assert all(
        signin.ip_address == ip_address
        for signin in ip_result["matches"]
    )
        
if __name__ == "__main__":
        test_live_environment_search_user_signins()
        test_live_environment_search_ip_signins()