import os

from connectors.config import load_graph_config


"""
ORION Microsoft Graph Configuration Validation

This test verifies configuration loading only.
It does not contact Microsoft Graph.
"""


TEST_VALUES = {
    "ORION_GRAPH_TENANT_ID": "00000000-0000-0000-0000-000000000001",
    "ORION_GRAPH_CLIENT_ID": "00000000-0000-0000-0000-000000000002",
    "ORION_GRAPH_CLIENT_SECRET": "synthetic-secret-not-for-production",
    "ORION_GRAPH_SCOPE": "https://graph.microsoft.com/.default",
    "ORION_GRAPH_BASE_URL": "https://graph.microsoft.com/v1.0",
}


original_values = {
    key: os.environ.get(key)
    for key in TEST_VALUES
}


try:
    os.environ.update(TEST_VALUES)

    config = load_graph_config()

    print("\n" + "=" * 72)
    print("ORION MICROSOFT GRAPH CONFIGURATION")
    print("=" * 72)

    print(f"Tenant ID:  {config.tenant_id}")
    print(f"Client ID:  {config.client_id}")
    print(f"Scope:      {config.scope}")
    print(f"Base URL:   {config.base_url}")
    print(f"Authority:  {config.authority}")
    print("Secret:     Loaded securely — value not displayed")

    print("=" * 72)

    assert config.tenant_id == TEST_VALUES[
        "ORION_GRAPH_TENANT_ID"
    ]
    assert config.client_id == TEST_VALUES[
        "ORION_GRAPH_CLIENT_ID"
    ]
    assert config.scope.endswith("/.default")
    assert config.base_url == (
        "https://graph.microsoft.com/v1.0"
    )
    assert config.authority.startswith(
        "https://login.microsoftonline.com/"
    )

    print("\nVALIDATION PASSED")
    print(
        "ORION securely loaded and validated its "
        "Microsoft Graph configuration."
    )

finally:
    for key, original_value in original_values.items():
        if original_value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = original_value