from connectors.config import load_graph_config
from connectors.graph_client import GraphClient
from enrichment.identity_enrichment import (
    IdentityEnrichmentEngine,
)

"""
ORION Live Identity Enrichment Validation

Retrieves the first available user from Microsoft Graph and
enriches the identity using manager, group, device, and risk context.
"""


def display_value(value) -> str:
    """
    Produces readable terminal output for empty values.
    """

    if value in (None, "", []):
        return "Not configured"

    return str(value)


config = load_graph_config()
client = GraphClient(config)
engine = IdentityEnrichmentEngine(client)


users = client.get_users(maximum_users=1)

if not users:
    raise RuntimeError(
        "No Microsoft Entra users were available for enrichment."
    )


target_user = users[0]["id"]

print("\n" + "=" * 72)
print("ORION LIVE IDENTITY ENRICHMENT")
print("=" * 72)
print(f"Target object ID: {target_user}")
print("Retrieving live identity context...")


profile = engine.enrich_user(target_user)


print("\nCore Identity")
print("-" * 72)
print(
    f"Display Name:       "
    f"{display_value(profile.display_name)}"
)
print(
    f"UPN:                "
    f"{display_value(profile.user_principal_name)}"
)
print(
    f"Email:              "
    f"{display_value(profile.email)}"
)
print(
    f"Job Title:          "
    f"{display_value(profile.job_title)}"
)
print(
    f"Department:         "
    f"{display_value(profile.department)}"
)
print(
    f"Office:             "
    f"{display_value(profile.office_location)}"
)
print(
    f"Account Enabled:    "
    f"{profile.account_enabled}"
)


print("\nManager")
print("-" * 72)
print(
    f"Manager Name:       "
    f"{display_value(profile.manager_name)}"
)
print(
    f"Manager UPN:        "
    f"{display_value(profile.manager_upn)}"
)


print("\nGroups")
print("-" * 72)

if profile.groups:
    for group in profile.groups:
        print(f"  - {group}")
else:
    print("  - No direct group memberships returned")


print("\nRegistered Devices")
print("-" * 72)

if profile.registered_devices:
    for device in profile.registered_devices:
        print(f"  - {device}")
else:
    print("  - No registered devices returned")


print("\nIdentity Risk")
print("-" * 72)
print(f"Risk Level:         {profile.risk_level}")
print(f"Risk State:         {profile.risk_state}")
print(f"Risk Detail:        {profile.risk_detail}")


print("\nEnrichment Status")
print("-" * 72)

for source, result in profile.enrichment_status.items():
    print(f"{source.title():18} {result}")


print("=" * 72)


assert profile.object_id
assert profile.display_name
assert profile.user_principal_name
assert profile.enrichment_status["profile"] == "Retrieved"


print("\nVALIDATION PASSED")
print(
    "ORION successfully produced a live, normalized "
    "Microsoft Entra identity profile."
)