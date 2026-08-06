from connectors.config import load_graph_config
from connectors.graph_client import GraphClient

"""
ORION Live Microsoft Graph User Retrieval Validation

This test authenticates using ORION's application identity
and retrieves a limited number of users from Microsoft Entra ID.
"""


def safe_value(value) -> str:
    """
    Prevents empty values from producing unclear output.
    """

    if value is None or value == "":
        return "Not configured"

    return str(value)


config = load_graph_config()
client = GraphClient(config)


print("\n" + "=" * 72)
print("ORION LIVE MICROSOFT GRAPH USER RETRIEVAL")
print("=" * 72)
print("Requesting up to five users from Microsoft Entra ID...")


users = client.get_users(maximum_users=5)


print(f"\nUsers retrieved: {len(users)}")


for index, user in enumerate(users, start=1):
    print("\n" + "-" * 72)
    print(f"User {index}")
    print("-" * 72)
    print(
        f"Display Name:       "
        f"{safe_value(user.get('displayName'))}"
    )
    print(
        f"User Principal Name:"
        f" {safe_value(user.get('userPrincipalName'))}"
    )
    print(
        f"Email:              "
        f"{safe_value(user.get('mail'))}"
    )
    print(
        f"Job Title:          "
        f"{safe_value(user.get('jobTitle'))}"
    )
    print(
        f"Department:         "
        f"{safe_value(user.get('department'))}"
    )
    print(
        f"Office:             "
        f"{safe_value(user.get('officeLocation'))}"
    )
    print(
        f"Account Enabled:    "
        f"{safe_value(user.get('accountEnabled'))}"
    )
    print(
        f"Object ID:          "
        f"{safe_value(user.get('id'))}"
    )


print("\n" + "=" * 72)


assert isinstance(users, list)

if users:
    assert users[0].get("id")
    assert users[0].get("displayName")


print("\nVALIDATION PASSED")
print(
    "ORION successfully authenticated and retrieved live "
    "Microsoft Entra user data through Microsoft Graph."
)