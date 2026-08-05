from connectors.auth import GraphAuthenticator
from connectors.config import load_graph_config


"""
ORION Live Microsoft Graph Authentication Validation

This test contacts Microsoft Entra ID and requests a real
application access token through the OAuth 2.0 client-credentials flow.

The access token is never printed.
"""


def mask_identifier(value: str) -> str:
    """
    Safely masks an identifier for terminal output.
    """

    if len(value) < 12:
        return "********"

    return f"{value[:6]}...{value[-6:]}"


config = load_graph_config()
authenticator = GraphAuthenticator(config)

print("\n" + "=" * 72)
print("ORION MICROSOFT GRAPH LIVE AUTHENTICATION")
print("=" * 72)

print(f"Tenant ID:  {mask_identifier(config.tenant_id)}")
print(f"Client ID:  {mask_identifier(config.client_id)}")
print(f"Authority:  {config.authority}")
print(f"Scope:      {config.scope}")
print("Secret:     Loaded securely — value not displayed")
print()
print("Requesting live Microsoft Graph application token...")


token = authenticator.acquire_token()


print("Token acquired successfully.")
print(f"Token type: {token.token_type}")
print(f"Expires in: {token.expires_in} seconds")
print("Token value: Hidden for security")
print("=" * 72)


assert token.access_token
assert token.token_type.lower() == "bearer"
assert token.expires_in > 0
assert token.authorization_header["Authorization"].startswith(
    "Bearer "
)


print("\nVALIDATION PASSED")
print(
    "ORION successfully authenticated with Microsoft Entra ID "
    "and obtained a live Microsoft Graph access token."
)