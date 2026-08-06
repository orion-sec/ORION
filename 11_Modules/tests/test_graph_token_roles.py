import base64
import json

from connectors.auth import GraphAuthenticator
from connectors.config import load_graph_config


def decode_payload(access_token: str) -> dict:
    payload = access_token.split(".")[1]
    payload += "=" * (-len(payload) % 4)

    return json.loads(
        base64.urlsafe_b64decode(payload).decode("utf-8")
    )


def test_graph_token_roles():
    config = load_graph_config()
    token = GraphAuthenticator(config).acquire_token()
    claims = decode_payload(token.access_token)

    roles = claims.get("roles", [])

    print("\nGRAPH APPLICATION TOKEN ROLES")
    print("--------------------------------")
    for role in sorted(roles):
        print(role)

    assert "SecurityIncident.Read.All" in roles

    print("--------------------------------")
    print("✓ SecurityIncident.Read.All present in token")


if __name__ == "__main__":
    test_graph_token_roles()