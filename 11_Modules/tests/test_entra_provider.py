from connectors.config import load_graph_config
from providers.entra_provider import EntraProvider


def test_entra_provider():

    provider = EntraProvider(
        load_graph_config()
    )

    result = provider.enrich_user(
        "orion.sec_outlook.com#EXT#@orionsecoutlook.onmicrosoft.com"
    )

    print()
    print("=" * 40)
    print("ORION ENTRA PROVIDER")
    print("=" * 40)
    print("Provider:", result.provider)
    print("Status:", result.status)

    if result.error:
        print("Reason:", result.error)
    else:
        print("User:")
        print(result.identity)

if __name__ == "__main__":
        test_entra_provider()