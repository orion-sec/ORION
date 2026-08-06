from connectors.config import load_graph_config
from connectors.graph_client import GraphClient


def test_graph_mailbox():

    client = GraphClient(load_graph_config())

    profile = client.get_mailbox_profile(
        "orion.sec_outlook.com#EXT#@orionsecoutlook.onmicrosoft.com"
    )

    print(profile)


if __name__ == "__main__":
    test_graph_mailbox()