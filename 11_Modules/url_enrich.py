from urllib.parse import urlparse


def enrich_url(url):
    parsed_url = urlparse(url)

    return {
        "url": url,
        "scheme": parsed_url.scheme,
        "hostname": parsed_url.hostname,
        "port": parsed_url.port,
        "path": parsed_url.path,
        "query": parsed_url.query
    }

def enrich_urls(url_list):
    enriched_urls = []

    for url in url_list:
        enriched_urls.append(enrich_url(url))

    return enriched_urls