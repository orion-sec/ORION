import re


def extract_iocs(investigation):

    urls = re.findall(r'https?://\S+', investigation)

    clean_urls = []

    for url in urls:
        url = url.rstrip(".,;:!?")
        clean_urls.append(url)

    urls = list(set(clean_urls))

    ips = re.findall(r'\d+\.\d+\.\d+\.\d+', investigation)
    md5_hashes = re.findall(r'\b[a-fA-F0-9]{32}\b', investigation)
    sha1_hashes = re.findall(r'\b[a-fA-F0-9]{40}\b', investigation)
    sha256_hashes = re.findall(r'\b[a-fA-F0-9]{64}\b', investigation)
    emails = re.findall(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', investigation)
    domains = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', investigation)

    ips = list(set(ips))
    md5_hashes = list(set(md5_hashes))
    sha1_hashes = list(set(sha1_hashes))
    sha256_hashes = list(set(sha256_hashes))
    emails = list(set(emails))
    domains = list(set(domains))

    return {
    "URLs": urls,
    "IP Addresses": ips,
    "MD5 Hashes": md5_hashes,
    "SHA1 Hashes": sha1_hashes,
    "SHA256 Hashes": sha256_hashes,
    "Email Addresses": emails,
    "Domains": domains
}