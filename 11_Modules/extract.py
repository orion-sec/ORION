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
    domain_pattern = r'\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b'

    text_without_emails = re.sub(
        r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',
        '',
        investigation
    )

    domains = re.findall(
        domain_pattern,
        text_without_emails
    )

    email_domains = [
        email.split('@')[1]
        for email in emails
    ]

    domains.extend(email_domains)

    domains = list(
        dict.fromkeys(
            domain.lower().rstrip('.')
            for domain in domains
        )
    )

    blocked_file_extensions = {
        "exe",
        "dll",
        "msi",
        "zip",
        "rar",
        "iso",
        "bat",
        "cmd",
        "ps1",
        "js",
        "vbs",
        "scr"
    }

    filtered_domains = []

    for domain in domains:
        top_level_part = domain.rsplit(".", 1)[-1].lower()

        if top_level_part not in blocked_file_extensions:
            filtered_domains.append(domain)

    domains = filtered_domains

    ips = list(set(ips))
    md5_hashes = list(set(md5_hashes))
    sha1_hashes = list(set(sha1_hashes))
    sha256_hashes = list(set(sha256_hashes))
    emails = list(set(emails))
    domains = list(dict.fromkeys(domains))

    return {
    "URLs": urls,
    "IP Addresses": ips,
    "MD5 Hashes": md5_hashes,
    "SHA1 Hashes": sha1_hashes,
    "SHA256 Hashes": sha256_hashes,
    "Email Addresses": emails,
    "Domains": domains
}