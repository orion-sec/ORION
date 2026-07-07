import re

def display_results(title, items):
    print()
    print(f"{title} Found ({len(items)}):")

    if items:
        for number, item in enumerate(items, start=1):
            print(f"{number}. {item}")
    else:
        print("None found.")

def display_summary(urls, ips, md5_hashes, sha1_hashes, sha256_hashes, emails, domains):
    print("=" * 35)
    print("IOC SUMMARY")
    print("=" * 35)

    print(f"URLs     : {len(urls)}")
    print(f"IPs      : {len(ips)}")
    print(f"MD5      : {len(md5_hashes)}")
    print(f"SHA1     : {len(sha1_hashes)}")
    print(f"SHA256   : {len(sha256_hashes)}")
    print(f"Emails   : {len(emails)}")
    print(f"Domains  : {len(domains)}")

    print()

print("==============================")
print("    ORION IOC EXTRACTOR v1")
print("==============================")

investigation = input("Paste investigation text here: ")

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

urls = list(set(urls))
ips = list(set(ips))
md5_hashes = list(set(md5_hashes))
sha1_hashes = list(set(sha1_hashes))
sha256_hashes = list(set(sha256_hashes))
emails = list(set(emails))
domains = list(set(domains))

display_summary(urls, ips, md5_hashes, sha1_hashes, sha256_hashes, emails, domains)

print()
display_results("URLs", urls)
display_results("IP Addresses", ips)
display_results("MD5 Hashes", md5_hashes)
display_results("SHA1 Hashes", sha1_hashes)
display_results("SHA256 Hashes", sha256_hashes)
display_results("Email Addresses", emails)
display_results("Domains", domains)

print()
print("Investigation received successfully!")
print()

print("You entered:")
print(investigation)