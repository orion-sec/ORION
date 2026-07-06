import re
print("==============================")
print("    ORION IOC EXTRACTOR v1")
print("==============================")

investigation = input("Paste investigation text here: ")

urls = re.findall(r'https?://\S+', investigation)

ips = re.findall(r'\d+\.\d+\.\d+\.\d+', investigation)
md5_hashes = re.findall(r'\b[a-fA-F0-9]{32}\b', investigation)
sha1_hashes = re.findall(r'\b[a-fA-F0-9]{40}\b', investigation)
sha256_hashes = re.findall(r'\b[a-fA-F0-9]{64}\b', investigation)
emails = re.findall(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', investigation)
domains = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', investigation)

print()
print("URLs Found:")
for number, url in enumerate(urls, start=1):
    print(f"{number}. {url}")

print()
print("IP Addresses Found:")
for number, ip in enumerate(ips, start=1):
    print(f"{number}. {ip}")

print()
print("MD5 Hashes Found:")
for number, hash_value in enumerate(md5_hashes, start=1):
    print(f"{number}. {hash_value}")

print()
print("SHA1 Hashes Found:")
for number, hash_value in enumerate(sha1_hashes, start=1):
    print(f"{number}. {hash_value}")

print()
print("SHA256 Hashes Found:")
for number, hash_value in enumerate(sha256_hashes, start=1):
    print(f"{number}. {hash_value}")

    print()
print("Email Addresses Found:")
for number, email in enumerate(emails, start=1):
    print(f"{number}. {email}")

    print()
print("Domains Found:")
for number, domain in enumerate(domains, start=1):
    print(f"{number}. {domain}")

print()
print("Investigation received successfully!")
print()

print("You entered:")
print(investigation)