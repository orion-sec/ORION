def display_results(title, items):
    print()
    print(f"{title} Found ({len(items)}):")

    if items:
        for number, item in enumerate(items, start=1):
            print(f"{number}. {item}")
    else:
        print("None found.")


def display_all_results(results):

    for title, items in results.items():
        display_results(title, items)

def display_report(results):
    display_summary(
        results["URLs"],
        results["IP Addresses"],
        results["MD5 Hashes"],
        results["SHA1 Hashes"],
        results["SHA256 Hashes"],
        results["Email Addresses"],
        results["Domains"]
    )

    print()

    display_all_results(results)        

def display_summary(urls, ips, md5_hashes, sha1_hashes, sha256_hashes, emails, domains):
    print("=" * 35)
    print("IOC SUMMARY")
    print("=" * 35)

    print(f"URLs      : {len(urls)}")
    print(f"IPs        : {len(ips)}")
    print(f"MD5        : {len(md5_hashes)}")
    print(f"SHA1       : {len(sha1_hashes)}")
    print(f"SHA256     : {len(sha256_hashes)}")
    print(f"Emails     : {len(emails)}")
    print(f"Domains    : {len(domains)}")

    print()        