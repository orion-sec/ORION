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

def display_enriched_ips(enriched_ips):
    print()
    print("=" * 35)
    print("IP ENRICHMENT")
    print("=" * 35)

    for ip in enriched_ips:
        print(f"IP Address : {ip['ip']}")
        print(f"Version    : {ip['version']}")
        print(f"Private    : {ip['is_private']}")
        print(f"Global     : {ip['is_global']}")
        print(f"Loopback   : {ip['is_loopback']}")
        print(f"Multicast  : {ip['is_multicast']}")
        print(f"Reserved   : {ip['is_reserved']}")
        print("-" * 35)

def display_scores(scores):

    print()
    print("=" * 35)
    print("RISK SCORES")
    print("=" * 35)

    for score in scores:
        print(f"Risk   : {score['risk']}")
        print(f"Score  : {score['score']}")
        print(f"Reason : {score['reason']}")
        print("-" * 35)   

def display_recommendations(recommendations):
    print()
    print("=" * 35)
    print("ANALYST RECOMMENDATIONS")
    print("=" * 35)

    for recommendation_list in recommendations:
        for number, action in enumerate(recommendation_list, start=1):
            print(f"{number}. {action}")

        print("-" * 35)
def display_priorities(priorities):
    print()
    print("=" * 35)
    print("INVESTIGATION PRIORITY")
    print("=" * 35)

    for priority in priorities:
        print(f"Priority : {priority['priority']}")
        print(f"Action   : {priority['action']}")
        print("-" * 35)

def display_threat_intelligence(threat_results):
    print()
    print("=" * 35)
    print("THREAT INTELLIGENCE")
    print("=" * 35)

    for threat in threat_results:
        print(f"IP          : {threat['ip']}")
        print(f"Source      : {threat['source']}")
        print(f"Status      : {threat['status']}")
        print(f"Reputation  : {threat['reputation']}")
        print(f"Confidence  : {threat['confidence']}")
        print(f"Reports     : {threat['reports']}")
        print("-" * 35)

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

    display_all_results({
    "URLs": results["URLs"],
    "IP Addresses": results["IP Addresses"],
    "MD5 Hashes": results["MD5 Hashes"],
    "SHA1 Hashes": results["SHA1 Hashes"],
    "SHA256 Hashes": results["SHA256 Hashes"],
    "Email Addresses": results["Email Addresses"],
    "Domains": results["Domains"]
})

    display_enriched_ips(results["Enriched IPs"])
    display_scores(results["IP Scores"])
    display_recommendations(results["Recommendations"])
    display_priorities(results["Priorities"])
    display_threat_intelligence(
    results["Threat Intelligence"]
)

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