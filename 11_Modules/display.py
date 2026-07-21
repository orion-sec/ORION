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
    print("IOC RISK SCORES")
    print("=" * 35)

    for score in scores:
        print(f"Risk   : {score['risk']}")
        print(f"Score  : {score['score']}")
        print(f"Reason : {score['reason']}")
        print("-" * 35)   

def display_recommendations(recommendations):
    print()
    print("=" * 35)
    print("IOC-LEVEL RECOMMENDATIONS")
    print("=" * 35)

    for recommendation_list in recommendations:
        for number, action in enumerate(recommendation_list, start=1):
            print(f"{number}. {action}")

        print("-" * 35)
def display_priorities(priorities):
    print()
    print("=" * 35)
    print("IOC-LEVEL PRIORITY")
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

def display_threat_correlation(correlation_results):
    print()
    print("=" * 35)
    print("THREAT CORRELATION")
    print("=" * 35)

    for correlation in correlation_results:
        print(f"Verdict    : {correlation['verdict']}")
        print(f"Confidence : {correlation['confidence']}")
        print(f"Sources    : {correlation['sources']}")
        print(f"Reason     : {correlation['reason']}")
        print("-" * 35)

def display_enriched_urls(enriched_urls):
    print()
    print("=" * 35)
    print("URL ENRICHMENT")
    print("=" * 35)

    for url in enriched_urls:
        print(f"URL      : {url['url']}")
        print(f"Scheme   : {url['scheme']}")
        print(f"Hostname : {url['hostname']}")
        print(f"Port     : {url['port']}")
        print(f"Path     : {url['path']}")
        print(f"Query    : {url['query']}")
        print("-" * 35)

def display_url_scores(url_scores):
    print()
    print("=" * 35)
    print("URL RISK SCORES")
    print("=" * 35)

    for result in url_scores:
        print(f"URL     : {result['url']}")
        print(f"Risk    : {result['risk']}")
        print(f"Score   : {result['score']}")

        if result["reasons"]:
            print("Reasons :")
            for reason in result["reasons"]:
                print(f"  - {reason}")
        else:
            print("Reasons : No suspicious URL characteristics detected")

        print("-" * 35)

def display_domain_intelligence(domain_results):
    print()
    print("=" * 35)
    print("DOMAIN INTELLIGENCE")
    print("=" * 35)

    for result in domain_results:
        print(f"Domain     : {result['domain']}")
        print(f"Status     : {result['status']}")
        print(f"Reputation : {result['reputation']}")
        print(f"Confidence : {result['confidence']}")

        if result["matched_keywords"]:
            print(f"Matched    : {', '.join(result['matched_keywords'])}")
        else:
            print("Matched    : None")

        print("-" * 35)

def display_investigation_assessment(assessment):
    print()
    print("=" * 35)
    print("INVESTIGATION ASSESSMENT")
    print("=" * 35)

    print(f"Verdict        : {assessment['verdict']}")
    print(f"Confidence     : {assessment['confidence']}")
    print(f"Strong Signals : {assessment['strong_signals']}")
    print(f"Suspicious     : {assessment['suspicious_signals']}")
    print(f"Evidence Score : {assessment['evidence_score']}")

    print("Evidence :")

    if assessment["evidence"]:
        for item in assessment["evidence"]:
            print(f"  - {item}")
    else:
        print("  - No significant evidence identified")

    print("-" * 35)

def display_investigation_recommendations(recommendations):
    print()
    print("=" * 35)
    print("INVESTIGATION RECOMMENDATIONS")
    print("=" * 35)

    for number, action in enumerate(recommendations, start=1):
        print(f"{number}. {action}")

    print("-" * 35)


def display_investigation_priority(priority):
    print()
    print("=" * 35)
    print("OVERALL INVESTIGATION PRIORITY")
    print("=" * 35)

    print(f"Priority : {priority['priority']}")
    print(f"Action   : {priority['action']}")
    print("-" * 35)

def display_attack_patterns(patterns):
    print()
    print("=" * 35)
    print("ATTACK PATTERN DETECTION")
    print("=" * 35)

    if not patterns:
        print("No known attack patterns detected.")
        print("-" * 35)
        return

    for pattern in patterns:
        print(f"Pattern     : {pattern['name']}")
        print(f"Severity    : {pattern['severity']}")
        print(f"Confidence  : {pattern['confidence']}")
        print(f"Description : {pattern['description']}")
        print("-" * 35)

def display_mitre_attack(mitre_results):
    print()
    print("=" * 35)
    print("MITRE ATT&CK")
    print("=" * 35)

    if mitre_results:
        for mitre_result in mitre_results:
            print(f"Tactic         : {mitre_result['tactic']}")
            print(
                f"Technique      : "
                f"{mitre_result['technique_id']} - "
                f"{mitre_result['technique_name']}"
            )
            print(f"Confidence     : {mitre_result['confidence']}")
            print(f"Classification Reason     : {mitre_result['reason']}")
            print("-" * 35)
    else:
        print("No MITRE ATT&CK mappings identified.")
        print("-" * 35)        

def display_response_playbooks(playbooks):
    print()
    print("=" * 35)
    print("RESPONSE PLAYBOOKS")
    print("=" * 35)

    if not playbooks:
        print("No response playbooks generated.")
        print("-" * 35)
        return

    for playbook in playbooks:
        print(f"Pattern     : {playbook['pattern']}")
        print(f"Severity    : {playbook['severity']}")
        print(f"Confidence  : {playbook['confidence']}")
        print("Actions     :")

        for number, action in enumerate(playbook["actions"], start=1):
            print(f"  {number}. {action}")

        print("-" * 35)

def display_contextual_risk(contextual_risk):
    print("\n===================================")
    print("CONTEXTUAL RISK ASSESSMENT")
    print("===================================")

    print(f"Risk Score    : {contextual_risk['score']}")
    print(f"Severity      : {contextual_risk['severity']}")
    print(f"Confidence    : {contextual_risk['confidence']}")
    print(f"Containment   : {contextual_risk['containment']}")

    print("Evidence      :")

    if contextual_risk["evidence"]:
        for item in contextual_risk["evidence"]:
            print(f"  - {item}")
    else:
        print("  - No significant contextual risk evidence identified.")

    print("-----------------------------------")

def display_identity_entities(identity):
    print("===================================")
    print("IDENTITY ENTITIES")
    print("===================================")

    primary_user = identity.get("primary_user")

    if primary_user:
        print(f"Primary User     : {primary_user['email']}")
        print(f"Display Name     : {primary_user['display_name']}")
        print(f"Department       : {primary_user['department']}")
        print(f"Manager          : {primary_user['manager']}")
        print(f"Role             : {primary_user['role']}")
        print(f"Privilege Level  : {primary_user['privilege_level']}")
        print(f"Risk Level       : {primary_user['risk_level']}")
        print(f"Source           : {primary_user['source']}")
    else:
        print("Primary User     : None identified")

    print()

    print(f"Identity Count   : {identity['identity_count']}")

    if identity["email_addresses"]:
        print("Email Addresses  :")
        for index, email in enumerate(identity["email_addresses"], start=1):
            print(f"  {index}. {email}")
    else:
        print("Email Addresses  : None found.")

    print("-----------------------------------")
    print()

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

    display_identity_entities(
    results["Identity Entities"]
)
    display_enriched_ips(results["Enriched IPs"])
    display_enriched_urls(results["Enriched URLs"])
    display_url_scores(results["URL Scores"])
    display_domain_intelligence(results["Domain Intelligence"])
    display_investigation_assessment(
    results["Investigation Assessment"]
)
        
    display_investigation_recommendations(
        results["Investigation Recommendations"]
    )

    display_investigation_priority(
        results["Investigation Priority"]
)

    display_attack_patterns(
        results["Attack Patterns"]
)

    display_mitre_attack(results["MITRE ATT&CK"]
                         
)

    display_contextual_risk(
        results["Contextual Risk"]
)

    display_response_playbooks(
        results["Response Playbooks"]
)
    
    display_scores(results["IP Scores"])
    display_recommendations(results["Recommendations"])
    display_priorities(results["Priorities"])
    display_threat_intelligence(results["Threat Intelligence"])
    display_threat_correlation(results["Threat Correlation"])

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