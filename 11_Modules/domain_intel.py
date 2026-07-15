def inspect_domain(domain):
    suspicious_keywords = [
    "login",
    "signin",
    "verify",
    "secure",
    "account",
    "update",
    "password",
    "support"
]
    
    matched_keywords = []

    for keyword in suspicious_keywords:
      if keyword in domain.lower():
        matched_keywords.append(keyword)

    if matched_keywords:
        status = "Reviewed"
        reputation = "Suspicious"
        confidence = 40
    else:
        status = "Reviewed"
        reputation = "Unknown"
        confidence = 0

    return {
        "domain": domain,
        "status": status,
        "reputation": reputation,
        "confidence": confidence,
        "matched_keywords": matched_keywords,
    }

def inspect_domains(domain_list):
    domain_results = []

    for domain in domain_list:
        domain_results.append(inspect_domain(domain))

    return domain_results