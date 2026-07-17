def detect_attack_patterns(
    url_scores,
    domain_results,
    ip_scores,
    threat_correlation
):

    attack_patterns = []

    # Detect credential phishing patterns
    suspicious_url = any(
        result["risk"] in ["Medium", "High"]
        for result in url_scores
    )

    suspicious_domain = any(
        result["reputation"] == "Suspicious"
        for result in domain_results
    )

    if suspicious_url and suspicious_domain:
        attack_patterns.append({
            "name": "Credential Phishing",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "Suspicious URL characteristics combined with a "
                "suspicious login-related domain."
            )
        })
    
        # Detect malware delivery patterns
    malware_url = any(
        any(
            indicator in result["url"].lower()
            for indicator in [
                ".exe",
                ".dll",
                ".zip",
                ".rar",
                ".iso",
                ".msi",
                "download",
                "payload",
                "installer"
            ]
        )
        for result in url_scores
    )

    malicious_infrastructure = (
        any(
            result["risk"] == "High"
            for result in ip_scores
        )
        or threat_correlation["verdict"] in ["Suspicious", "Malicious"]
    )

    if malware_url and malicious_infrastructure:
        attack_patterns.append({
            "name": "Malware Delivery",
            "severity": "High",
            "confidence": "Medium",
            "description": (
                "A suspicious file-delivery URL was identified together "
                "with risky or malicious infrastructure."
            )
        })

    return attack_patterns