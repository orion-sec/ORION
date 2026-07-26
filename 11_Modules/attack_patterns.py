def detect_attack_patterns(
    investigation,
    url_scores,
    domain_results,
    ip_scores,
    threat_correlation
):

    attack_patterns = []

    investigation_text = investigation.lower()

        # Detect credential phishing patterns
    suspicious_url = any(
        result["risk"] in ["Medium", "High"]
        for result in url_scores
    )

    suspicious_domain = any(
        result["reputation"] == "Suspicious"
        for result in domain_results
    )

    credential_submission = any(
        phrase in investigation_text
        for phrase in [
            "entered credentials",
            "submitted credentials",
            "entered password",
            "submitted password",
            "provided credentials",
            "credential harvesting",
            "login details entered",
        ]
    )

    phishing_context = any(
        phrase in investigation_text
        for phrase in [
            "phishing email",
            "phishing link",
            "suspicious login page",
            "fake login page",
            "credential harvesting",
        ]
    )

    post_compromise_signals = [
        phrase
        for phrase in [
            "mfa method changed",
            "authentication method changed",
            "suspicious inbox rule",
            "forwarding rule",
            "impossible travel",
            "sensitive mailbox data was accessed",
        ]
        if phrase in investigation_text
    ]

    if credential_submission and (
        suspicious_url
        or suspicious_domain
        or phishing_context
    ):
        severity = (
            "High"
            if post_compromise_signals
            else "Medium"
        )

        confidence = (
            "High"
            if len(post_compromise_signals) >= 2
            else "Medium"
        )

        attack_patterns.append({
            "name": "Credential Phishing",
            "severity": severity,
            "confidence": confidence,
            "description": (
                "Credential submission was identified in a phishing "
                "context with evidence of possible account compromise."
            ),
        })
    
            # Detect malware delivery patterns
    malware_indicators = [
        ".exe",
        ".dll",
        ".zip",
        ".rar",
        ".iso",
        ".msi",
        "download",
        "payload",
        "installer",
    ]

    malware_url = any(
        any(
            indicator in result.get("url", "").lower()
            for indicator in malware_indicators
        )
        for result in url_scores
    )

    malware_narrative = any(
        phrase in investigation_text
        for phrase in [
            "malware attachment",
            "malicious attachment",
            "malicious file",
            "downloaded malware",
            "executed payload",
            "payload executed",
            "suspicious executable",
            "trojan",
            "ransomware",
            "malicious powershell",
        ]
    )

    execution_signals = [
        phrase
        for phrase in [
            "file executed",
            "payload executed",
            "process created",
            "powershell executed",
            "command prompt launched",
            "endpoint contained",
            "host isolated",
            "edr detection",
        ]
        if phrase in investigation_text
    ]

    malicious_infrastructure = (
        any(
            result.get("risk") == "High"
            for result in ip_scores
        )
        or threat_correlation.get("verdict")
        in ["Suspicious", "Malicious"]
    )

    if (
        malware_url
        or malware_narrative
    ) and (
        malicious_infrastructure
        or execution_signals
    ):
        severity = (
            "Critical"
            if len(execution_signals) >= 2
            else "High"
        )

        confidence = (
            "High"
            if execution_signals
            else "Medium"
        )

        attack_patterns.append({
            "name": "Malware Delivery",
            "severity": severity,
            "confidence": confidence,
            "description": (
                "Malware delivery or execution evidence was identified "
                "with suspicious infrastructure or endpoint activity."
            ),
        })

    return attack_patterns