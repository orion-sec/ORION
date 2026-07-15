def assess_investigation(ip_scores, url_scores, domain_results, correlation_result):
    evidence_score = 0
    evidence = []
    strong_signals = 0
    suspicious_signals = 0

        # Evaluate IP evidence
    for result in ip_scores:
        risk = result["risk"]

        if risk == "High":
            evidence_score += 40
            strong_signals += 1
            evidence.append(
                f"High-risk IP evidence identified: {result['reason']}"
            )

        elif risk == "Medium":
            evidence_score += 25
            suspicious_signals += 1
            evidence.append(
                f"Suspicious IP evidence identified: {result['reason']}"
            )

        elif risk == "Low":
            evidence_score += 5

            # Evaluate URL evidence
    for result in url_scores:
        risk = result["risk"]

        if risk == "High":
            evidence_score += 30
            strong_signals += 1
            evidence.append(
                "High-risk URL characteristics identified"
            )

        elif risk == "Medium":
            evidence_score += 20
            suspicious_signals += 1
            evidence.append(
                "Suspicious URL characteristics identified"
            )

        elif risk == "Low":
            evidence_score += 10
            suspicious_signals += 1
            evidence.append(
                "Low-confidence suspicious URL characteristics identified"
            )

        # Evaluate domain evidence
    for result in domain_results:
        if result["reputation"] == "Suspicious":
            evidence_score += 20
            suspicious_signals += 1
            evidence.append(
                f"Suspicious domain characteristics identified: {result['domain']}"
            )

        # Evaluate threat intelligence correlation
    correlation_verdict = correlation_result["verdict"]

    if correlation_verdict == "Malicious":
        evidence_score += 50
        strong_signals += 2
        evidence.append(
            "Multiple threat intelligence sources identified malicious activity"
        )

    elif correlation_verdict == "Suspicious":
        evidence_score += 35
        strong_signals += 1
        evidence.append(
            "Threat intelligence identified suspicious activity"
        )

    # Determine overall investigation verdict
    if strong_signals >= 2:
        verdict = "Malicious"
        confidence = "High"

    elif strong_signals == 1:
        verdict = "Suspicious"
        confidence = "High"

    elif suspicious_signals >= 2:
        verdict = "Suspicious"
        confidence = "Medium"

    elif suspicious_signals == 1:
        verdict = "Review Required"
        confidence = "Low"

    else:
        verdict = "No Significant Threat Identified"
        confidence = "Low"
        
    return {
    "verdict": verdict,
    "confidence": confidence,
    "evidence_score": evidence_score,
    "strong_signals": strong_signals,
    "suspicious_signals": suspicious_signals,
    "evidence": evidence
}