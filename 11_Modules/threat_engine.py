def collect_threat_evidence(result):
    """
    Collects security-relevant evidence from one normalized
    threat-intelligence result.

    Args:
        result: Normalized threat-intelligence dictionary.

    Returns:
        A list of human-readable evidence statements.
    """

    evidence = []

    confidence = result.get("confidence", 0)
    reports = result.get("reports", 0)
    usage_type = result.get("usage_type")
    is_public = result.get("is_public")
    is_whitelisted = result.get("is_whitelisted")
    is_tor = result.get("is_tor")
    last_reported_at = result.get("last_reported_at")

    if confidence >= 80:
        evidence.append(
            f"Abuse confidence score is high at {confidence}%."
        )

    elif confidence >= 25:
        evidence.append(
            f"Abuse confidence score is elevated at {confidence}%."
        )

    if reports > 0:
        evidence.append(
            f"The IP has {reports} abuse report(s)."
        )

    if usage_type:
        evidence.append(
            f"Infrastructure usage type is {usage_type}."
        )

    if is_public is True:
        evidence.append(
            "The IP address is publicly routable."
        )

    if is_whitelisted is True:
        evidence.append(
            "The threat-intelligence provider marks the IP as whitelisted."
        )

    if is_tor is True:
        evidence.append(
            "The IP address is identified as a Tor exit node."
        )

    if last_reported_at:
        evidence.append(
            f"The IP was last reported at {last_reported_at}."
        )

    return evidence

def score_threat_result(result):
    """
    Calculates a threat score for one normalized
    threat-intelligence result.

    Args:
        result: Normalized threat-intelligence dictionary.

    Returns:
        Integer threat score.
    """

    score = 0

    reputation = result.get("reputation", "Unknown")
    confidence = result.get("confidence", 0)
    reports = result.get("reports", 0)
    usage_type = result.get("usage_type") or ""
    isp = result.get("isp") or ""
    is_public = result.get("is_public")
    is_whitelisted = result.get("is_whitelisted")
    is_tor = result.get("is_tor")

    if reputation == "Malicious":
        score += 100

    elif reputation == "Suspicious":
        score += 50

    if confidence >= 90:
        score += 60

    elif confidence >= 70:
        score += 40

    elif confidence >= 40:
        score += 20

    if reports > 100:
        score += 25

    elif reports > 20:
        score += 10

    if is_tor is True:
        score += 30

    if is_public is True:
        score += 5

    infrastructure_text = f"{usage_type} {isp}".lower()

    if any(
        keyword in infrastructure_text
        for keyword in [
            "data center",
            "hosting",
            "cloud",
            "transit",
            "aws",
            "azure"
        ]
    ):
        score += 10

    if is_whitelisted is True:
        score -= 50

    return max(score, 0)

def correlate_threat_intelligence(threat_results):
    available_results = []
    evidence = []

    for result in threat_results:
        if result["status"] == "Available":
            available_results.append(result)

    if not available_results:
        return {
            "verdict": "Unknown",
            "confidence": "None",
            "sources": 0,
            "reason": "No threat intelligence sources available"
        }
        
    total_score = 0

    for result in available_results:

        evidence.extend(
            collect_threat_evidence(result)
        )

        total_score += score_threat_result(result)


    if total_score >= 100:
        return {
            "verdict": "Malicious",
            "confidence": "High",
            "score": total_score,
            "sources": len(available_results),
            "reason": "Threat intelligence evidence produced a high-risk score.",
            "evidence": evidence
        }

    if total_score >= 25:
        return {
            "verdict": "Suspicious",
            "confidence": "Medium",
            "score": total_score,
            "sources": len(available_results),
            "reason": "Threat intelligence evidence produced an elevated-risk score.",
            "evidence": evidence
        }

    return {
        "verdict": "Clean",
        "confidence": "Low",
        "score": total_score,
        "sources": len(available_results),
        "reason": "Threat intelligence evidence did not reach the suspicious threshold.",
        "evidence": evidence
    }
        