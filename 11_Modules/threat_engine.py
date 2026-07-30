from threat_sources import get_threat_source
from evidence import create_evidence
from evidence_reasoning import reason_over_evidence

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

    source = result.get("source")
    source_metadata = get_threat_source(source)

    source_name = source_metadata.get("display_name", source or "Unknown")
    source_confidence = source_metadata.get("confidence", "Unknown")
    source_category = source_metadata.get("category", "Unknown")

    evidence.append(
    create_evidence(
        "Source",
        (
            f"Threat intelligence source is {source_name}, "
            f"classified as {source_category} with "
            f"{source_confidence} source confidence."
        )
    )
)

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
        create_evidence(
            "Infrastructure",
            f"Infrastructure usage type is {usage_type}."
        )
    )

    if is_public is True:
        evidence.append(
        create_evidence(
            "Network",
            "The IP address is publicly routable."
        )
    )

    if is_whitelisted is True:
        evidence.append(
        create_evidence(
            "Reputation",
            "The threat-intelligence provider marks the IP as whitelisted."
        )
    )

    if is_tor is True:
        evidence.append(
        create_evidence(
            "Network",
            "The IP address is identified as a Tor exit node."
        )
    )

    if last_reported_at:
        evidence.append(
        create_evidence(
            "Historical",
            f"The IP was last reported at {last_reported_at}."
        )
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

    source = result.get("source")
    source_metadata = get_threat_source(source)
    source_weight = source_metadata.get("weight", 0)
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
        score += source_weight

    elif reputation == "Suspicious":
        score += 50
        score += source_weight

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

    findings = reason_over_evidence(evidence)


    if total_score >= 100:
        return {
            "verdict": "Malicious",
            "confidence": "High",
            "score": total_score,
            "sources": len(available_results),
            "reason": "Threat intelligence evidence produced a high-risk score.",
            "evidence": evidence,
            "findings": findings
        }

    if total_score >= 25:
        return {
            "verdict": "Suspicious",
            "confidence": "Medium",
            "score": total_score,
            "sources": len(available_results),
            "reason": "Threat intelligence evidence produced an elevated-risk score.",
            "evidence": evidence,
            "findings": findings
        }

    return {
        "verdict": "Clean",
        "confidence": "Low",
        "score": total_score,
        "sources": len(available_results),
        "reason": "Threat intelligence evidence did not reach the suspicious threshold.",
        "evidence": evidence,
        "findings": findings
    }
        