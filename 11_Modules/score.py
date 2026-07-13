def score_ip(ip, threat_result, correlation_result):

    if ip["is_loopback"]:
        return {
            "risk": "Informational",
            "score": 0,
            "reason": "Loopback Address"
        }

    if ip["is_private"]:
        return {
            "risk": "Low",
            "score": 10,
            "reason": "Private IP Address"
        }

    reputation = threat_result["reputation"]
    confidence = threat_result["confidence"]
    correlation_verdict = correlation_result["verdict"]

    if correlation_verdict == "Malicious":
        return {
            "risk": "High",
            "score": 95,
            "reason": "Multiple threat intelligence sources correlated malicious IOC"
        }

    if correlation_verdict == "Suspicious":
        return {
            "risk": "High",
            "score": 80,
            "reason": "Threat intelligence correlation identified suspicious IOC"
        }

    if reputation == "Malicious":
        return {
            "risk": "High",
            "score": 90,
            "reason": "Threat Intelligence identified malicious IOC"
        }

    if reputation == "Suspicious":
        return {
            "risk": "High",
            "score": 75,
            "reason": "Threat Intelligence identified suspicious IOC"
        }

    if reputation == "Clean" and confidence == 0:
        return {
            "risk": "Low",
            "score": 20,
            "reason": "Public IP with no current AbuseIPDB confidence"
        }

    if ip["is_reserved"]:
        return {
            "risk": "Low",
            "score": 15,
            "reason": "Reserved Address"
        }

    if ip["is_global"]:
        return {
            "risk": "Medium",
            "score": 50,
            "reason": "Public Global IP requires further investigation"
        }

    return {
        "risk": "Unknown",
        "score": 25,
        "reason": "Unable to classify"
    }