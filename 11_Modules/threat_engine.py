def correlate_threat_intelligence(threat_results):
    available_results = []

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
        
    malicious_results = []

    for result in available_results:
        if result["reputation"] == "Malicious":
            malicious_results.append(result)

    if len(malicious_results) >= 2:
        return {
            "verdict": "Malicious",
            "confidence": "High",
            "sources": len(available_results),
            "reason": "Multiple threat intelligence sources identified malicious activity"
        }
    
    if len(malicious_results) == 1:
        return {
            "verdict": "Suspicious",
            "confidence": "Medium",
            "sources": len(available_results),
            "reason": "One threat intelligence source identified malicious activity"
        }
    
    return {
        "verdict": "Clean",
        "confidence": "Low",
        "sources": len(available_results),
        "reason": "No available threat intelligence source identified malicious activity"
       }
    