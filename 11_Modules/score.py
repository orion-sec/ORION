def score_ip(ip):

    if ip["is_private"]:
        return {
            "risk": "Low",
            "score": 10,
            "reason": "Private IP Address"
        }

    if ip["is_loopback"]:
        return {
            "risk": "Informational",
            "score": 0,
            "reason": "Loopback Address"
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
            "reason": "Public Global IP"
        }

    return {
        "risk": "Unknown",
        "score": 25,
        "reason": "Unable to classify"
    }