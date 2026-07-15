def score_url(url_data):
    score = 0
    reasons = []

    if url_data["scheme"] == "http":
        score += 10
        reasons.append("URL uses unencrypted HTTP")

    if url_data["port"] not in (None, 80, 443):
        score += 15
        reasons.append("URL uses a non-standard port")

    suspicious_keywords = [
        "login",
        "signin",
        "verify",
        "account",
        "reset",
        "password",
        "secure",
        "update"
    ]

    url_text = url_data["url"].lower()

    for keyword in suspicious_keywords:
        if keyword in url_text:
            score += 5
            reasons.append(f"Suspicious URL keyword detected: {keyword}")

    if score >= 40:
        risk = "High"
    elif score >= 20:
        risk = "Medium"
    elif score > 0:
        risk = "Low"
    else:
        risk = "Informational"

    return {
        "url": url_data["url"],
        "risk": risk,
        "score": score,
        "reasons": reasons
    }