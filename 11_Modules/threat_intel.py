import os

import requests
from dotenv import load_dotenv


load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")


def lookup_ip_reputation(ip):

    fallback_result = {
    "ip": ip["ip"],
    "source": "AbuseIPDB",
    "status": "Unavailable",
    "reputation": "Unknown",
    "confidence": 0,
    "reports": 0,
    "country_code": None,
    "country_name": None,
    "isp": None,
    "usage_type": None,
    "domain": None,
    "hostnames": [],
    "last_reported_at": None,
    "is_public": None,
    "ip_version": None,
    "is_whitelisted": None,
    "is_tor": None
}

    if not ABUSEIPDB_API_KEY:
        return fallback_result

    url = "https://api.abuseipdb.com/api/v2/check"

    querystring = {
    "ipAddress": ip["ip"],
    "maxAgeInDays": "90",
    "verbose": ""
}

    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            params=querystring,
            timeout=10
        )

        response.raise_for_status()

        payload = response.json()
        data = payload.get("data", {})

        confidence = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)

        if confidence >= 80:
            reputation = "Malicious"

        elif confidence >= 25:
            reputation = "Suspicious"

        else:
            reputation = "Clean"

        return {
            "ip": data.get("ipAddress"),
            "source": "AbuseIPDB",
            "status": "Available",
            "reputation": reputation,
            "confidence": confidence,
            "reports": reports,
            "country_code": data.get("countryCode"),
            "country_name": data.get("countryName"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "domain": data.get("domain"),
            "hostnames": data.get("hostnames", []),
            "last_reported_at": data.get("lastReportedAt"),
            "is_public": data.get("isPublic"),
            "ip_version": data.get("ipVersion"),
            "is_whitelisted": data.get("isWhitelisted"),
            "is_tor": data.get("isTor")
        }

    except requests.RequestException:
        return fallback_result