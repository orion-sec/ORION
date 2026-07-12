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
    "reports": 0
}

    if not ABUSEIPDB_API_KEY:
        return fallback_result

    url = "https://api.abuseipdb.com/api/v2/check"

    querystring = {
        "ipAddress": ip["ip"],
        "maxAgeInDays": "90"
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

        data = response.json()["data"]

        confidence = data["abuseConfidenceScore"]
        reports = data["totalReports"]

        if confidence >= 80:
            reputation = "Malicious"

        elif confidence >= 25:
            reputation = "Suspicious"

        else:
            reputation = "Clean"

        return {
            "ip": data["ipAddress"],
            "source": "AbuseIPDB",
            "status": "Available",
            "reputation": reputation,
            "confidence": confidence,
            "reports": reports
        }

    except requests.RequestException:
        return fallback_result