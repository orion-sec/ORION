def get_response_playbook(attack_patterns):
    playbooks = []

    for pattern in attack_patterns:
        pattern_name = pattern["name"]

        if pattern_name == "Malware Delivery":
            playbooks.append({
                "pattern": pattern_name,
                "severity": pattern["severity"],
                "confidence": pattern["confidence"],
                "actions": [
                    "Identify the affected endpoint and user.",
                    "Review EDR telemetry for file execution and process activity.",
                    "Isolate the endpoint if malicious execution is confirmed.",
                    "Block the malicious URL and associated domain.",
                    "Block malicious IP addresses where operationally appropriate.",
                    "Block the file hash if available.",
                    "Search the environment for the same URL, domain, IP, or hash.",
                    "Collect relevant forensic evidence before remediation.",
                    "Escalate confirmed compromise to Incident Response."
                ]
            })

        elif pattern_name == "Credential Phishing":
            playbooks.append({
                "pattern": pattern_name,
                "severity": pattern["severity"],
                "confidence": pattern["confidence"],
                "actions": [
                    "Identify all users who received or interacted with the phishing URL.",
                    "Review email security telemetry and message delivery details.",
                    "Remove the phishing email from affected mailboxes where possible.",
                    "Block the malicious URL, domain, and sender.",
                    "Review sign-in logs for suspicious authentication activity.",
                    "Revoke active sessions if credential compromise is suspected.",
                    "Reset passwords for users who submitted credentials.",
                    "Review MFA registration and authentication methods.",
                    "Check for malicious inbox rules, forwarding rules, or OAuth consent.",
                    "Search the environment for related phishing indicators.",
                    "Escalate confirmed account compromise to Incident Response."
                ]
            })

    return playbooks