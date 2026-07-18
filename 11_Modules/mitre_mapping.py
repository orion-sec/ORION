def map_attack_patterns(attack_patterns):
    mitre_results = []

    mitre_mappings = {
        "Credential Phishing": {
            "tactic": "Initial Access",
            "technique_id": "T1566.002",
            "technique_name": "Spearphishing Link",
            "reason": "Credential harvesting activity was identified through a suspicious link."
        },
        "Malware Delivery": {
            "tactic": "Command and Control",
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "reason": "A suspicious file download was identified from risky or malicious infrastructure."
        }
    }

    for pattern in attack_patterns:
        pattern_name = pattern["name"]

        if pattern_name in mitre_mappings:
            mapping = mitre_mappings[pattern_name]

            mitre_results.append({
                "pattern": pattern_name,
                "tactic": mapping["tactic"],
                "technique_id": mapping["technique_id"],
                "technique_name": mapping["technique_name"],
                "confidence": pattern["confidence"],
                "reason": mapping["reason"]
            })
    
    return mitre_results