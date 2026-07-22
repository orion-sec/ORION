import re
import sys
import os

sys.path.append(os.path.abspath("../11_Modules"))

from display import display_report
from extract import extract_iocs
from enrich import enrich_ips
from url_enrich import enrich_urls
from url_score import score_url
from score import score_ip
from decision import (
    recommend_action,
    determine_priority,
    recommend_investigation_action,
    determine_investigation_priority
)
from pipeline import OrionPipeline, initialise_results_stage
from threat_intel import lookup_ip_reputation
from threat_engine import correlate_threat_intelligence
from domain_intel import inspect_domains
from mitre_mapping import map_attack_patterns
from investigation_engine import assess_investigation
from attack_patterns import detect_attack_patterns
from response_playbooks import get_response_playbook
from context_risk import assess_contextual_risk
from identity_entities import extract_identity_entities
from identity_enrichment import enrich_identity
from business_impact import assess_business_impact
from operational_decision import determine_operational_decision

print("==============================")
print("    ORION IOC EXTRACTOR v1")
print("==============================")

investigation = input("Paste investigation text here: ")
results = extract_iocs(investigation)
results["Enriched Identity"] = enrich_identity(
    results["Identity Entities"]
)

results["Business Impact"] = assess_business_impact(
    results["Enriched Identity"]
)

results["Enriched IPs"] = enrich_ips(results["IP Addresses"])
results["Enriched URLs"] = enrich_urls(results["URLs"])
results["Domain Intelligence"] = inspect_domains(results["Domains"])
results["URL Scores"] = []

for url in results["Enriched URLs"]:
    url_score_result = score_url(url)
    results["URL Scores"].append(url_score_result)

results["IP Scores"] = []
results["Recommendations"] = []
results["Priorities"] = []
results["Threat Intelligence"] = []
results["Threat Correlation"] = []
results["Attack Patterns"] = []

for ip in results["Enriched IPs"]:
    threat_result = lookup_ip_reputation(ip)
    threat_results = [threat_result]
    correlation_result = correlate_threat_intelligence(threat_results)
    risk_result = score_ip(ip, threat_result, correlation_result)
    priority_result = determine_priority(risk_result["score"])
    results["Threat Correlation"].append(correlation_result)

    results["Threat Intelligence"].append(threat_result)
    results["IP Scores"].append(risk_result)
    results["Recommendations"].append(
        recommend_action(risk_result)
    )
    results["Priorities"].append(priority_result)

if results["Threat Correlation"]:
    correlation_result = results["Threat Correlation"][0]
else:
    correlation_result = {
        "verdict": "Unknown",
        "confidence": "Low",
        "sources": 0,
        "reason": "No IP-based threat intelligence correlation available."
    }

results["Investigation Assessment"] = assess_investigation(
    results["IP Scores"],
    results["URL Scores"],
    results["Domain Intelligence"],
    correlation_result
)

results["Attack Patterns"] = detect_attack_patterns(
    investigation,
    results["URL Scores"],
    results["Domain Intelligence"],
    results["IP Scores"],
    correlation_result
)

results["MITRE ATT&CK"] = map_attack_patterns(
    results["Attack Patterns"]
)

results["Response Playbooks"] = get_response_playbook(
    results["Attack Patterns"]
)

results["Contextual Risk"] = assess_contextual_risk(
    investigation
)

results["Operational Decision"] = determine_operational_decision(
    results["Contextual Risk"],
    results["Business Impact"]
)

results["Investigation Recommendations"] = recommend_investigation_action(
    results["Investigation Assessment"]
)

results["Investigation Priority"] = determine_investigation_priority(
    results["Investigation Assessment"]
)

display_report(results)

print()
print("Investigation received successfully!")
print()

print("You entered:")
print(investigation)