import re
import sys
import os

sys.path.append(os.path.abspath("../11_Modules"))

from display import display_report
from extract import extract_iocs
from enrich import enrich_ips
from score import score_ip
from decision import recommend_action, determine_priority

print("==============================")
print("    ORION IOC EXTRACTOR v1")
print("==============================")

investigation = input("Paste investigation text here: ")
results = extract_iocs(investigation)
results["Enriched IPs"] = enrich_ips(results["IP Addresses"])

results["IP Scores"] = []
results["Recommendations"] = []
results["Priorities"] = []

for ip in results["Enriched IPs"]:
    risk_result = score_ip(ip)
    priority_result = determine_priority(risk_result["score"])

    results["IP Scores"].append(risk_result)
    results["Recommendations"].append(
        recommend_action(risk_result)
    )
    results["Priorities"].append(priority_result)

display_report(results)

print()
print("Investigation received successfully!")
print()

print("You entered:")
print(investigation)