import re
import sys
import os

sys.path.append(os.path.abspath("../11_Modules"))

from display import display_report
from extract import extract_iocs
from enrich import enrich_ips
from score import score_ip

print("==============================")
print("    ORION IOC EXTRACTOR v1")
print("==============================")

investigation = input("Paste investigation text here: ")
results = extract_iocs(investigation)
results["Enriched IPs"] = enrich_ips(results["IP Addresses"])

results["IP Scores"] = []

for ip in results["Enriched IPs"]:
    results["IP Scores"].append(score_ip(ip))

display_report(results)

print()
print("Investigation received successfully!")
print()

print("You entered:")
print(investigation)