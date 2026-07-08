import re
import sys
import os

sys.path.append(os.path.abspath("../11_Modules"))

from display import display_report
from extract import extract_iocs

print("==============================")
print("    ORION IOC EXTRACTOR v1")
print("==============================")

investigation = input("Paste investigation text here: ")

results = extract_iocs(investigation)
display_report(results)

print()
print("Investigation received successfully!")
print()

print("You entered:")
print(investigation)