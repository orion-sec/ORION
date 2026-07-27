"""
===========================================================================
ORION Engineering Utility
===========================================================================

File:
    rename_kb_files.py

Purpose:
    Renames ORION Knowledge Base documents to the official
    KB-XXX naming convention.

Author:
    Onwenmadu Samuel Chukwuka

Project:
    ORION - AI Security Engineering Platform

Academy:
    The ORION Engineering Academy

===========================================================================
"""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

KNOWLEDGE_BASE = PROJECT_ROOT / "02_Knowledge_Base"

print("=" * 70)
print("ORION Engineering Utility")
print("=" * 70)

print(f"Project Root   : {PROJECT_ROOT}")
print(f"Knowledge Base : {KNOWLEDGE_BASE}")

FILE_MAPPING = {
    "Git_Basics.md": "KB-001_Git_Basics.md",
    "CLI_Commands.md": "KB-002_CLI_Commands.md",
    "Python_Concepts.md": "KB-003_Python_Concepts.md",
    "Python_Modules.md": "KB-004_Python_Modules.md",
    "IOC_Enrichment.md": "KB-005_IOC_Enrichment.md",
    "URL_and_Domain_Intelligence.md": "KB-006_URL_and_Domain_Intelligence.md",
    "Threat_Intelligence_API_and_Risk_Scoring.md": "KB-007_Threat_Intelligence_API_and_Risk_Scoring.md",
    "Threat_Intelligence_Correlation.md": "KB-008_Threat_Intelligence_Correlation.md",
    "Risk_Scoring_Engine.md": "KB-009_Risk_Scoring_Engine.md",
    "SOC_Decision_and_Priority_Engine.md": "KB-010_SOC_Decision_and_Priority_Engine.md",
    "Behavioural Evidence Analysis & Response Playbook Engine.md": "KB-011_Behavioural_Evidence_Analysis_and_Response_Playbook_Engine.md",
    "Malware_Delivery_Detection_and_Investigation_Reasoning.md": "KB-012_Malware_Delivery_Detection_and_Investigation_Reasoning.md",
    "MITRE ATT&CK Mapping Engine.md": "KB-013_MITRE_ATTACK_Mapping_Engine.md",
    "Identity_Intelligence_and_IOC_Separation.md": "KB-014_Identity_Intelligence_and_IOC_Separation.md",
    "Investigation_Level_Reasoning_and_Decision_Architecture.md": "KB-015_Investigation_Level_Reasoning_and_Decision_Architecture.md",
    "Pipeline_Stage_Architecture.md": "KB-016_Pipeline_Stage_Architecture.md",
    "Enterprise_Pipeline_Observability.md": "KB-017_Enterprise_Pipeline_Observability.md",
    "Pipeline_Architecture_and_System_Evolution.md": "KB-018_Pipeline_Architecture_and_System_Evolution.md",
    "Evidence_Driven_Investigation_Pipelines.md": "KB-019_Evidence_Driven_Investigation_Pipelines.md",
    "Operational_Decision_Architecture.md": "KB-020_Operational_Decision_Architecture.md",
    "Response_Playbook_Architecture_and_ORION_Ecosystem_Vision.md": "KB-021_Response_Playbook_Architecture_and_ORION_Ecosystem_Vision.md",
}

def rename_one_file(old_name: str, new_name: str) -> None:
    """
    Renames a single Knowledge Base document.

    Args:
        old_name: Current filename.
        new_name: New filename using the KB-XXX convention.
    """

    old_path = KNOWLEDGE_BASE / old_name
    new_path = KNOWLEDGE_BASE / new_name

    if not old_path.exists():
        print(f"[WARNING] File not found: {old_name}")
        return

    old_path.rename(new_path)
    print(f"[SUCCESS] {old_name} -> {new_name}")


for old_name, new_name in FILE_MAPPING.items():
    rename_one_file(old_name, new_name)