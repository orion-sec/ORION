"""
import time
ORION Processing Pipeline

Responsible for executing investigation stages
in the correct order.
"""


def initialise_results_stage(investigation, results):
    """
    Initialise shared investigation state for the pipeline.
    """

    results["Investigation"] = investigation

    return results

import time

from extract import extract_iocs
from identity_entities import extract_identity_entities
from identity_enrichment import enrich_identity
from business_impact import assess_business_impact
from enrich import enrich_ips
from threat_intel import lookup_ip_reputation
from threat_engine import correlate_threat_intelligence
from context_risk import assess_contextual_risk
from operational_decision import determine_operational_decision
from attack_patterns import detect_attack_patterns
from response_playbooks import get_response_playbook

STAGE_NAMES = {
    "initialise_results_stage": "Initializing Investigation",
    "ioc_extraction_stage": "Extracting Indicators of Compromise",
    "identity_extraction_stage": "Extracting Identity Entities",
    "identity_enrichment_stage": "Enriching Identity Context",
    "business_impact_stage": "Assessing Business Impact",
    "ip_enrichment_stage": "Enriching IP Addresses",
    "threat_intelligence_stage": "Querying Threat Intelligence",
    "threat_correlation_stage": "Correlating Threat Intelligence",
    "operational_decision_stage": "Determining Operational Response",
    "attack_pattern_stage": "Detecting Attack Patterns",
    "response_playbook_stage": "Generating Response Playbooks",
}


def ioc_extraction_stage(investigation, results):
    """
    Extract IOCs from the investigation narrative.
    """

    ioc_results = extract_iocs(investigation)

    results.update(ioc_results)

    return results

def identity_extraction_stage(investigation, results):
    """
    Extract identity entities from the investigation narrative.
    """

    results["Identity Entities"] = extract_identity_entities(
        investigation
    )

    return results

def identity_enrichment_stage(investigation, results):
    """
    Enrich extracted identity entities with organisational context.
    """

    results["Enriched Identity"] = enrich_identity(
        results["Identity Entities"]
    )

    return results

def business_impact_stage(investigation, results):
    """
    Assess organisational impact using enriched identity context.
    """

    results["Business Impact"] = assess_business_impact(
        results["Enriched Identity"]
    )

    return results

def ip_enrichment_stage(investigation, results):
    """
    Enrich extracted IP addresses with structured context.
    """

    results["Enriched IPs"] = enrich_ips(
        results["IP Addresses"]
    )

    return results

def threat_intelligence_stage(investigation, results):
    """
    Query threat intelligence for extracted IP addresses.
    """

    results["Threat Intelligence"] = []

    for ip in results["Enriched IPs"]:
        threat_result = lookup_ip_reputation(ip)
        results["Threat Intelligence"].append(threat_result)

    return results

def threat_correlation_stage(investigation, results):
    """
    Correlate collected threat intelligence results.
    """

    results["Threat Correlation"] = []

    if results["Threat Intelligence"]:
        correlation_result = correlate_threat_intelligence(
            results["Threat Intelligence"]
        )

        results["Threat Correlation"].append(
            correlation_result
        )

    return results

def contextual_risk_stage(investigation, results):
    """
    Calculate the overall contextual investigation risk.
    """

    results["Contextual Risk"] = assess_contextual_risk(
        investigation
    )

    return results

def operational_decision_stage(investigation, results):
    """
    Determine the operational response using contextual risk
    and business impact.
    """

    results["Operational Decision"] = determine_operational_decision(
        results["Contextual Risk"],
        results["Business Impact"]
    )

    return results

def attack_pattern_stage(investigation, results):
    """
    Detect recognised attack patterns from investigation evidence.
    """

    correlation_result = (
        results["Threat Correlation"][0]
        if results["Threat Correlation"]
        else {
            "verdict": "Unknown",
            "confidence": "Low",
            "sources": 0,
            "reason": "No threat correlation available."
        }
    )

    results["Attack Patterns"] = detect_attack_patterns(
        investigation,
        results.get("URL Scores", []),
        results.get("Domain Intelligence", []),
        results.get("IP Scores", []),
        correlation_result
    )

    return results

def response_playbook_stage(investigation, results):
    """
    Generate response playbooks for detected attack patterns.
    """

    results["Response Playbooks"] = get_response_playbook(
        results["Attack Patterns"]
    )

    return results

class OrionPipeline:

    def __init__(self):
        self.stages = []

    def add_stage(self, stage):
        self.stages.append(stage)

    def load_default_pipeline(self):
        """
        Load the default ORION investigation workflow.
        """

        self.add_stage(initialise_results_stage)
        self.add_stage(ioc_extraction_stage)
        self.add_stage(identity_extraction_stage)
        self.add_stage(identity_enrichment_stage)
        self.add_stage(business_impact_stage)
        self.add_stage(ip_enrichment_stage)
        self.add_stage(threat_intelligence_stage)
        self.add_stage(threat_correlation_stage)
        self.add_stage(contextual_risk_stage)
        self.add_stage(operational_decision_stage)
        self.add_stage(attack_pattern_stage)
        self.add_stage(response_playbook_stage)

    def run(self, investigation, results=None):

        if results is None:
            results = {}

        successful = 0
        failed = 0
        failed_stage = None

        total_stages = len(self.stages)

        for index, stage in enumerate(self.stages, start=1):

            stage_name = STAGE_NAMES.get(
                stage.__name__,
                stage.__name__
            )

            start_time = time.perf_counter()

            print(
                f"[PIPELINE] [{index}/{total_stages}] "
                f"Starting: {stage_name}"
            )

            try:
                results = stage(investigation, results)

                duration_ms = (
                    time.perf_counter() - start_time
                ) * 1000

                print(
                    f"[PIPELINE] [{index}/{total_stages}] "
                    f"Completed: {stage_name} "
                    f"({duration_ms:.2f} ms)"
                )

                successful += 1

            except Exception as error:

                duration_ms = (
                    time.perf_counter() - start_time
                ) * 1000

                print(
                    f"[PIPELINE] [{index}/{total_stages}] "
                    f"Failed: {stage_name} "
                    f"({duration_ms:.2f} ms)"
                )

                print(f"[PIPELINE] Error: {error}")

                failed += 1
                failed_stage = stage_name

                raise

        print()
        print("===================================")
        print("PIPELINE EXECUTION SUMMARY")
        print("===================================")

        print(f"Stages Executed : {len(self.stages)}")
        print(f"Successful      : {successful}")
        print(f"Failed          : {failed}")

        if failed_stage:
            print(f"Failed Stage    : {failed_stage}")
            print("Execution Status: FAILED")
        else:
            print("Execution Status: SUCCESS")

        print("===================================")

        return results  
