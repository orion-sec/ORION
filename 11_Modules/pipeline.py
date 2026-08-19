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

from attack_patterns import detect_attack_patterns
from business_impact import assess_business_impact
from cognitive.cognitive_pipeline import execute as execute_cognitive_pipeline
from connectors.virustotal_client import VirusTotalError
from context_risk import assess_contextual_risk
from correlation.blast_radius import assess_blast_radius
from correlation.entity_correlator import correlate_entities
from correlation.investigation_expander import expand_investigation
from enrich import enrich_ips
from evidence_reasoning import reason_over_evidence
from extract import extract_iocs
from factories.case_factory import create_investigation_case
from factories.sentinel_incident_factory import create_sentinel_incident
from identity_enrichment import enrich_identity
from identity_entities import extract_identity_entities
from models.indicator_profile import IndicatorProfile
from models.investigation import Investigation
from models.investigation_case import (
    CaseSeverity,
    CaseStatus,
)
from operational_decision import determine_operational_decision
from response_playbooks import get_response_playbook
from threat_engine import correlate_threat_intelligence
from threat_intel import lookup_ip_reputation


def normalise_threat_evidence(value) -> list[dict]:
    """
    Converts any legacy threat-intelligence output into a flat
    list of structured evidence dictionaries.
    """

    normalised: list[dict] = []

    def add_item(item, source: str = "ORION Threat Intelligence") -> None:
        if item is None:
            return

        if isinstance(item, str):
            cleaned = item.strip()

            if cleaned:
                normalised.append(
                    {
                        "category": "Threat Intelligence",
                        "finding": cleaned,
                        "evidence": cleaned,
                        "source": source,
                    }
                )

            return

        if isinstance(item, dict):
            evidence_keys = {
                "category",
                "finding",
                "evidence",
                "reason",
                "description",
            }

            # This dictionary is one evidence record.
            if evidence_keys.intersection(item.keys()):
                finding = (
                    item.get("finding")
                    or item.get("evidence")
                    or item.get("reason")
                    or item.get("description")
                    or "Threat-intelligence evidence was identified."
                )

                normalised.append(
                    {
                        **item,
                        "category": str(item.get("category") or "Threat Intelligence"),
                        "finding": str(finding),
                        "evidence": str(item.get("evidence") or finding),
                        "source": str(item.get("source") or source),
                    }
                )

                return

            # This is a container dictionary.
            for key, child_value in item.items():
                add_item(
                    child_value,
                    source=f"{source}: {key}",
                )

            return

        if isinstance(item, (list, tuple, set)):
            for child_value in item:
                add_item(child_value, source=source)

            return

        cleaned = str(item).strip()

        if cleaned:
            normalised.append(
                {
                    "category": "Threat Intelligence",
                    "finding": cleaned,
                    "evidence": cleaned,
                    "source": source,
                }
            )

    add_item(value)

    return normalised


def build_investigation_text(investigation) -> str:
    """
    Converts structured alert data into searchable investigation text.

    Older ORION extraction modules expect plain text, while modern
    connectors provide structured dictionaries.
    """

    if investigation is None:
        return ""

    if isinstance(investigation, str):
        return investigation

    if isinstance(investigation, dict):
        preferred_fields = (
            "title",
            "description",
            "summary",
            "details",
            "alert_type",
            "category",
            "user",
            "affected_user",
            "host",
            "device",
            "affected_host",
            "ip_address",
            "ip",
            "url",
            "domain",
            "file_hash",
            "process_chain",
        )

        text_parts: list[str] = []

        for field_name in preferred_fields:
            value = investigation.get(field_name)

            if value is None:
                continue

            if isinstance(value, (list, tuple, set)):
                text_parts.extend(
                    str(item).strip() for item in value if str(item).strip()
                )

            elif isinstance(value, dict):
                text_parts.extend(
                    f"{key}: {item}" for key, item in value.items() if item is not None
                )

            else:
                cleaned_value = str(value).strip()

                if cleaned_value:
                    text_parts.append(cleaned_value)

        # Preserve any useful fields not included above.
        for key, value in investigation.items():
            if key in preferred_fields or value is None:
                continue

            if isinstance(value, (str, int, float, bool)):
                text_parts.append(f"{key}: {value}")

        return "\n".join(dict.fromkeys(text_parts))

    return str(investigation)


STAGE_NAMES = {
    "initialise_results_stage": "Initializing Investigation",
    "ioc_extraction_stage": "Extracting Indicators of Compromise",
    "identity_extraction_stage": "Extracting Identity Entities",
    "identity_enrichment_stage": "Enriching Identity Context",
    "signin_evidence_stage": "Collecting Entra Sign-In Evidence",
    "business_impact_stage": "Assessing Business Impact",
    "ip_enrichment_stage": "Enriching IP Addresses",
    "threat_intelligence_stage": "Querying Threat Intelligence",
    "threat_correlation_stage": "Correlating Threat Intelligence",
    "operational_decision_stage": "Determining Operational Response",
    "attack_pattern_stage": "Detecting Attack Patterns",
    "response_playbook_stage": "Generating Response Playbooks",
    "case_creation_stage": "Creating Investigation Case",
    "evidence_reasoning_stage": "Reasoning Over Security Evidence",
    "cognitive_reasoning_stage": "Executing Cognitive Investigation",
    "entity_correlation_stage": "Correlating Investigation Entities",
    "environment_search_stage": "Searching Related Environment Activity",
    "investigation_expansion_stage": "Expanding Investigation Scope",
    "blast_radius_stage": "Assessing Investigation Blast Radius",
    "indicator_intelligence_stage": "Enriching Indicators with Threat Intelligence",

}


def security_incident_stage(investigation, results):
    """
    Normalise external security incidents into ORION's
    provider-neutral SecurityIncident model.
    """

    raw_incidents = results.get("Raw Security Incidents", [])

    if not raw_incidents:
        results["Security Incidents"] = []
        return results

    security_incidents = []

    for raw_incident in raw_incidents:
        source_provider = str(
            raw_incident.get("source_provider", "")
        ).strip().lower()

        raw_payload = raw_incident.get("raw")

        if not isinstance(raw_payload, dict):
            continue

        if source_provider == "microsoft sentinel":
            entities = raw_incident.get("entities", [])
            alerts = raw_incident.get("alerts", [])

            if not isinstance(entities, list):
                entities = []

            if not isinstance(alerts, list):
                alerts = []

            security_incidents.append(
                create_sentinel_incident(
                    raw_incident=raw_payload,
                    entities=entities,
                    alerts=alerts,
                )
            )

    results["Security Incidents"] = security_incidents

    investigation_aggregate = results.get(
        "Investigation Aggregate"
    )

    if isinstance(investigation_aggregate, Investigation):
        investigation_aggregate.security_incidents = list(
            security_incidents
        )

    return results

def ioc_extraction_stage(investigation, results):
    """
    Extract IOCs from structured or unstructured investigation data.
    """

    investigation_text = build_investigation_text(investigation)

    results["Investigation Text"] = investigation_text

    ioc_results = extract_iocs(investigation_text)

    results.update(ioc_results)

    investigation_aggregate = results.get("Investigation Aggregate")

    if isinstance(investigation_aggregate, Investigation):
        investigation_aggregate.indicators = dict(ioc_results)

    return results


def identity_extraction_stage(investigation, results):
    """
    Extract identity entities from structured or unstructured
    investigation data.
    """

    investigation_text = results.get("Investigation Text")

    if not investigation_text:
        investigation_text = build_investigation_text(investigation)
        results["Investigation Text"] = investigation_text

    identity_results = extract_identity_entities(investigation_text)

    results["Identity Entities"] = identity_results

    investigation_aggregate = results.get("Investigation Aggregate")

    if isinstance(investigation_aggregate, Investigation):
        investigation_aggregate.identity_entities = dict(identity_results or {})

    return results


def identity_enrichment_stage(investigation, results):
    """
    Enrich extracted identity entities with organisational context.
    """

    enriched_identity = enrich_identity(results.get("Identity Entities", {}))

    results["Enriched Identity"] = enriched_identity

    investigation_aggregate = results.get("Investigation Aggregate")

    if isinstance(investigation_aggregate, Investigation):
        investigation_aggregate.identity_enrichment = dict(enriched_identity or {})

    return results


def signin_evidence_stage(investigation, results):
    """
    Preserve investigation-scoped Microsoft Entra sign-in evidence.

    This stage must not perform an unfiltered tenant-wide sign-in
    collection because independent ORION investigations must remain
    isolated from unrelated activity.

    Additional sign-in telemetry is discovered later through
    entity-driven environment search.
    """

    evidence = results.get(
        "Sign-In Evidence",
        [],
    )

    if not isinstance(evidence, list):
        evidence = []

    results["Sign-In Evidence"] = evidence

    investigation_aggregate = results.get(
        "Investigation Aggregate"
    )

    if isinstance(
        investigation_aggregate,
        Investigation,
    ):
        investigation_aggregate.signin_evidence = evidence

    return results


def entity_correlation_stage(investigation, results):
    """
    Extract correlation pivots from evidence belonging to the
    current independent ORION investigation.

    This stage does not merge incidents. It prepares entity keys
    that can later be used for environment-wide searches.
    """

    evidence_records = []

    security_incidents = results.get(
        "Security Incidents",
        [],
    )

    if isinstance(security_incidents, list):
        evidence_records.extend(security_incidents)

    sign_in_evidence = results.get(
        "Sign-In Evidence",
        [],
    )

    if isinstance(sign_in_evidence, list):
        evidence_records.extend(sign_in_evidence)

    existing_evidence = results.get(
        "Evidence",
        [],
    )

    if isinstance(existing_evidence, list):
        evidence_records.extend(existing_evidence)

    correlation = correlate_entities(
        evidence_records
    )

    results["Entity Correlation"] = correlation

    investigation_aggregate = results.get(
        "Investigation Aggregate"
    )

    if isinstance(investigation_aggregate, Investigation):
        investigation_aggregate.metadata[
            "entity_correlation"
        ] = correlation

    return results


def environment_search_stage(investigation, results):
    """
    Search the wider environment using correlation pivots
    extracted from the current independent investigation.

    Environment-search results remain separate from the original
    alert evidence so ORION can preserve evidence provenance.
    """

    provider = results.get(
        "Environment Search Provider"
    )

    if provider is None:
        results["Environment Search"] = {
            "search_count": 0,
            "results": [],
        }
        results["Environment Evidence"] = []
        return results

    correlation = results.get(
        "Entity Correlation",
        {},
    )

    if not isinstance(correlation, dict):
        correlation = {}

    correlation_keys = correlation.get(
        "correlation_keys",
        [],
    )

    if not isinstance(correlation_keys, list):
        correlation_keys = []

    if not correlation_keys:
        results["Environment Search"] = {
            "search_count": 0,
            "results": [],
        }
        results["Environment Evidence"] = []
        return results

    search_results = provider.search(
        correlation_keys=correlation_keys,
        timespan="P7D",
    )

    results["Environment Search"] = search_results

    environment_evidence = []

    if isinstance(search_results, dict):
        related_results = search_results.get(
            "results",
            [],
        )

        if isinstance(related_results, list):
            for related_result in related_results:
                if not isinstance(
                    related_result,
                    dict,
                ):
                    continue

                matches = related_result.get(
                    "matches",
                    [],
                )

                if isinstance(matches, list):
                    environment_evidence.extend(
                        matches
                    )

    results["Environment Evidence"] = (
        environment_evidence
    )

    investigation_aggregate = results.get(
        "Investigation Aggregate"
    )

    if isinstance(
        investigation_aggregate,
        Investigation,
    ):
        investigation_aggregate.metadata[
            "environment_search"
        ] = search_results

    return results


def investigation_expansion_stage(investigation, results):
    """
    Expand the current investigation using related evidence
    discovered by ORION's environment-search layer.

    Expansion remains scoped to the current investigation and
    does not merge unrelated security incidents.
    """

    environment_evidence = results.get(
        "Environment Evidence",
        [],
    )

    if not isinstance(environment_evidence, list):
        environment_evidence = []

    expansion = expand_investigation(
        environment_evidence
    )

    results["Investigation Expansion"] = expansion

    return results


def blast_radius_stage(investigation, results):
    """
    Assess the investigation blast radius from the
    expanded environment evidence.
    """

    expansion = results.get(
        "Investigation Expansion",
        {},
    )

    if not isinstance(expansion, dict):
        expansion = {}

    blast_radius = assess_blast_radius(
        expansion
    )

    results["Blast Radius"] = blast_radius

    return results


def indicator_intelligence_stage(investigation, results):
    """
    Enrich investigation correlation pivots with external
    indicator intelligence.

    VirusTotal is injected explicitly through pipeline results
    so ordinary regression tests never make unintended live
    external API calls.
    """

    provider = results.get(
        "VirusTotal Provider"
    )

    if provider is None:
        results["Indicator Intelligence"] = []
        return results

    correlation = results.get(
        "Entity Correlation",
        {},
    )

    if not isinstance(correlation, dict):
        results["Indicator Intelligence"] = []
        return results

    correlation_keys = correlation.get(
        "correlation_keys",
        [],
    )

    if not isinstance(correlation_keys, list):
        results["Indicator Intelligence"] = []
        return results

    profiles = []

    for correlation_key in correlation_keys:
        if not isinstance(
            correlation_key,
            dict,
        ):
            continue

        indicator_type = str(
            correlation_key.get(
                "type",
                "",
            )
        ).strip()

        value = str(
            correlation_key.get(
                "value",
                "",
            )
        ).strip()

        if not value:
            continue

        try:
            if indicator_type == "file_hash":
                profile = provider.lookup_file_hash(
                    value
                )

            elif indicator_type == "domain":
                profile = provider.lookup_domain(
                    value
                )

            elif indicator_type == "url":
                profile = provider.lookup_url(
                    value
                )

            elif indicator_type == "ip":
                profile = provider.lookup_ip(
                    value
                )

            else:
                continue

            profiles.append(profile)

        except (
            VirusTotalError,
            ValueError,
        ) as error:
            profiles.append(
                {
                    "indicator_type": indicator_type,
                    "value": value,
                    "provider": "VirusTotal",
                    "status": "Unavailable",
                    "error": str(error),
                }
            )

    results["Indicator Intelligence"] = profiles

    return results


def evidence_reasoning_stage(investigation, results):
    """
    Reason over collected evidence and attach structured findings
    to the ORION investigation.
    """

    evidence = []

    evidence.extend(results.get("Sign-In Evidence", []))

    environment_evidence = results.get(
        "Environment Evidence",
        [],
    )

    if isinstance(environment_evidence, list):
        evidence.extend(environment_evidence)

    existing_evidence = results.get("Evidence", [])

    if isinstance(existing_evidence, list):
        evidence.extend(existing_evidence)

    findings = reason_over_evidence(evidence)

    existing_findings = results.get("Findings", [])

    if not isinstance(existing_findings, list):
        existing_findings = []

    results["Findings"] = [
        *existing_findings,
        *findings,
    ]

    investigation_aggregate = results.get("Investigation Aggregate")

    if isinstance(investigation_aggregate, Investigation):
        investigation_aggregate.findings = results["Findings"]

    return results


def cognitive_reasoning_stage(investigation, results):
    """
    Execute ORION's cognitive reasoning and investigation
    decision engine over the evidence collected by the pipeline.
    """

    evidence = []

    #
    # Convert normalised security incidents into
    # investigation-specific cognitive evidence.
    #
    security_incidents = results.get(
        "Security Incidents",
        [],
    )

    if isinstance(security_incidents, list):
        for incident in security_incidents:
            title_lower = incident.title.lower()

            #
            # Classify incident-level evidence.
            #
            incident_category = "Infrastructure"

            if "malware" in title_lower:
                incident_category = "Malware"

            elif (
                "powershell" in title_lower
                or "process" in title_lower
                or "execution" in title_lower
                or "T1059" in incident.techniques
            ):
                incident_category = "Process"

            elif (
                "sign-in" in title_lower
                or "signin" in title_lower
                or "identity" in title_lower
                or "account" in title_lower
                or "T1078" in incident.techniques
            ):
                incident_category = "Identity"

            evidence.append(
                {
                    "category": incident_category,
                    "finding": (
                        f"Security incident detected: "
                        f"{incident.title}"
                    ),
                    "evidence": (
                        f"Severity={incident.severity}; "
                        f"Status={incident.status}; "
                        f"Tactics={incident.tactics}; "
                        f"Techniques={incident.techniques}; "
                        f"Entities={len(incident.entities)}; "
                        f"Alerts={len(incident.alerts)}"
                    ),
                    "source": incident.source_product,
                    "incident_id": incident.incident_id,
                }
            )

            #
            # Convert Sentinel entities into evidence categories.
            #
            for entity in incident.entities:
                if not isinstance(entity, dict):
                    continue

                kind = str(
                    entity.get(
                        "kind",
                        "Unknown",
                    )
                )

                properties = entity.get(
                    "properties",
                    {},
                )

                kind_lower = kind.lower()

                entity_category = "Infrastructure"

                if kind_lower in {
                    "host",
                    "device",
                }:
                    entity_category = "Endpoint"

                elif kind_lower in {
                    "file",
                    "filehash",
                }:
                    entity_category = "File"

                elif kind_lower in {
                    "account",
                    "user",
                }:
                    entity_category = "Identity"

                elif kind_lower in {
                    "process",
                }:
                    entity_category = "Process"

                elif kind_lower in {
                    "ip",
                    "ipaddress",
                }:
                    entity_category = "Network"

                evidence.append(
                    {
                        "category": entity_category,
                        "finding": (
                            f"Incident entity identified: {kind}"
                        ),
                        "evidence": str(properties),
                        "source": incident.source_product,
                        "incident_id": incident.incident_id,
                    }
                )

            #
            # Convert associated Sentinel alerts into evidence.
            #
            for alert in incident.alerts:
                if not isinstance(alert, dict):
                    continue

                alert_properties = alert.get(
                    "properties",
                    {},
                )

                if not isinstance(alert_properties, dict):
                    alert_properties = {}

                alert_name = str(
                    alert_properties.get(
                        "alertDisplayName",
                        "",
                    )
                )

                alert_description = str(
                    alert_properties.get(
                        "description",
                        "",
                    )
                )

                alert_type = str(
                    alert_properties.get(
                        "alertType",
                        "",
                    )
                )

                alert_tactics = alert_properties.get(
                    "tactics",
                    [],
                )

                if not isinstance(alert_tactics, list):
                    alert_tactics = []

                additional_data = alert_properties.get(
                    "additionalData",
                    {},
                )

                if not isinstance(additional_data, dict):
                    additional_data = {}

                mitre_techniques = str(
                    additional_data.get(
                        "MitreTechniques",
                        "",
                    )
                )

                classification_text = " ".join(
                    [
                        alert_name,
                        alert_description,
                        alert_type,
                        " ".join(
                            str(item)
                            for item in alert_tactics
                        ),
                        mitre_techniques,
                    ]
                ).lower()

                #
                # Preserve the incident classification unless
                # the alert contains stronger explicit evidence.
                #
                alert_category = incident_category

                if (
                    "malware" in classification_text
                    or "ransomware" in classification_text
                ):
                    alert_category = "Malware"

                elif (
                    "sign-in" in classification_text
                    or "signin" in classification_text
                    or "authentication" in classification_text
                    or "credential" in classification_text
                    or "valid account" in classification_text
                    or "t1078" in classification_text
                ):
                    alert_category = "Identity"

                elif (
                    "powershell" in classification_text
                    or "command execution" in classification_text
                    or "script execution" in classification_text
                    or "t1059" in classification_text
                ):
                    alert_category = "Process"

                evidence.append(
                    {
                        "category": alert_category,
                        "finding": (
                            "Associated Sentinel alert identified"
                        ),
                        "evidence": str(alert_properties),
                        "source": incident.source_product,
                        "incident_id": incident.incident_id,
                    }
                )

    #
    # Add Microsoft Entra sign-in evidence.
    #
    sign_in_evidence = results.get(
        "Sign-In Evidence",
        [],
    )

    if isinstance(sign_in_evidence, list):
        evidence.extend(sign_in_evidence)

    #
    # Add existing structured ORION evidence.
    #
    existing_evidence = results.get(
        "Evidence",
        [],
    )

    if isinstance(existing_evidence, list):
        evidence.extend(existing_evidence)

    #
    # Preserve findings from earlier reasoning stages.
    #
    existing_findings = results.get(
        "Findings",
        [],
    )

    if isinstance(existing_findings, list):
        evidence.extend(existing_findings)

    #
    # Promote structured indicator intelligence into
    # cognitive evidence.
    #
    indicator_intelligence = results.get(
        "Indicator Intelligence",
        [],
    )

    if not isinstance(
        indicator_intelligence,
        list,
    ):
        indicator_intelligence = [
            indicator_intelligence
        ]

    for profile in indicator_intelligence:
        if not isinstance(
            profile,
            IndicatorProfile,
        ):
            continue

        classification = (
            profile.classification.value
            if hasattr(
                profile.classification,
                "value",
            )
            else str(profile.classification)
        )

        indicator_type = (
            profile.indicator_type.value
            if hasattr(
                profile.indicator_type,
                "value",
            )
            else str(profile.indicator_type)
        )

        evidence.append(
            {
                "category": (
                    profile.category
                    if profile.category != "Unknown"
                    else "Threat Intelligence"
                ),
                "finding": (
                    f"{indicator_type} {profile.value} "
                    f"is classified as {classification} "
                    f"by {profile.provider}"
                ),
                "evidence": (
                    f"Risk={profile.risk_level}; "
                    f"Confidence={profile.confidence}%; "
                    f"ThreatFamily={profile.threat_family}; "
                    f"Sources={profile.intelligence_sources}; "
                    f"MITRE={profile.mitre_techniques}; "
                    f"InternalPrevalence="
                    f"{profile.internal_prevalence}"
                ),
                "source": profile.provider,
            }
        )


    #
    # Build cognitive decision signals.
    #
    signals = {}

    contextual_risk = results.get(
        "Contextual Risk",
        {},
    )

    if isinstance(contextual_risk, dict):
        score = contextual_risk.get("score")

        if isinstance(score, (int, float)):
            signals["contextual_risk"] = score

    business_impact = results.get(
        "Business Impact",
        {},
    )

    if isinstance(business_impact, dict):
        score = business_impact.get("score")

        if isinstance(score, (int, float)):
            signals["business_impact"] = score

    #
    # Build decision context.
    #
    decision_context = {
        "supporting_evidence": normalise_text_items(
            results.get(
                "Findings",
                [],
            )
        ),
        "indicator_intelligence": results.get(
            "Indicator Intelligence",
            [],
        ),
    }

    #
    # Execute ORION cognitive investigation.
    #
    cognitive_run = execute_cognitive_pipeline(
        evidence=evidence,
        signals=signals,
        decision_context=decision_context,
    )

    #
    # Publish cognitive results.
    #
    results["Cognitive Run"] = cognitive_run
    results["Findings"] = cognitive_run.findings
    results["Questions"] = cognitive_run.questions
    results["Hypotheses"] = cognitive_run.hypotheses
    results["Investigation Outcome"] = (
        cognitive_run.outcome
    )

    #
    # Synchronise the Investigation aggregate.
    #
    investigation_aggregate = results.get(
        "Investigation Aggregate"
    )

    if isinstance(
        investigation_aggregate,
        Investigation,
    ):
        investigation_aggregate.findings = (
            cognitive_run.findings
        )

        investigation_aggregate.questions = (
            cognitive_run.questions
        )

        investigation_aggregate.hypotheses = (
            cognitive_run.hypotheses
        )

        investigation_aggregate.investigation_outcome = (
            cognitive_run.outcome
        )

    return results


def business_impact_stage(investigation, results):
    """
    Assess organisational impact using enriched identity context.
    """

    business_impact = assess_business_impact(results["Enriched Identity"])

    results["Business Impact"] = business_impact

    investigation_aggregate = results.get("Investigation Aggregate")

    if isinstance(investigation_aggregate, Investigation):
        investigation_aggregate.business_impact = business_impact

    return results


def ip_enrichment_stage(investigation, results):
    """
    Enrich extracted IP addresses with structured context.
    """

    results["Enriched IPs"] = enrich_ips(results["IP Addresses"])

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
    Correlates the original normalized threat-intelligence results.
    """

    threat_results = results.get(
        "Threat Intelligence",
        [],
    )

    if not isinstance(threat_results, list):
        threat_results = [threat_results]

    correlation_result = correlate_threat_intelligence(threat_results)

    results["Threat Correlation"] = correlation_result

    return results


def contextual_risk_stage(investigation, results):
    """
    Calculate the overall contextual investigation risk.
    """

    results["Contextual Risk"] = assess_contextual_risk(investigation)

    return results


def operational_decision_stage(investigation, results):
    """
    Determine the operational response using ORION's cognitive
    investigation outcome together with risk, business impact,
    and original alert severity.
    """

    operational_decision = determine_operational_decision(
        contextual_risk=results.get(
            "Contextual Risk",
            {},
        ),
        business_impact=results.get(
            "Business Impact",
            {},
        ),
        investigation_outcome=results.get(
            "Investigation Outcome"
        ),
        security_incidents=results.get(
            "Security Incidents",
            [],
        ),
    )

    results["Operational Decision"] = (
        operational_decision
    )

    investigation_aggregate = results.get(
        "Investigation Aggregate"
    )

    if isinstance(
        investigation_aggregate,
        Investigation,
    ):
        investigation_aggregate.operational_decision = (
            operational_decision
        )

    return results


def attack_pattern_stage(investigation, results):
    """
    Detect recognised attack patterns from investigation evidence.
    """

    correlation_result = results.get("Threat Correlation")

    if not isinstance(correlation_result, dict):
        correlation_result = {
            "verdict": "Unknown",
            "confidence": "Low",
            "sources": 0,
            "reason": "No threat correlation available.",
        }

    investigation_text = build_investigation_text(investigation)

    results["Attack Patterns"] = detect_attack_patterns(
        investigation_text,
        results.get("URL Scores", []),
        results.get("Domain Intelligence", []),
        results.get("IP Scores", []),
        correlation_result,
    )

    return results


def response_playbook_stage(investigation, results):
    """
    Generate response playbooks for detected attack patterns.
    """

    results["Response Playbooks"] = get_response_playbook(results["Attack Patterns"])

    return results


def case_creation_stage(investigation, results):
    """
    Creates one central InvestigationCase from the completed
    ORION investigation pipeline results.
    """

    operational_decision = results.get(
        "Operational Decision",
        {},
    )

    business_impact = results.get(
        "Business Impact",
        {},
    )

    contextual_risk = results.get(
        "Contextual Risk",
        {},
    )

    live_identity_profile = results.get("Live Identity Profile")

    enriched_identity = results.get(
        "Enriched Identity",
        {},
    )

    #
    # Resolve alert metadata.
    #
    if isinstance(investigation, dict):
        title = str(
            investigation.get("title")
            or investigation.get("alert_title")
            or investigation.get("name")
            or "ORION Security Investigation"
        )

        alert_id = str(investigation.get("alert_id") or investigation.get("id") or "")

        alert_source = str(
            investigation.get("source") or investigation.get("alert_source") or "ORION"
        )

        alert_type = str(
            investigation.get("alert_type") or investigation.get("category") or ""
        )

        affected_user = str(
            investigation.get("user") or investigation.get("affected_user") or ""
        )

        affected_host = str(
            investigation.get("host")
            or investigation.get("device")
            or investigation.get("affected_host")
            or ""
        )

        raw_alert = investigation

    else:
        title = "ORION Security Investigation"
        alert_id = ""
        alert_source = "ORION"
        alert_type = ""
        affected_user = ""
        affected_host = ""
        raw_alert = {
            "investigation": str(investigation),
        }

    #
    # Prefer the live Microsoft identity where available.
    #
    if live_identity_profile is not None:
        affected_user = live_identity_profile.user_principal_name or affected_user

    elif isinstance(enriched_identity, dict):
        affected_user = str(
            enriched_identity.get("user_principal_name")
            or enriched_identity.get("upn")
            or enriched_identity.get("user")
            or affected_user
        )

    #
    # Resolve severity.
    #
    severity_value = ""

    if isinstance(operational_decision, dict):
        severity_value = (
            operational_decision.get("severity")
            or operational_decision.get("priority")
            or operational_decision.get("risk")
            or ""
        )

    if not severity_value and isinstance(
        contextual_risk,
        dict,
    ):
        severity_value = (
            contextual_risk.get("severity")
            or contextual_risk.get("risk")
            or contextual_risk.get("level")
            or ""
        )

    case = create_investigation_case(
        title=title,
        alert_id=alert_id,
        alert_source=alert_source,
        alert_type=alert_type,
        severity=map_case_severity(severity_value),
        status=CaseStatus.INVESTIGATING,
        affected_user=affected_user,
        affected_host=affected_host,
        raw_alert=raw_alert,
    )

    #
    # Attach the live Microsoft Graph identity profile.
    #
    case.identity_profile = live_identity_profile

    #
    # Business-impact values.
    #
    if isinstance(business_impact, dict):
        score = business_impact.get("score", 0)

        try:
            case.business_impact_score = int(score)
        except (TypeError, ValueError):
            case.business_impact_score = 0

        case.business_impact_level = str(
            business_impact.get("impact") or business_impact.get("level") or "Unknown"
        )

    #
    # Confidence.
    #
    if isinstance(operational_decision, dict):
        confidence_value = operational_decision.get(
            "confidence",
            0,
        )

        try:
            case.confidence = int(confidence_value)
        except (TypeError, ValueError):
            case.confidence = 0

    #
    # Transfer evidence from existing pipeline outputs.
    #
    evidence_sources = [
        results.get("Threat Intelligence"),
        results.get("Threat Correlation"),
        results.get("Contextual Risk"),
        results.get("Attack Patterns"),
    ]

    for evidence_source in evidence_sources:
        for evidence_item in normalise_text_items(evidence_source):
            case.add_evidence(evidence_item)

    #
    # Transfer response recommendations.
    #
    for action in normalise_text_items(results.get("Response Playbooks")):
        case.add_recommended_action(action)

    #
    # Preserve the existing pipeline results for later API/UI use.
    #
    case.metadata["pipeline_results"] = {
        key: value
        for key, value in results.items()
        if key
        not in {
            "Investigation Case",
            "Live Identity Profile",
        }
    }

    #
    # Add identity-enrichment context to the timeline.
    #
    if live_identity_profile is not None:
        case.add_timeline_event(
            event_type="Identity Enriched",
            description=(
                "ORION enriched the affected identity using live Microsoft Graph data."
            ),
            source="Microsoft Graph",
            entity=(
                live_identity_profile.user_principal_name
                or live_identity_profile.object_id
            ),
            metadata={
                "display_name": (live_identity_profile.display_name),
                "groups": live_identity_profile.groups,
                "registered_devices": (live_identity_profile.registered_devices),
                "risk_level": (live_identity_profile.risk_level),
                "enrichment_status": (live_identity_profile.enrichment_status),
            },
        )

        privileged_groups = {
            "global administrator",
            "privileged role administrator",
            "security administrator",
            "exchange administrator",
            "user administrator",
        }

        matched_privileged_groups = [
            group
            for group in live_identity_profile.groups
            if group.strip().lower() in privileged_groups
        ]

        if matched_privileged_groups:
            case.tags.append("Privileged Identity")

            case.add_evidence(
                "The affected identity has privileged group "
                "membership: " + ", ".join(matched_privileged_groups) + "."
            )

    results["Investigation Case"] = case

    return results


def normalise_text_items(value) -> list[str]:
    """
    Converts different pipeline result structures into unique text items.
    """

    if value is None:
        return []

    if isinstance(value, str):
        cleaned_value = value.strip()
        return [cleaned_value] if cleaned_value else []

    if isinstance(value, dict):
        text_items = []

        for key in (
            "evidence",
            "reason",
            "reasons",
            "recommendations",
            "recommended_actions",
            "actions",
            "playbook",
        ):
            if key in value:
                text_items.extend(normalise_text_items(value[key]))

        if text_items:
            return list(dict.fromkeys(text_items))

        return [str(value)]

    if isinstance(value, (list, tuple, set)):
        text_items = []

        for item in value:
            text_items.extend(normalise_text_items(item))

        return list(dict.fromkeys(text_items))

    return [str(value)]


def map_case_severity(value) -> CaseSeverity:
    """
    Converts pipeline severity values into the InvestigationCase enum.
    """

    cleaned_value = str(value or "").strip().lower()

    severity_mapping = {
        "informational": CaseSeverity.INFORMATIONAL,
        "info": CaseSeverity.INFORMATIONAL,
        "low": CaseSeverity.LOW,
        "medium": CaseSeverity.MEDIUM,
        "high": CaseSeverity.HIGH,
        "critical": CaseSeverity.CRITICAL,
    }

    return severity_mapping.get(
        cleaned_value,
        CaseSeverity.INFORMATIONAL,
    )


def build_investigation_aggregate(results: dict) -> Investigation:
    """
    Convert the legacy pipeline results dictionary into the
    ORION Investigation root aggregate.
    """

    identity_profile = (
        results.get("Live Identity Profile")
        or results.get("Identity Profile")
        or results.get("Enriched Identity")
    )

    return Investigation(
        narrative=results.get("Narrative"),
        security_incidents=results.get("Security Incidents", [],),
        indicators=results.get("IOCs", {}),
        identity_entities=dict(results.get("Identity Entities", {}) or {}),
        identity_enrichment=dict(results.get("Enriched Identity", {}) or {}),
        identity_profile=identity_profile,
        signin_evidence=results.get(
            "Sign-In Evidence",
            [],
        ),
        enriched_ips=results.get("Enriched IPs", []),
        threat_intelligence=results.get("Threat Intelligence", []),
        threat_correlation=results.get("Threat Correlation", {}),
        business_impact=results.get("Business Impact", {}),
        contextual_risk=results.get("Contextual Risk", {}),
        operational_decision=results.get("Operational Decision", {}),
        attack_patterns=results.get("Attack Patterns", []),
        response_playbooks=results.get("Response Playbooks", []),
        hypotheses=results.get("Hypotheses", []),
        findings=results.get("Findings", []),
        questions=results.get("Questions", []),
        confidence_assessment=results.get("Confidence Assessment"),
        investigation_outcome=results.get("Investigation Outcome"),
        investigation_case=results.get("Investigation Case"),
        metadata={
            "pipeline_version": "Day41",
            "legacy_pipeline": True,
            "entity_correlation": results.get(
                "Entity Correlation",
                {},
            ),
            "indicator_intelligence": results.get(
                "Indicator Intelligence",
                [],
            ),
        },
    )


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
        self.add_stage(security_incident_stage)
        self.add_stage(ioc_extraction_stage)
        self.add_stage(identity_extraction_stage)
        self.add_stage(identity_enrichment_stage)
        self.add_stage(signin_evidence_stage)
        self.add_stage(entity_correlation_stage)
        self.add_stage(environment_search_stage)
        self.add_stage(investigation_expansion_stage)
        self.add_stage(blast_radius_stage)
        self.add_stage(indicator_intelligence_stage)
        self.add_stage(evidence_reasoning_stage)
        self.add_stage(business_impact_stage)
        self.add_stage(ip_enrichment_stage)
        self.add_stage(threat_intelligence_stage)
        self.add_stage(threat_correlation_stage)
        self.add_stage(contextual_risk_stage)
        self.add_stage(cognitive_reasoning_stage)
        self.add_stage(operational_decision_stage)
        self.add_stage(attack_pattern_stage)
        self.add_stage(response_playbook_stage)
        self.add_stage(case_creation_stage)

    def run(self, investigation, results=None):

        if results is None:
            results = {}

        investigation_aggregate = Investigation()

        results["Investigation Aggregate"] = investigation_aggregate

        successful = 0
        failed = 0
        failed_stage = None

        total_stages = len(self.stages)

        for index, stage in enumerate(self.stages, start=1):
            stage_name = STAGE_NAMES.get(stage.__name__, stage.__name__)

            start_time = time.perf_counter()

            print(f"[PIPELINE] [{index}/{total_stages}] Starting: {stage_name}")

            try:
                results = stage(investigation, results)

                duration_ms = (time.perf_counter() - start_time) * 1000

                print(
                    f"[PIPELINE] [{index}/{total_stages}] "
                    f"Completed: {stage_name} "
                    f"({duration_ms:.2f} ms)"
                )

                successful += 1

            except Exception as error:
                duration_ms = (time.perf_counter() - start_time) * 1000

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

        completed_aggregate = build_investigation_aggregate(results)

        results["Investigation Aggregate"] = completed_aggregate

        return results
