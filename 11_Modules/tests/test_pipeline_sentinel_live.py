from connectors.azure_monitor import AzureMonitorClient
from connectors.config import load_graph_config
from pipeline import OrionPipeline
from providers.provider_manager import ProviderManager


def test_live_sentinel_incidents_run_independently() -> None:
    """
    Validate that every Microsoft Sentinel incident is investigated
    independently by ORION.

    Correlation between incidents will be handled separately and only
    when shared entities or other meaningful relationships are found.
    """

    config = load_graph_config()

    client = AzureMonitorClient(config)

    subscriptions = client.list_subscriptions()

    if not subscriptions:
        raise RuntimeError(
            "No Azure subscriptions were returned."
        )

    subscription_id = subscriptions[0]["subscriptionId"]

    resource_group = "orion-rg"
    workspace_name = "orion-law"

    print()
    print("=" * 70)
    print("ORION LIVE SENTINEL -> INDEPENDENT INVESTIGATIONS")
    print("=" * 70)
    print(f"Using Subscription : {subscription_id}")
    print(f"Resource Group     : {resource_group}")
    print(f"Workspace          : {workspace_name}")

    providers = ProviderManager(
        config=config,
        subscription_id=subscription_id,
        resource_group=resource_group,
        workspace_name=workspace_name,
    )

    #
    # Collect live Sentinel incidents with entities and alerts.
    #
    raw_security_incidents = (
        providers.sentinel.collect_incidents()
    )

    if not raw_security_incidents:
        raise RuntimeError(
            "No Microsoft Sentinel incidents were collected."
        )

    investigation_results = []

    #
    # IMPORTANT:
    # Each Sentinel incident gets a completely independent
    # ORION investigation and pipeline execution.
    #
    for index, raw_security_incident in enumerate(
        raw_security_incidents,
        start=1,
    ):
        raw_incident = raw_security_incident.get(
            "raw",
            {},
        )

        if not isinstance(raw_incident, dict):
            continue

        properties = raw_incident.get(
            "properties",
            {},
        )

        if not isinstance(properties, dict):
            properties = {}

        incident_id = str(
            raw_incident.get(
                "name",
                "",
            )
        )

        incident_title = str(
            properties.get(
                "title",
                "Microsoft Sentinel Incident",
            )
        )

        severity = str(
            properties.get(
                "severity",
                "Unknown",
            )
        )

        #
        # Fresh pipeline for this incident only.
        #
        pipeline = OrionPipeline()
        pipeline.load_default_pipeline()

        initial_results = {
            "Raw Security Incidents": [
                raw_security_incident
            ],
            "Environment Search Provider": (
                providers.environment_search
            ),
        }

        investigation_input = {
            "title": incident_title,
            "alert_id": incident_id,
            "source": "Microsoft Sentinel",
            "alert_source": "Microsoft Sentinel",
            "alert_type": "Sentinel Incident",
            "severity": severity,
        }

        print()
        print("=" * 70)
        print(
            f"STARTING ORION INVESTIGATION #{index}"
        )
        print("=" * 70)
        print(f"Incident ID : {incident_id}")
        print(f"Title       : {incident_title}")
        print(f"Severity    : {severity}")

        results = pipeline.run(
            investigation=investigation_input,
            results=initial_results,
        )

        investigation_results.append(
            {
                "incident_id": incident_id,
                "title": incident_title,
                "results": results,
            }
        )

    #
    # Display each ORION investigation independently.
    #
    print()
    print("=" * 70)
    print("ORION INDEPENDENT INVESTIGATION RESULTS")
    print("=" * 70)

    for index, item in enumerate(
        investigation_results,
        start=1,
    ):
        results = item["results"]

        security_incidents = results.get(
            "Security Incidents",
            [],
        )

        findings = results.get(
            "Findings",
            [],
        )

        questions = results.get(
            "Questions",
            [],
        )

        hypotheses = results.get(
            "Hypotheses",
            [],
        )

        outcome = results.get(
            "Investigation Outcome"
        )

        entity_correlation = results.get(
            "Entity Correlation",
            {},
        )

        environment_search = results.get(
            "Environment Search",
            {},
        )

        environment_evidence = results.get(
            "Environment Evidence",
            [],
        )

        investigation_expansion = results.get(
            "Investigation Expansion",
            {},
        )

        blast_radius = results.get(
            "Blast Radius",
            {},
        )

        operational_decision = results.get(
            "Operational Decision",
            {},
        )

        response_playbooks = results.get(
            "Response Playbooks",
            [],
        )

        aggregate = results[
            "Investigation Aggregate"
        ]

        print()
        print("#" * 70)
        print(
            f"ORION INVESTIGATION #{index}"
        )
        print("#" * 70)

        print(
            f"Incident ID        : "
            f"{item['incident_id']}"
        )

        print(
            f"Title              : "
            f"{item['title']}"
        )

        print(
            f"Normalised Incidents: "
            f"{len(security_incidents)}"
        )

        #
        # Normalised incident.
        #
        for incident in security_incidents:
            print()
            print("NORMALISED INCIDENT")
            print("-" * 70)

            print(
                f"Severity           : "
                f"{incident.severity}"
            )

            print(
                f"Status             : "
                f"{incident.status}"
            )

            print(
                f"Tactics            : "
                f"{incident.tactics}"
            )

            print(
                f"Techniques         : "
                f"{incident.techniques}"
            )

            print(
                f"Entities           : "
                f"{len(incident.entities)}"
            )

            print(
                f"Alerts             : "
                f"{len(incident.alerts)}"
            )

        #
        # Findings.
        #
        print()
        print("FINDINGS")
        print("-" * 70)
        print(f"Count              : {len(findings)}")

        for finding_index, finding in enumerate(
            findings,
            start=1,
        ):
            print(
                f"[{finding_index}] {finding}"
            )

        #
        # Questions.
        #
        print()
        print("QUESTIONS")
        print("-" * 70)
        print(f"Count              : {len(questions)}")

        for question_index, question in enumerate(
            questions,
            start=1,
        ):
            print(
                f"[{question_index}] {question}"
            )

        #
        # Hypotheses.
        #
        print()
        print("HYPOTHESES")
        print("-" * 70)
        print(f"Count              : {len(hypotheses)}")

        for hypothesis_index, hypothesis in enumerate(
            hypotheses,
            start=1,
        ):
            print(
                f"[{hypothesis_index}] "
                f"{hypothesis}"
            )

        #
        # Cognitive outcome.
        #
        print()
        print("INVESTIGATION OUTCOME")
        print("-" * 70)

        if outcome is None:
            print("Outcome            : None")

        else:
            print(
                f"Outcome Type       : "
                f"{type(outcome).__name__}"
            )

            print(
                f"Disposition        : "
                f"{getattr(outcome, 'disposition', None)}"
            )

            print(
                f"Confidence         : "
                f"{getattr(outcome, 'confidence', None)}"
            )

            print(
                f"Reason             : "
                f"{getattr(outcome, 'reason', None)}"
            )

            print(
                "Recommended Action : "
                f"{getattr(
                    outcome,
                    'recommended_action',
                    None,
                )}"
            )

        #
        # Correlation and environment investigation.
        #

        print()
        print("ENTITY CORRELATION")
        print("-" * 70)

        print(
            "Correlation Keys    : "
            f"{entity_correlation.get('correlation_keys', [])}"
        )

        print()
        print("ENVIRONMENT SEARCH")
        print("-" * 70)

        print(
            "Search Count        : "
            f"{environment_search.get('search_count', 0)}"
        )

        print(
            "Environment Evidence: "
            f"{len(environment_evidence)}"
        )

        print()
        print("INVESTIGATION EXPANSION")
        print("-" * 70)

        print(
            "Expanded            : "
            f"{investigation_expansion.get('expanded', False)}"
        )

        print(
            "Affected Entities   : "
            f"{investigation_expansion.get('affected_entity_count', 0)}"
        )

        print(
            "Entities            : "
            f"{investigation_expansion.get('entities', {})}"
        )

        print()
        print("BLAST RADIUS")
        print("-" * 70)

        print(
            "Scope               : "
            f"{blast_radius.get('scope', 'None')}"
        )

        print(
            "Affected Entities   : "
            f"{blast_radius.get('affected_entity_count', 0)}"
        )

        print(
            "Active Categories   : "
            f"{blast_radius.get('active_categories', 0)}"
        )

        print(
            "Entity Counts       : "
            f"{blast_radius.get('counts', {})}"
        )


        #
        # Operational response.
        #
        print()
        print("OPERATIONAL RESPONSE")
        print("-" * 70)

        print(
            "Operational Decision: "
            f"{operational_decision}"
        )

        print(
            "Response Playbooks   : "
            f"{response_playbooks}"
        )

        #
        # Aggregate validation display.
        #
        print()
        print("AGGREGATE")
        print("-" * 70)

        print(
            "Aggregate Incidents : "
            f"{len(aggregate.security_incidents)}"
        )

        print(
            "Aggregate Findings  : "
            f"{len(aggregate.findings)}"
        )

        print(
            "Aggregate Hypotheses: "
            f"{len(aggregate.hypotheses)}"
        )

        print(
            "Aggregate Outcome   : "
            f"{aggregate.investigation_outcome}"
        )

        #
        # Each pipeline execution MUST contain exactly one
        # Sentinel incident.
        #
        assert len(security_incidents) == 1

        assert len(
            aggregate.security_incidents
        ) == 1

        assert (
            aggregate.security_incidents[0].incident_id
            == item["incident_id"]
        )

        assert results.get(
            "Cognitive Run"
        ) is not None

        assert outcome is not None

    #
    # Ensure ORION created one independent investigation
    # for every collected Sentinel incident.
    #
    assert len(investigation_results) == len(
        raw_security_incidents
    )


if __name__ == "__main__":
    test_live_sentinel_incidents_run_independently()
