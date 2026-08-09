def determine_operational_decision(
    contextual_risk,
    business_impact,
    investigation_outcome=None,
    security_incidents=None,
):
    """
    Produce a deterministic and auditable operational decision.

    Cognitive investigation outcome takes precedence over simple
    contextual-risk scoring.

    Auto-close is never permitted unless ORION has reached an
    explicit benign / low-fidelity disposition.
    """

    contextual_risk = (
        contextual_risk
        if isinstance(contextual_risk, dict)
        else {}
    )

    business_impact = (
        business_impact
        if isinstance(business_impact, dict)
        else {}
    )

    if not isinstance(security_incidents, list):
        security_incidents = []

    #
    # Determine highest source-alert severity.
    #
    severity_rank = {
        "informational": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    highest_alert_severity = "unknown"
    highest_rank = -1

    for incident in security_incidents:
        severity = str(
            getattr(incident, "severity", "")
        ).strip().lower()

        rank = severity_rank.get(
            severity,
            -1,
        )

        if rank > highest_rank:
            highest_rank = rank
            highest_alert_severity = severity

    #
    # Resolve cognitive disposition.
    #
    disposition = ""

    if investigation_outcome is not None:
        raw_disposition = getattr(
            investigation_outcome,
            "disposition",
            "",
        )

        disposition = str(
            getattr(
                raw_disposition,
                "value",
                raw_disposition,
            )
        ).strip().lower()

    cognitive_confidence = 0

    if investigation_outcome is not None:
        raw_confidence = getattr(
            investigation_outcome,
            "confidence",
            0,
        )

        try:
            cognitive_confidence = int(
                raw_confidence
            )
        except (TypeError, ValueError):
            cognitive_confidence = 0

    reasons = []
    actions = []

    #
    # ============================================================
    # GATE 1
    # HUMAN REVIEW / INSUFFICIENT EVIDENCE
    # ============================================================
    #
    # This always blocks automatic closure.
    #
    if (
        "human review" in disposition
        or "insufficient" in disposition
        or "undetermined" in disposition
    ):
        decision = "Escalate for Analyst Review"

        if highest_alert_severity in {
            "critical",
            "high",
        }:
            priority = "P2"
        else:
            priority = "P3"

        automation_readiness = "Auto-Close Blocked"

        actions = [
            "Preserve all investigation evidence.",
            "Escalate the investigation with ORION findings and hypotheses.",
            "Resolve outstanding investigation questions.",
            "Do not close automatically.",
        ]

        reasons.append(
            "ORION has not reached a deterministic benign "
            "or malicious disposition."
        )

    #
    # ============================================================
    # GATE 2
    # MALICIOUS / COMPROMISE
    # ============================================================
    #
    elif (
        "malicious" in disposition
        or "compromise" in disposition
        or "true positive" in disposition
    ):
        if highest_alert_severity == "critical":
            decision = (
                "Immediate Escalation and Containment"
            )
            priority = "P1"

        elif highest_alert_severity == "high":
            decision = (
                "Escalate and Prepare Containment"
            )
            priority = "P1"

        else:
            decision = (
                "Escalate for Security Response"
            )
            priority = "P2"

        automation_readiness = (
            "Remediation Approval Required"
        )

        actions = [
            "Escalate with the complete ORION investigation package.",
            "Prepare relevant containment actions.",
            "Request senior analyst approval for remediation.",
            "Execute approved remediation through the appropriate provider.",
        ]

        reasons.append(
            "ORION determined that the available evidence "
            "supports malicious or compromised activity."
        )

    #
    # ============================================================
    # GATE 3
    # BENIGN / FALSE POSITIVE / LOW FIDELITY
    # ============================================================
    #
    elif (
        "benign" in disposition
        or "false positive" in disposition
        or "low fidelity" in disposition
    ):
        if cognitive_confidence >= 80:
            decision = "Auto-Close"
            priority = "P4"
            automation_readiness = (
                "Auto-Close Approved"
            )

            actions = [
                "Record ORION's benign determination.",
                "Attach supporting evidence to the alert.",
                "Close the alert as benign or false positive.",
                "Retain investigation telemetry for future correlation.",
            ]

            reasons.append(
                "ORION reached a benign disposition with "
                "sufficient confidence for automated closure."
            )

        else:
            decision = "Validate Before Closure"
            priority = "P3"
            automation_readiness = (
                "Analyst Validation Required"
            )

            actions = [
                "Review the evidence supporting the benign determination.",
                "Confirm no related suspicious activity exists.",
                "Close only after validation.",
            ]

            reasons.append(
                "ORION identified likely benign activity, "
                "but confidence is below the auto-close threshold."
            )

    #
    # ============================================================
    # GATE 4
    # SAFETY FALLBACK
    # ============================================================
    #
    else:
        decision = "Continue Investigation"

        if highest_alert_severity in {
            "critical",
            "high",
        }:
            priority = "P2"
        else:
            priority = "P3"

        automation_readiness = (
            "Automation Blocked"
        )

        actions = [
            "Continue evidence collection.",
            "Search for related activity across the environment.",
            "Resolve outstanding investigation questions.",
            "Do not automatically close or remediate.",
        ]

        reasons.append(
            "No trusted final cognitive disposition "
            "is currently available."
        )

    return {
        "decision": decision,
        "priority": priority,
        "automation_readiness": automation_readiness,
        "actions": actions,
        "reasons": reasons,
        "inputs": {
            "contextual_risk": (
                contextual_risk.get(
                    "severity",
                    "Unknown",
                )
            ),
            "business_impact": (
                business_impact.get(
                    "impact",
                    "Unknown",
                )
            ),
            "alert_severity": highest_alert_severity,
            "cognitive_disposition": disposition,
            "cognitive_confidence": cognitive_confidence,
        },
    }
