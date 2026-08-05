from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from .base_model import BaseModel
from .identity_profile import IdentityProfile
from .incident_narrative import IncidentNarrative
from .investigation_outcome import InvestigationOutcome


class CaseStatus(str, Enum):
    """
    Represents the operational lifecycle of an ORION case.
    """

    NEW = "New"
    TRIAGE = "Triage"
    INVESTIGATING = "Investigating"
    CONTAINMENT_PENDING = "Containment Pending"
    CONTAINED = "Contained"
    MONITORING = "Monitoring"
    CLOSED = "Closed"
    ESCALATED = "Escalated"


class CaseSeverity(str, Enum):
    """
    Represents the current severity assigned to a case.
    """

    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class CaseTimelineEvent(BaseModel):
    """
    Represents one chronological event within an ORION case.
    """

    timestamp: str
    event_type: str
    description: str

    source: str = "ORION"
    actor: str = ""
    entity: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class InvestigationCase(BaseModel):
    """
    Central ORION case object.

    Combines investigation, enrichment, intelligence, reasoning,
    decision and reporting outputs into one persistent structure.
    """

    case_id: str
    title: str

    status: CaseStatus = CaseStatus.NEW
    severity: CaseSeverity = CaseSeverity.INFORMATIONAL

    alert_id: str = ""
    alert_source: str = ""
    alert_type: str = ""

    created_at: str = field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )

    updated_at: str = field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )

    assigned_to: str = ""
    tenant_id: str = ""

    affected_user: str = ""
    affected_host: str = ""

    identity_profile: IdentityProfile | None = None
    investigation_outcome: InvestigationOutcome | None = None
    incident_narrative: IncidentNarrative | None = None

    confidence: int = 0
    business_impact_score: int = 0
    business_impact_level: str = "Unknown"

    findings: list[Any] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    hypotheses: list[Any] = field(default_factory=list)
    investigation_questions: list[Any] = field(
        default_factory=list
    )

    indicators: list[Any] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

    supporting_evidence: list[str] = field(
        default_factory=list
    )

    contradicting_evidence: list[str] = field(
        default_factory=list
    )

    unresolved_questions: list[str] = field(
        default_factory=list
    )

    recommended_actions: list[str] = field(
        default_factory=list
    )

    timeline: list[CaseTimelineEvent] = field(
        default_factory=list
    )

    tags: list[str] = field(default_factory=list)
    raw_alert: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def touch(self) -> None:
        """
        Updates the case modification timestamp.
        """

        self.updated_at = datetime.now(
            timezone.utc
        ).isoformat()

    def add_timeline_event(
        self,
        event_type: str,
        description: str,
        source: str = "ORION",
        actor: str = "",
        entity: str = "",
        metadata: dict[str, Any] | None = None,
        timestamp: str | None = None,
    ) -> CaseTimelineEvent:
        """
        Adds a chronological event to the case.
        """

        event = CaseTimelineEvent(
            timestamp=(
                timestamp
                or datetime.now(timezone.utc).isoformat()
            ),
            event_type=event_type,
            description=description,
            source=source,
            actor=actor,
            entity=entity,
            metadata=metadata or {},
        )

        self.timeline.append(event)

        self.timeline.sort(
            key=lambda item: item.timestamp
        )

        self.touch()

        return event

    def add_evidence(self, evidence_item: str) -> None:
        """
        Adds unique evidence to the case.
        """

        cleaned_item = evidence_item.strip()

        if cleaned_item and cleaned_item not in self.evidence:
            self.evidence.append(cleaned_item)
            self.touch()

    def add_recommended_action(self, action: str) -> None:
        """
        Adds a unique recommended response action.
        """

        cleaned_action = action.strip()

        if (
            cleaned_action
            and cleaned_action not in self.recommended_actions
        ):
            self.recommended_actions.append(cleaned_action)
            self.touch()

    def add_mitre_technique(self, technique: str) -> None:
        """
        Adds a unique MITRE ATT&CK technique.
        """

        cleaned_technique = technique.strip()

        if (
            cleaned_technique
            and cleaned_technique not in self.mitre_techniques
        ):
            self.mitre_techniques.append(cleaned_technique)
            self.touch()

    def change_status(self, status: CaseStatus) -> None:
        """
        Changes the operational case status.
        """

        previous_status = self.status
        self.status = status

        self.add_timeline_event(
            event_type="Case Status Changed",
            description=(
                f"Case status changed from "
                f"{previous_status.value} to {status.value}."
            ),
        )

    def change_severity(
        self,
        severity: CaseSeverity,
        reason: str = "",
    ) -> None:
        """
        Changes case severity and records the decision.
        """

        previous_severity = self.severity
        self.severity = severity

        description = (
            f"Case severity changed from "
            f"{previous_severity.value} "
            f"to {severity.value}."
        )

        if reason:
            description = f"{description} Reason: {reason}"

        self.add_timeline_event(
            event_type="Severity Changed",
            description=description,
        )