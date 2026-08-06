from dataclasses import dataclass, field
from typing import Any

from .base_model import BaseModel
from .confidence_assessment import ConfidenceAssessment
from .identity_profile import IdentityProfile
from .incident_narrative import IncidentNarrative
from .investigation_case import InvestigationCase
from .investigation_outcome import InvestigationOutcome


@dataclass
class Investigation(BaseModel):
    """
    Root aggregate for an ORION investigation.

    Every investigation stage reads from and writes to this object.
    """

    # Alert / Narrative
    narrative: IncidentNarrative | None = None

    # Indicators
    indicators: dict[str, Any] = field(default_factory=dict)

    # Identity
    identity_entities: dict[str, Any] = field(default_factory=dict)
    identity_enrichment: dict[str, Any] = field(default_factory=dict)
    identity_profile: IdentityProfile | None = None

    # Enrichment
    enriched_ips: list = field(default_factory=list)
    threat_intelligence: list = field(default_factory=list)
    threat_correlation: dict[str, Any] = field(default_factory=dict)

    # Investigation
    business_impact: dict = field(default_factory=dict)
    contextual_risk: dict = field(default_factory=dict)
    operational_decision: dict = field(default_factory=dict)

    attack_patterns: list = field(default_factory=list)
    response_playbooks: list = field(default_factory=list)

    # Cognitive
    hypotheses: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    questions: list = field(default_factory=list)

    # Assessment
    confidence_assessment: ConfidenceAssessment | None = None
    investigation_outcome: InvestigationOutcome | None = None

    # Case Management
    investigation_case: InvestigationCase | None = None

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)