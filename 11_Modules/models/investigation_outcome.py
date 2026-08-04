from dataclasses import dataclass, field
from enum import Enum

from .base_model import BaseModel


class Disposition(str, Enum):
    """
    Supported ORION investigation dispositions.
    """

    TRUE_POSITIVE = "True Positive"
    FALSE_POSITIVE = "False Positive"
    BENIGN_POSITIVE = "Benign Positive"
    SUSPICIOUS = "Suspicious"
    NEEDS_HUMAN_REVIEW = "Needs Human Review"
    POLICY_VIOLATION = "Policy Violation"
    MISCONFIGURATION = "Misconfiguration"
    AUTHORIZED_ADMINISTRATIVE_ACTIVITY = "Authorized Administrative Activity"
    AUTHORIZED_SECURITY_TESTING = "Authorized Security Testing"
    BUSINESS_RISK = "Business Risk"
    INFRASTRUCTURE_ISSUE = "Infrastructure Issue"
    THREAT_HUNT_CANDIDATE = "Threat Hunt Candidate"
    INSUFFICIENT_EVIDENCE = "Insufficient Evidence"


@dataclass
class InvestigationOutcome(BaseModel):
    """
    Represents ORION's final assessment of an investigation.
    """

    disposition: Disposition
    confidence: int
    reason: str
    supporting_evidence: list = field(default_factory=list)
    contradicting_evidence: list = field(default_factory=list)
    unresolved_questions: list = field(default_factory=list)
    recommended_actions: list = field(default_factory=list)