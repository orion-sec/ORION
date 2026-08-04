from dataclasses import dataclass, field

from .base_model import BaseModel


@dataclass
class IncidentNarrative(BaseModel):
    """
    Represents an analyst-ready narrative produced from
    an ORION investigation outcome.
    """

    executive_summary: str = ""
    analyst_verdict: str = ""
    severity: str = "Unknown"
    disposition: str = "Unknown"
    confidence: int = 0
    key_evidence: list = field(default_factory=list)