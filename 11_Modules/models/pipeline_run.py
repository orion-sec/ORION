from dataclasses import dataclass, field

from .base_model import BaseModel
from .investigation_outcome import InvestigationOutcome


@dataclass
class PipelineRun(BaseModel):
    """
    Represents a complete execution of ORION's
    cognitive pipeline.
    """

    findings: list = field(default_factory=list)
    questions: list = field(default_factory=list)
    hypotheses: list = field(default_factory=list)
    outcome: InvestigationOutcome | None = None
    status: str = "Running"
