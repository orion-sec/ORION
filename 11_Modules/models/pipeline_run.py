from dataclasses import dataclass, field

from .base_model import BaseModel


@dataclass
class PipelineRun(BaseModel):
    """
    Represents a complete execution of ORION's
    cognitive pipeline.
    """

    findings: list = field(default_factory=list)

    questions: list = field(default_factory=list)

    hypotheses: list = field(default_factory=list)

    status: str = "Running"