from dataclasses import dataclass, field

from .base_model import BaseModel


@dataclass
class ConfidenceAssessment(BaseModel):
    """
    Represents ORION's explainable confidence calculation.
    """

    final_score: int
    breakdown: dict = field(default_factory=dict)
    weights: dict = field(default_factory=dict)
    explanations: list = field(default_factory=list)