from dataclasses import dataclass

from .base_model import BaseModel


@dataclass
class Hypothesis(BaseModel):
    """
    Represents a possible explanation for the available
    investigation findings.
    """

    title: str
    explanation: str
    confidence: int = 0