from dataclasses import dataclass

from .base_model import BaseModel


@dataclass
class Question(BaseModel):
    """
    Represents an unresolved investigation question ORION
    needs answered in order to reduce uncertainty.
    """

    question: str
    reason: str
    category: str = "General"
    evidence_gap: str = ""
    priority: str = "Medium"
    status: str = "Unresolved"