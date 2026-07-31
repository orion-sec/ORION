from dataclasses import dataclass

from .base_model import BaseModel


@dataclass
class Question(BaseModel):
    """
    Represents a question ORION needs answered in order to
    reduce uncertainty during an investigation.
    """

    question: str
    reason: str