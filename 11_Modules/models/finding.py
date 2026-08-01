from dataclasses import dataclass

from .base_model import BaseModel


@dataclass
class Finding(BaseModel):
    """
    Represents a conclusion ORION reached
    after reasoning over evidence.
    """

    category: str
    finding: str