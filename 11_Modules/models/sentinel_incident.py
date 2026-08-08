from dataclasses import dataclass, field
from typing import Any

from .base_model import BaseModel


@dataclass
class SentinelIncident(BaseModel):
    """
    Normalized Microsoft Sentinel incident for ORION.
    """

    incident_id: str
    title: str
    severity: str
    status: str
    created_time_utc: str

    raw_metadata: dict[str, Any] = field(default_factory=dict)