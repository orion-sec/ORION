from dataclasses import dataclass, field
from typing import Any

from .base_model import BaseModel


@dataclass
class SecurityIncident(BaseModel):
    """
    Vendor-neutral security incident used throughout ORION.

    Provider-specific incidents are normalised into this model
    before entering ORION's investigation and reasoning layers.
    """

    incident_id: str
    title: str
    severity: str
    status: str
    created_time_utc: str

    source_provider: str = ""
    source_product: str = ""

    raw_metadata: dict[str, Any] = field(
        default_factory=dict
    )