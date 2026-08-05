from dataclasses import dataclass, field
from typing import Any

from .base_model import BaseModel


@dataclass
class IdentityProfile(BaseModel):
    """
    Represents a Microsoft Entra identity enriched by ORION.
    """

    object_id: str
    user_principal_name: str
    display_name: str

    email: str = ""
    job_title: str = ""
    department: str = ""
    office_location: str = ""
    account_enabled: bool = False

    manager_name: str = ""
    manager_upn: str = ""

    groups: list[str] = field(default_factory=list)
    registered_devices: list[str] = field(default_factory=list)

    risk_level: str = "Unknown"
    risk_state: str = "Unknown"
    risk_detail: str = "Unknown"

    enrichment_status: dict[str, str] = field(default_factory=dict)
    raw_metadata: dict[str, Any] = field(default_factory=dict)