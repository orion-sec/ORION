from dataclasses import dataclass, field
from typing import Any

from .base_model import BaseModel


@dataclass
class SignInEvidence(BaseModel):
    """
    Represents a Microsoft Entra sign-in event collected by ORION.
    """

    time_generated: str
    user_principal_name: str
    user_id: str
    ip_address: str

    autonomous_system_number: int | None = None

    application: str = ""
    result_type: str = ""
    result_description: str = ""
    client_app: str = ""
    user_agent: str = ""

    conditional_access_status: str = ""
    risk_level: str = ""

    location: str = ""
    device_detail: dict[str, Any] = field(default_factory=dict)

    correlation_id: str = ""

    raw_metadata: dict[str, Any] = field(default_factory=dict)