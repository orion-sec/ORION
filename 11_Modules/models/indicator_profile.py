from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .base_model import BaseModel


class IndicatorType(str, Enum):
    """
    Supported ORION indicator types.
    """

    URL = "URL"
    IP_ADDRESS = "IP Address"
    DOMAIN = "Domain"
    FILE_HASH = "File Hash"
    EMAIL = "Email"
    USER = "User"
    DEVICE = "Device"


class IndicatorClassification(str, Enum):
    """
    Intelligence classification assigned to an indicator.
    """

    CONFIRMED_MALICIOUS = "Confirmed Malicious"
    SUSPICIOUS = "Suspicious"
    BENIGN = "Benign"
    UNKNOWN = "Unknown"


@dataclass
class IndicatorProfile(BaseModel):
    """
    Represents an enriched security indicator.
    """

    indicator_type: IndicatorType
    value: str

    classification: IndicatorClassification = (
        IndicatorClassification.UNKNOWN
    )

    risk_level: str = "Unknown"
    confidence: int = 0

    category: str = "Unknown"
    threat_family: str = "Unknown"

    first_seen: str = "Unknown"
    last_seen: str = "Unknown"

    country: str = "Unknown"
    asn: str = "Unknown"
    provider: str = "Unknown"

    internal_prevalence: int = 0

    intelligence_sources: list[str] = field(default_factory=list)
    related_entities: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    metadata: dict[str, Any] = field(default_factory=dict)