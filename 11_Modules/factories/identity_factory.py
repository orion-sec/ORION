from typing import Any

from models.identity_profile import IdentityProfile


def create_identity_profile(
    object_id: str,
    user_principal_name: str,
    display_name: str,
    email: str = "",
    job_title: str = "",
    department: str = "",
    office_location: str = "",
    account_enabled: bool = False,
    manager_name: str = "",
    manager_upn: str = "",
    groups: list[str] | None = None,
    registered_devices: list[str] | None = None,
    risk_level: str = "Unknown",
    risk_state: str = "Unknown",
    risk_detail: str = "Unknown",
    enrichment_status: dict[str, str] | None = None,
    raw_metadata: dict[str, Any] | None = None,
) -> IdentityProfile:
    """
    Creates a normalized ORION identity profile.
    """

    return IdentityProfile(
        object_id=object_id,
        user_principal_name=user_principal_name,
        display_name=display_name,
        email=email,
        job_title=job_title,
        department=department,
        office_location=office_location,
        account_enabled=account_enabled,
        manager_name=manager_name,
        manager_upn=manager_upn,
        groups=groups or [],
        registered_devices=registered_devices or [],
        risk_level=risk_level,
        risk_state=risk_state,
        risk_detail=risk_detail,
        enrichment_status=enrichment_status or {},
        raw_metadata=raw_metadata or {},
    )