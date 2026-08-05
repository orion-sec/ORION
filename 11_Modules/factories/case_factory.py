from typing import Any
from uuid import uuid4

from models.investigation_case import (
    CaseSeverity,
    CaseStatus,
    InvestigationCase,
)


def generate_case_id() -> str:
    """
    Generates a readable ORION case identifier.
    """

    short_identifier = str(uuid4()).split("-")[0].upper()

    return f"ORION-CASE-{short_identifier}"


def create_investigation_case(
    title: str,
    alert_id: str = "",
    alert_source: str = "",
    alert_type: str = "",
    severity: CaseSeverity = CaseSeverity.INFORMATIONAL,
    status: CaseStatus = CaseStatus.NEW,
    affected_user: str = "",
    affected_host: str = "",
    tenant_id: str = "",
    assigned_to: str = "",
    raw_alert: dict[str, Any] | None = None,
    case_id: str | None = None,
) -> InvestigationCase:
    """
    Creates a new normalized ORION investigation case.
    """

    cleaned_title = title.strip()

    if not cleaned_title:
        raise ValueError("Case title cannot be empty.")

    investigation_case = InvestigationCase(
        case_id=case_id or generate_case_id(),
        title=cleaned_title,
        alert_id=alert_id,
        alert_source=alert_source,
        alert_type=alert_type,
        severity=severity,
        status=status,
        affected_user=affected_user,
        affected_host=affected_host,
        tenant_id=tenant_id,
        assigned_to=assigned_to,
        raw_alert=raw_alert or {},
    )

    investigation_case.add_timeline_event(
        event_type="Case Created",
        description=(
            f"ORION created investigation case "
            f"{investigation_case.case_id}."
        ),
        source=alert_source or "ORION",
        entity=affected_user or affected_host,
    )

    return investigation_case