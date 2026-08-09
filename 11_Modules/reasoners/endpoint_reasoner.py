from factories.finding_factory import create_finding


def reason_about_endpoint(item):
    """
    Produces endpoint findings from host or device evidence.
    """

    finding = str(item.get("finding", "")).strip()
    evidence = str(item.get("evidence", "")).strip()

    if not finding and not evidence:
        return None

    return create_finding(
        "Endpoint",
        (
            f"Endpoint-related evidence was identified. "
            f"{finding}. Evidence: {evidence}"
        ),
    )
