from factories.finding_factory import create_finding


def reason_about_identity(item):
    """
    Produces findings from identity and account evidence.
    """

    finding = str(item.get("finding", "")).strip()
    evidence = str(item.get("evidence", "")).strip()

    if not finding and not evidence:
        return None

    return create_finding(
        "Identity",
        (
            f"Identity-related evidence was identified. "
            f"{finding}. Evidence: {evidence}"
        ),
    )
