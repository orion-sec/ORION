from factories.finding_factory import create_finding


def reason_about_process(item):
    """
    Produces process execution findings.
    """

    finding = str(item.get("finding", "")).strip()
    evidence = str(item.get("evidence", "")).strip()

    if not finding and not evidence:
        return None

    return create_finding(
        "Process",
        (
            f"Suspicious process or execution activity was identified. "
            f"{finding}. Evidence: {evidence}"
        ),
    )
