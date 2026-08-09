from factories.finding_factory import create_finding


def reason_about_file(item):
    """
    Produces findings from file and file-hash evidence.
    """

    finding = str(item.get("finding", "")).strip()
    evidence = str(item.get("evidence", "")).strip()

    if not finding and not evidence:
        return None

    return create_finding(
        "File",
        (
            f"File-related evidence was identified. "
            f"{finding}. Evidence: {evidence}"
        ),
    )
