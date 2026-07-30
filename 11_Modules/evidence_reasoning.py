def create_finding(category, finding):
    """
    Creates a standardized ORION finding object.
    """
    return {
        "category": category,
        "finding": finding
    }

def reason_over_evidence(evidence):
    """
    Converts structured evidence into structured findings.
    """
    findings = []

    for item in evidence:
        category = item.get("category")
        statement = item.get("statement")

        if category == "Infrastructure":
            findings.append(
                create_finding(
                    "Infrastructure",
                    (
                        "The investigated IP appears to originate "
                        "from hosted or data-centre infrastructure."
                    )
                )
            )

    return findings