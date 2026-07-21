import re


def extract_identity_entities(investigation):
    """
    Extract identity-related entities from an investigation narrative.

    This first version focuses on email addresses and assigns the first
    detected address as the primary user identity for investigation context.
    """

    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

    email_addresses = re.findall(
        email_pattern,
        investigation
    )

    unique_emails = list(dict.fromkeys(email_addresses))

    primary_user = None

    if unique_emails:
        primary_user = {
            "display_name": "Unknown",
            "email": unique_emails[0],
            "department": "Unknown",
            "manager": "Unknown",
            "role": "Unknown",
            "privilege_level": "Unknown",
            "risk_level": "Unknown",
            "source": "Investigation Narrative",
        }

    return {
        "primary_user": primary_user,
        "email_addresses": unique_emails,
        "identity_count": len(unique_emails),
    }