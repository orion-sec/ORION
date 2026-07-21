def enrich_identity(identity):
    """
    Enrich a primary identity with business context.

    This initial version uses placeholder values.
    Future versions will retrieve live information from
    Microsoft Graph, Active Directory, CMDB and other
    enterprise data sources.
    """

    primary_user = identity.get("primary_user")

    if primary_user is None:
        return None

    enriched_identity = primary_user.copy()

    enriched_identity.update(
        {
            "job_title": "Unknown",
            "country": "Unknown",
            "office": "Unknown",
            "account_type": "Employee",
            "vip": False,
            "criticality": "Medium",
            "device_count": 0,
            "identity_source": "Placeholder",
        }
    )

    return enriched_identity