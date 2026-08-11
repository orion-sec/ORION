from typing import Any


def assess_blast_radius(
    expansion: dict[str, Any],
) -> dict[str, Any]:
    """
    Produce a basic blast-radius summary from ORION's
    investigation-expansion context.
    """

    entities = expansion.get(
        "entities",
        {},
    )

    if not isinstance(entities, dict):
        entities = {}

    counts = {
        "users": len(entities.get("users", [])),
        "ips": len(entities.get("ips", [])),
        "devices": len(entities.get("devices", [])),
        "file_hashes": len(
            entities.get("file_hashes", [])
        ),
        "domains": len(
            entities.get("domains", [])
        ),
        "urls": len(entities.get("urls", [])),
    }

    affected_entity_count = sum(
        counts.values()
    )

    active_categories = sum(
        1
        for count in counts.values()
        if count > 0
    )

    if affected_entity_count == 0:
        scope = "None"

    elif active_categories == 1:
        scope = "Single-Entity-Type"

    else:
        scope = "Multi-Entity"

    return {
        "counts": counts,
        "affected_entity_count": affected_entity_count,
        "active_categories": active_categories,
        "scope": scope,
        "expanded": affected_entity_count > 0,
    }