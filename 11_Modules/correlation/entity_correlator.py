from collections import defaultdict
from typing import Any

from models.security_incident import SecurityIncident
from models.signin_evidence import SignInEvidence


def _clean(value: Any) -> str:
    """
    Convert an entity value into a normalised comparison string.
    """

    if value is None:
        return ""

    return str(value).strip()


def _add_entity(
    entities: dict[str, set[str]],
    entity_type: str,
    value: Any,
) -> None:
    """
    Add a non-empty entity value to the normalised entity map.
    """

    cleaned = _clean(value)

    if not cleaned:
        return

    entities[entity_type].add(cleaned)


def _extract_from_signin(
    event: SignInEvidence,
    entities: dict[str, set[str]],
) -> None:
    """
    Extract correlation entities from Microsoft Entra
    sign-in evidence.
    """

    _add_entity(
        entities,
        "user",
        event.user_principal_name,
    )

    _add_entity(
        entities,
        "ip",
        event.ip_address,
    )

    device_detail = event.device_detail

    if not isinstance(device_detail, dict):
        return

    for key in (
        "deviceId",
        "displayName",
        "deviceName",
        "hostName",
        "hostname",
    ):
        _add_entity(
            entities,
            "device",
            device_detail.get(key),
        )


def _extract_from_sentinel_entity(
    entity: dict[str, Any],
    entities: dict[str, set[str]],
) -> None:
    """
    Extract supported correlation entities from a raw
    Microsoft Sentinel entity dictionary.
    """

    properties = entity.get("properties", {})

    if not isinstance(properties, dict):
        properties = {}

    #
    # User / identity candidates.
    #
    additional_data = properties.get(
        "additionalData",
        {},
    )

    if not isinstance(additional_data, dict):
        additional_data = {}

    for key in (
        "userPrincipalName",
        "email",
        "mail",
    ):
        value = properties.get(key)

        if value:
            _add_entity(
                entities,
                "user",
                value,
            )

    #
    # Microsoft Sentinel frequently places the full UPN
    # inside additionalData.
    #
    for key in (
        "UserPrincipalName",
        "userPrincipalName",
    ):
        value = additional_data.get(key)

        if value:
            _add_entity(
                entities,
                "user",
                value,
            )

    #
    # Reconstruct a UPN where Sentinel provides the account
    # name and suffix separately.
    #
    account_name = _clean(
        properties.get("accountName")
    )

    upn_suffix = _clean(
        properties.get("upnSuffix")
    )

    if (
        account_name
        and upn_suffix
        and "@" not in account_name
    ):
        _add_entity(
            entities,
            "user",
            f"{account_name}@{upn_suffix}",
        )

    elif "@" in account_name:
        _add_entity(
            entities,
            "user",
            account_name,
        )

    #
    # IP candidates.
    #
    for key in (
        "address",
        "ipAddress",
        "ip",
    ):
        value = properties.get(key)

        if not value:
            continue

        cleaned = _clean(value)

        if cleaned and "@" not in cleaned:
            _add_entity(
                entities,
                "ip",
                cleaned,
            )

    #
    # Device / host candidates.
    #
    for key in (
        "hostName",
        "hostname",
        "deviceName",
        "displayName",
        "computer",
        "netBiosName",
        "dnsDomain",
    ):
        _add_entity(
            entities,
            "device",
            properties.get(key),
        )

    for key in (
        "hash",
        "hashValue",
        "file_hash",
        "md5",
        "sha1",
        "sha256",
        "MD5",
        "SHA1",
        "SHA256",
    ):
        _add_entity(
            entities,
            "file_hash",
            properties.get(key),
        )


def _extract_from_security_incident(
    incident: SecurityIncident,
    entities: dict[str, set[str]],
) -> None:
    """
    Extract correlation entities from a normalised ORION
    SecurityIncident.
    """

    for entity in incident.entities:
        if not isinstance(entity, dict):
            continue

        _extract_from_sentinel_entity(
            entity,
            entities,
        )


def extract_correlation_entities(
    evidence_records: list[Any],
) -> dict[str, list[str]]:
    """
    Extract supported correlation entities from ORION
    investigation evidence.

    Current supported entity types:

    - user
    - ip
    - device
    - file_hash
    - domain
    """

    entities: dict[str, set[str]] = defaultdict(set)

    for record in evidence_records:
        if isinstance(record, SignInEvidence):
            _extract_from_signin(
                record,
                entities,
            )
            continue

        if isinstance(record, SecurityIncident):
            _extract_from_security_incident(
                record,
                entities,
            )
            continue

        if not isinstance(record, dict):
            continue

        #
        # Generic ORION dictionary evidence.
        #
        for key in (
            "user",
            "user_principal_name",
            "email",
            "affected_user",
        ):
            _add_entity(
                entities,
                "user",
                record.get(key),
            )

        for key in (
            "ip",
            "ip_address",
            "source_ip",
            "destination_ip",
        ):
            _add_entity(
                entities,
                "ip",
                record.get(key),
            )

        for key in (
            "host",
            "hostname",
            "device",
            "device_name",
            "affected_host",
        ):
            _add_entity(
                entities,
                "device",
                record.get(key),
            )

        for key in (
            "hash",
            "file_hash",
            "md5",
            "sha1",
            "sha256",
            "MD5",
            "SHA1",
            "SHA256",
        ):
            _add_entity(
                entities,
                "file_hash",
                record.get(key),
            )

        for key in (
            "domain",
            "domain_name",
            "hostname_domain",
            "dns_domain",
            "fqdn",
        ):
            _add_entity(
                entities,
                "domain",
                record.get(key),
            )

        for key in (
            "url",
            "uri",
            "remote_url",
            "remoteUrl",
            "request_url",
            "requestUrl",
        ):
            _add_entity(
                entities,
                "url",
                record.get(key),
            )

    return {
        entity_type: sorted(values)
        for entity_type, values in entities.items()
        if values
    }


def correlate_entities(
    evidence_records: list[Any],
) -> dict[str, Any]:
    """
    Produce deterministic entity-correlation context for one
    ORION investigation.

    This function does not merge investigations.

    It identifies entities that can later be used to search
    the wider customer environment for related activity.
    """

    entities = extract_correlation_entities(
        evidence_records
    )

    correlation_keys = []

    for entity_type, values in entities.items():
        for value in values:
            correlation_keys.append(
                {
                    "type": entity_type,
                    "value": value,
                }
            )

    return {
        "entities": entities,
        "correlation_keys": correlation_keys,
        "entity_count": sum(
            len(values)
            for values in entities.values()
        ),
        "search_required": bool(correlation_keys),
    }