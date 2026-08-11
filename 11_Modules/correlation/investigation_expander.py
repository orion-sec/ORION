from typing import Any

from models.signin_evidence import SignInEvidence


def _add_value(
    values: set[str],
    value: Any,
) -> None:
    if value is None:
        return

    cleaned = str(value).strip()

    if cleaned:
        values.add(cleaned)


def expand_investigation(
    environment_evidence: list[Any],
) -> dict[str, Any]:
    """
    Summarise related entities discovered by ORION's
    environment-search layer.

    This function does not merge incidents. It builds
    investigation-expansion context from related evidence.
    """

    users: set[str] = set()
    ips: set[str] = set()
    devices: set[str] = set()
    file_hashes: set[str] = set()
    domains: set[str] = set()
    urls: set[str] = set()

    for record in environment_evidence:
        if isinstance(record, SignInEvidence):
            _add_value(
                users,
                record.user_principal_name,
            )

            _add_value(
                ips,
                record.ip_address,
            )

            device_detail = record.device_detail

            if isinstance(device_detail, dict):
                for key in (
                    "displayName",
                    "deviceName",
                    "hostName",
                    "hostname",
                    "deviceId",
                ):
                    _add_value(
                        devices,
                        device_detail.get(key),
                    )

            continue

        if not isinstance(record, dict):
            continue

        for key in (
            "UserPrincipalName",
            "user_principal_name",
            "user",
            "AccountUpn",
        ):
            _add_value(
                users,
                record.get(key),
            )

        for key in (
            "IPAddress",
            "ip_address",
            "RemoteIP",
            "LocalIP",
            "SourceIP",
            "DestinationIP",
        ):
            _add_value(
                ips,
                record.get(key),
            )

        for key in (
            "DeviceName",
            "device_name",
            "HostName",
            "hostname",
            "Computer",
        ):
            _add_value(
                devices,
                record.get(key),
            )

        for key in (
            "SHA256",
            "SHA1",
            "MD5",
            "FileHash",
            "file_hash",
        ):
            _add_value(
                file_hashes,
                record.get(key),
            )

        for key in (
            "Domain",
            "domain",
            "DomainName",
            "dns_domain",
        ):
            _add_value(
                domains,
                record.get(key),
            )

        for key in (
            "RemoteUrl",
            "URL",
            "Url",
            "url",
            "RequestURL",
        ):
            _add_value(
                urls,
                record.get(key),
            )

    entities = {
        "users": sorted(users),
        "ips": sorted(ips),
        "devices": sorted(devices),
        "file_hashes": sorted(file_hashes),
        "domains": sorted(domains),
        "urls": sorted(urls),
    }

    affected_entity_count = sum(
        len(values)
        for values in entities.values()
    )

    return {
        "entities": entities,
        "affected_entity_count": affected_entity_count,
        "evidence_count": len(environment_evidence),
        "expanded": affected_entity_count > 0,
    }