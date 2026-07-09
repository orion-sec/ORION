import ipaddress


def enrich_ip(ip):
    ip_object = ipaddress.ip_address(ip)

    return {
        "ip": ip,
        "version": f"IPv{ip_object.version}",
        "is_private": ip_object.is_private,
        "is_global": ip_object.is_global,
        "is_loopback": ip_object.is_loopback,
        "is_multicast": ip_object.is_multicast,
        "is_reserved": ip_object.is_reserved
    }


def enrich_ips(ip_list):
    enriched_ips = []

    for ip in ip_list:
        enriched_ips.append(enrich_ip(ip))

    return enriched_ips