"""
Mock IP enrichment: compute country/ASN metadata for a src_ip at ingest time.

Enrichment is computed once and stored immutably in Event.enrichment (JSON).
To swap in a real GeoIP backend (e.g. MaxMind GeoLite2), replace enrich_ip()
with a function that calls geoip2.database.Reader — the column schema is the same.
"""

import hashlib
import ipaddress

_COUNTRIES = [
    "United States", "China", "Russia", "Germany", "Netherlands",
    "United Kingdom", "France", "Brazil", "India", "Canada",
    "South Korea", "Japan", "Sweden", "Singapore", "Australia",
    "Ukraine", "Romania", "Poland", "Czech Republic", "Bulgaria",
]

_ASNS = [
    (13335, "Cloudflare, Inc."),
    (15169, "Google LLC"),
    (8075,  "Microsoft Corporation"),
    (16509, "Amazon.com, Inc."),
    (4134,  "China Telecom"),
    (3462,  "Chunghwa Telecom"),
    (20473, "AS-CHOOPA (Vultr)"),
    (14061, "DigitalOcean, LLC"),
    (16276, "OVH SAS"),
    (24940, "Hetzner Online GmbH"),
    (9002,  "RETN Limited"),
    (1273,  "CW Broadband"),
    (5483,  "Magyar Telekom"),
    (12322, "Free SAS"),
    (3209,  "Vodafone GmbH"),
    (6799,  "OTE S.A."),
    (39572, "DataWagon LLC"),
    (8708,  "RCS & RDS S.A."),
    (44566, "Informica Ltd."),
    (32590, "Valve Corporation"),
]

_PRIVATE = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
)
_PRIVATE_NETS = [ipaddress.ip_network(n) for n in _PRIVATE]


def enrich_ip(ip: str | None) -> dict | None:
    """Return {country, asn, asn_org, is_private} for ip, or None if ip is absent.

    Private/loopback/link-local addresses return is_private=True with null fields.
    Public addresses get deterministic fake values derived from sha256(ip) — same IP
    always yields the same country and ASN, so results are stable across re-ingests.
    """
    if not ip:
        return None

    try:
        addr = ipaddress.ip_address(ip)
        is_private = addr.is_private or addr.is_loopback or addr.is_link_local
        if not is_private:
            is_private = any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return {"is_private": True, "country": None, "asn": None, "asn_org": None}

    if is_private:
        return {"is_private": True, "country": None, "asn": None, "asn_org": None}

    digest = hashlib.sha256(ip.encode()).digest()
    country = _COUNTRIES[digest[0] % len(_COUNTRIES)]
    asn_num, asn_org = _ASNS[digest[1] % len(_ASNS)]
    return {"is_private": False, "country": country, "asn": asn_num, "asn_org": asn_org}
