"""IP address utility helpers."""
from __future__ import annotations

import ipaddress
from typing import Iterable

# Well-known VPN provider IP ranges (sample – extend as needed)
_KNOWN_VPN_CIDRS: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("198.51.100.0/24"),   # example VPN provider
    ipaddress.IPv4Network("203.0.113.0/24"),     # example VPN provider
]

# ---------------------------------------------------------------------------
# IPs / CIDRs that must NEVER be auto-blocked.
# Blocking these would break DNS, routing, CDNs, or OS updates.
# ---------------------------------------------------------------------------
_NEVER_BLOCK_IPS: frozenset[str] = frozenset({
    # Cloudflare public DNS
    "1.1.1.1", "1.0.0.1",
    # Google public DNS
    "8.8.8.8", "8.8.4.4",
    # OpenDNS / Cisco
    "208.67.222.222", "208.67.220.220",
    # Quad9
    "9.9.9.9", "149.112.112.112",
    # Comodo
    "8.26.56.26", "8.20.247.20",
    # AdGuard
    "94.140.14.14", "94.140.15.15",
    # Level3 / CenturyLink
    "4.2.2.1", "4.2.2.2",
})

_NEVER_BLOCK_CIDRS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    # RFC 1918 private ranges — LAN devices are never VPN gateways
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    # Loopback
    ipaddress.IPv4Network("127.0.0.0/8"),
    # Link-local (APIPA)
    ipaddress.IPv4Network("169.254.0.0/16"),
    # IPv6 loopback / link-local
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fe80::/10"),
    # Carrier-grade NAT
    ipaddress.IPv4Network("100.64.0.0/10"),
    # Broadcast
    ipaddress.IPv4Network("255.255.255.255/32"),
    # Multicast
    ipaddress.IPv4Network("224.0.0.0/4"),
    # ── Google ────────────────────────────────────────────────────────────
    # Blocking Google IPs breaks HTTPS, YouTube, Gmail, Google CDN, etc.
    ipaddress.IPv4Network("142.250.0.0/15"),
    ipaddress.IPv4Network("172.217.0.0/16"),
    ipaddress.IPv4Network("216.58.0.0/16"),
    ipaddress.IPv4Network("192.178.0.0/15"),
    ipaddress.IPv4Network("74.125.0.0/16"),
    ipaddress.IPv4Network("216.239.32.0/19"),  # Google anycast
    ipaddress.IPv4Network("34.0.0.0/10"),      # Google Cloud broad range
    # ── Cloudflare ───────────────────────────────────────────────────────
    # Blocking Cloudflare IPs for DNS/infrastructure breaks the web.
    # For CDN-backed gambling/piracy/vpn sites we block per-category — see
    # is_safe_to_block_threat() below which allows Cloudflare blocks for those.
    ipaddress.IPv4Network("104.16.0.0/13"),
    ipaddress.IPv4Network("104.24.0.0/14"),
    ipaddress.IPv4Network("162.158.0.0/15"),
    ipaddress.IPv4Network("172.64.0.0/13"),
    ipaddress.IPv4Network("131.0.72.0/22"),
    # ── Microsoft / Azure ───────────────────────────────────────────────
    ipaddress.IPv4Network("20.33.0.0/16"),
    ipaddress.IPv4Network("20.34.0.0/15"),
    ipaddress.IPv4Network("20.36.0.0/14"),
    ipaddress.IPv4Network("20.40.0.0/13"),
    ipaddress.IPv4Network("52.96.0.0/12"),
    # Bing / Microsoft Search / Office 365 / Teams
    ipaddress.IPv4Network("13.64.0.0/11"),   # 13.64–95
    ipaddress.IPv4Network("13.96.0.0/13"),   # 13.96–103
    ipaddress.IPv4Network("13.104.0.0/14"),  # 13.104–107 — Bing is here
    ipaddress.IPv4Network("40.64.0.0/10"),   # 40.64–127 — broad Azure West
    ipaddress.IPv4Network("40.112.0.0/13"),  # 40.112–119
    ipaddress.IPv4Network("40.120.0.0/14"),
    ipaddress.IPv4Network("52.224.0.0/11"),
    ipaddress.IPv4Network("52.160.0.0/11"),
    ipaddress.IPv4Network("52.128.0.0/9"),   # broad Microsoft/Azure
    ipaddress.IPv4Network("23.96.0.0/13"),   # Azure West US
]

# Subset: CDN ranges that ARE blockable for gambling/piracy/vpn destinations
# (Cloudflare is heavily used by those sites; Google Cloud less so)
_CDN_BLOCKABLE_FOR_THREATS: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("104.16.0.0/13"),   # Cloudflare
    ipaddress.IPv4Network("104.24.0.0/14"),
    ipaddress.IPv4Network("162.158.0.0/15"),
    ipaddress.IPv4Network("172.64.0.0/13"),
    ipaddress.IPv4Network("131.0.72.0/22"),
    ipaddress.IPv4Network("34.0.0.0/10"),     # Google Cloud (gambling sites use it too)
]


def is_safe_to_block(ip: str) -> bool:
    """Return True if it is safe to auto-block this IP.

    Returns False for:
    - Known public DNS resolvers (1.1.1.1, 8.8.8.8, …)
    - Any private / loopback / link-local / multicast address
    - Broadcast / unspecified addresses
    - Google, Cloudflare, Microsoft CDN ranges
    """
    ip = ip.strip()
    if not ip or ip == "0.0.0.0":
        return False
    if ip in _NEVER_BLOCK_IPS:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
            return False
        if addr.is_unspecified or addr.is_reserved:
            return False
        for net in _NEVER_BLOCK_CIDRS:
            if addr in net:
                return False
    except ValueError:
        return False
    return True


# Threat categories where CDN IPs (Cloudflare, Google Cloud) should also be blocked
_CDN_BLOCK_CATEGORIES: frozenset[str] = frozenset({
    "gambling_access", "pirated_content", "vpn_usage", "tor_usage",
})


def is_safe_to_block_threat(ip: str, threat_type: str | None = None) -> bool:
    """Like is_safe_to_block(), but allows blocking CDN IPs when the threat
    category is gambling, piracy, or VPN — since those sites hide behind
    Cloudflare and the CDN IP is the ONLY blockable address we have.

    For all other threat types falls back to is_safe_to_block().
    """
    # Always pass the base checks first (private, loopback, etc.)
    ip_str = ip.strip()
    if not ip_str or ip_str == "0.0.0.0":
        return False
    if ip_str in _NEVER_BLOCK_IPS:   # never block DNS resolvers regardless
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
            return False
        if addr.is_unspecified or addr.is_reserved:
            return False

        # For known-bad categories: allow CDN IPs through
        if threat_type in _CDN_BLOCK_CATEGORIES:
            # Only skip the CDN ranges that we explicitly allow for threats;
            # still block Microsoft/Google ranges that are infrastructure-only
            cdn_ip = any(addr in net for net in _CDN_BLOCKABLE_FOR_THREATS)
            if not cdn_ip:
                # Not a CDN IP — apply full protection list
                for net in _NEVER_BLOCK_CIDRS:
                    if addr in net:
                        return False
            # CDN IP for a threat category — allow block
            return True

        # Standard categories: full protection list
        for net in _NEVER_BLOCK_CIDRS:
            if addr in net:
                return False
    except ValueError:
        return False
    return True


def is_monitor_only_ip(ip: str) -> bool:
    """Return True if this IP is a well-known public DNS resolver or infrastructure
    server that should NOT be treated as a network device.

    These IPs appear as src_ip in DNS *response* packets captured by the sniffer,
    but they are upstream servers — not devices on the monitored network.
    Treating them as devices causes false positives (e.g. '8.8.8.8 is doing gambling').
    """
    ip = ip.strip()
    # All entries in _NEVER_BLOCK_IPS are public resolvers, not LAN devices
    return ip in _NEVER_BLOCK_IPS


def normalize_ip(ip: str) -> str:
    """Strip whitespace and normalise an IP string."""
    return str(ipaddress.ip_address(ip.strip()))


def is_private_ip(ip: str) -> bool:
    """Return True if the IP is RFC 1918 / loopback / link-local."""
    try:
        return ipaddress.ip_address(ip.strip()).is_private
    except ValueError:
        return False


def is_known_vpn_ip(ip: str, extra_ranges: Iterable[str] | None = None) -> bool:
    """Check if *ip* falls inside a known VPN provider range."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False

    for net in _KNOWN_VPN_CIDRS:
        if addr in net:
            return True

    if extra_ranges:
        for cidr in extra_ranges:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue

    return False


def compute_vpn_ratio(dst_ips: Iterable[str]) -> float:
    """Return the fraction of *dst_ips* that hit known VPN ranges."""
    ips = list(dst_ips)
    if not ips:
        return 0.0
    hits = sum(1 for ip in ips if is_known_vpn_ip(ip))
    return hits / len(ips)
