"""Domain-level blocking via the Linux /etc/hosts file + nftables IP block.

For CDN-backed sites (1xbet, stake.com, 1337x.to, thepiratebay.org) that
rotate IPs constantly, we use a two-layer approach:
  1. /etc/hosts redirect  → 127.0.0.1  (covers system DNS)
  2. nftables IP block    → DROP        (covers direct-IP connections)
  3. DoH interception     → DROP port 443/853 to known DoH resolvers
     so browsers CANNOT bypass /etc/hosts via DNS-over-HTTPS.
"""
from __future__ import annotations

import logging
import os
import re
import sys
from pathlib import Path

logger = logging.getLogger("netscan.domain_blocker")

# ---------------------------------------------------------------------------
# Hosts file location
# ---------------------------------------------------------------------------
if sys.platform == "win32":
    HOSTS_FILE = Path(r"C:\Windows\System32\drivers\etc\hosts")
else:
    HOSTS_FILE = Path("/etc/hosts")

_NETSCAN_START = "# ── NetScan IPS ────────────────────────────────"
_NETSCAN_END   = "# ── NetScan IPS END ────────────────────────────"

# Domains that must never be written to the hosts file
_NEVER_BLOCK_DOMAINS: frozenset[str] = frozenset({
    "google.com", "googleapis.com", "gstatic.com",
    "microsoft.com", "windows.com", "windowsupdate.com",
    "apple.com", "icloud.com",
    "cloudflare.com", "cloudflare-dns.com",
    "github.com", "githubusercontent.com",
    "youtube.com", "ytimg.com",
    "localhost",
})


def _is_safe_domain(domain: str) -> bool:
    """Return True if the domain is safe to block via hosts file."""
    d = domain.strip().lower()
    if not d or d.startswith("."):
        return False
    # Never block domains that contain a protected root
    for protected in _NEVER_BLOCK_DOMAINS:
        if d == protected or d.endswith("." + protected):
            return False
    return True


def _read_hosts() -> str:
    try:
        return HOSTS_FILE.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        logger.error("Cannot read hosts file: %s", exc)
        return ""


def _write_hosts(content: str) -> bool:
    try:
        HOSTS_FILE.write_text(content, encoding="utf-8")
        return True
    except PermissionError:
        logger.error(
            "Permission denied writing /etc/hosts. "
            "Run NetScan as root: sudo venv/bin/python3 cli.py live"
        )
        return False
    except Exception as exc:
        logger.error("Failed to write hosts file: %s", exc)
        return False


def _get_managed_domains() -> set[str]:
    """Return the set of domains currently managed by NetScan."""
    content = _read_hosts()
    in_block = False
    domains: set[str] = set()
    for line in content.splitlines():
        if _NETSCAN_START in line:
            in_block = True
            continue
        if _NETSCAN_END in line:
            break
        if in_block:
            m = re.match(r"^127\.0\.0\.1\s+(\S+)", line)
            if m:
                domains.add(m.group(1).lower())
    return domains


# Cache so we only fire DoH-block once per process lifetime (idempotent nft rules anyway)
_doh_blocked_once: bool = False


def _ensure_doh_blocked() -> None:
    """Fire DoH interception the first time a domain is blocked.

    After this, nft rules persist until NetScan stops or unblock_doh() is called.
    """
    global _doh_blocked_once
    if _doh_blocked_once:
        return
    try:
        from app.blocking.firewall import block_doh
        if block_doh():
            _doh_blocked_once = True
    except Exception as exc:
        logger.debug("DoH block call failed: %s", exc)


def _block_domain_ip(domain: str, reason: str) -> None:
    """Resolve *domain* and block its IP(s) via nftables/iptables.

    This covers direct-IP connections that bypass /etc/hosts entirely,
    and covers cases where the browser has a cached DNS response.
    Uses threat-aware CDN blocking so Cloudflare IPs are blocked too.
    """
    import socket
    try:
        # getaddrinfo returns all IPs (handles both A and AAAA)
        results = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
        ips = list({r[4][0] for r in results})
    except Exception:
        return

    if not ips:
        return

    try:
        from app.blocking.firewall import block_ips
        from app.utils.ip_utils import is_safe_to_block_threat
        # Use gambling_access threat type as the generic CDN-override category
        blockable = [ip for ip in ips if is_safe_to_block_threat(ip, "gambling_access")]
        if blockable:
            block_ips(blockable, f"Domain IP block: {domain} [{reason}]",
                      threat_type="gambling_access")
            logger.warning(
                "\ud83d\udeab DOMAIN IP BLOCKED \u2014 %s resolved to %s \u2192 nftables DROP",
                domain, blockable,
            )
    except Exception as exc:
        logger.debug("Domain IP block failed for %s: %s", domain, exc)


def block_domain(domain: str, reason: str = "") -> bool:
    """Add *domain* → 127.0.0.1 to the hosts file AND block its resolved IP
    via nftables/iptables AND intercept DoH so browsers cannot bypass /etc/hosts.

    Returns True if the domain was added (or was already present).
    """
    domain = domain.strip().lower()
    if not _is_safe_domain(domain):
        logger.debug("Domain block skipped (protected): %s", domain)
        return False

    content = _read_hosts()

    # Build (or extend) the NetScan block
    if _NETSCAN_START not in content:
        # First entry — append a clean section
        entry = (
            f"\n{_NETSCAN_START}\n"
            f"127.0.0.1 {domain}  # {reason}\n"
            f"{_NETSCAN_END}\n"
        )
        new_content = content.rstrip() + entry
    else:
        # Already have a block — check if domain is already there
        pattern = re.compile(
            rf"(127\.0\.0\.1\s+{re.escape(domain)}(\s|$))", re.IGNORECASE | re.MULTILINE
        )
        if pattern.search(content):
            logger.debug("Domain already in hosts file: %s", domain)
            # Still ensure DoH is intercepted even if domain was already blocked
            _ensure_doh_blocked()
            return True

        # Insert before the END marker
        new_entry = f"127.0.0.1 {domain}  # {reason}\n"
        new_content = content.replace(
            _NETSCAN_END,
            new_entry + _NETSCAN_END,
        )

    if _write_hosts(new_content):
        logger.warning("🚫 DOMAIN BLOCKED (hosts) — %s → 127.0.0.1  [%s]", domain, reason)
        # Block DoH immediately so browsers can't bypass /etc/hosts
        _ensure_doh_blocked()
        # Also block the resolved IP via nftables for direct-IP connections
        _block_domain_ip(domain, reason)
        return True
    return False


def block_domains(domains: list[str], reason: str = "") -> int:
    """Block multiple domains. Returns count of new entries added."""
    count = 0
    for d in set(domains):
        if block_domain(d, reason):
            count += 1
    return count


def unblock_domain(domain: str) -> bool:
    """Remove *domain* from the NetScan hosts block."""
    domain = domain.strip().lower()
    content = _read_hosts()
    pattern = re.compile(
        rf"^127\.0\.0\.1\s+{re.escape(domain)}\s*.*$\n?",
        re.IGNORECASE | re.MULTILINE,
    )
    new_content = pattern.sub("", content)
    if new_content == content:
        logger.debug("Domain not found in hosts file: %s", domain)
        return False
    if _write_hosts(new_content):
        logger.warning("✅ DOMAIN UNBLOCKED (hosts) — %s", domain)
        return True
    return False


def unblock_all_netscan_domains() -> int:
    """Remove the entire NetScan-managed block from the hosts file."""
    content = _read_hosts()
    pattern = re.compile(
        rf"{re.escape(_NETSCAN_START)}.*?{re.escape(_NETSCAN_END)}\n?",
        re.DOTALL,
    )
    new_content = pattern.sub("", content)
    removed = len(_get_managed_domains())
    if _write_hosts(new_content):
        logger.warning("✅ Removed all %d NetScan domain blocks from hosts file.", removed)
    return removed


def list_blocked_domains() -> list[str]:
    """Return sorted list of domains currently blocked by NetScan."""
    return sorted(_get_managed_domains())
