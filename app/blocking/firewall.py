"""Linux firewall integration for NetScan.

Supports two backends (auto-detected at import time):
  1. nftables  — preferred on Debian 12 / Kali; uses the ``nft`` binary.
  2. iptables  — fallback for older kernels / distros.

Rules are managed in a dedicated NetScan table/chain so they are easy to
list and flush without touching other firewall policy.

Requires: process running as root (uid 0) OR ``CAP_NET_ADMIN`` capability.
"""
from __future__ import annotations

import logging
import os
import subprocess
import shutil
from datetime import datetime
from typing import Iterable

from app.utils.ip_utils import is_safe_to_block

logger = logging.getLogger("netscan.firewall")


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------

def _cmd_exists(name: str) -> bool:
    return shutil.which(name) is not None


# Evaluated once at import time
_USE_NFTABLES: bool = _cmd_exists("nft")
_USE_IPTABLES: bool = not _USE_NFTABLES and _cmd_exists("iptables")

if _USE_NFTABLES:
    logger.debug("Firewall backend: nftables (nft)")
elif _USE_IPTABLES:
    logger.debug("Firewall backend: iptables")
else:
    logger.warning("No firewall backend found (nft/iptables). IP blocking disabled.")


# ---------------------------------------------------------------------------
# Privilege check — evaluated ONCE at import time
# ---------------------------------------------------------------------------

def _has_privileges() -> bool:
    """Return True if the process can modify OS firewall rules."""
    try:
        return os.getuid() == 0
    except AttributeError:
        return False


_PRIVILEGES_OK: bool = _has_privileges()

if not _PRIVILEGES_OK:
    logger.warning(
        "⚠  NetScan is NOT running as root. "
        "Automatic IP blocking is DISABLED. Detection/Alert still works. "
        "To enable blocking: run with  sudo  or grant CAP_NET_ADMIN:\n"
        "    sudo setcap cap_net_admin,cap_net_raw+eip $(which python3)"
    )


def is_blocking_enabled() -> bool:
    """Return True if the system has privileges to apply firewall rules."""
    return _PRIVILEGES_OK and (_USE_NFTABLES or _USE_IPTABLES)


# ---------------------------------------------------------------------------
# nftables helpers
# ---------------------------------------------------------------------------

_NFT_TABLE  = "inet netscan"
_NFT_CHAIN  = "block"


def _nft(*args: str, check: bool = False) -> subprocess.CompletedProcess:
    """Run ``nft`` with the given arguments."""
    return subprocess.run(
        ["nft", *args],
        capture_output=True,
        text=True,
        check=check,
    )


def _ensure_nft_table() -> bool:
    """Create the netscan table + block chain if they don't exist."""
    try:
        # Check if table exists
        r = _nft("list", "table", "inet", "netscan")
        if r.returncode != 0:
            # Create table
            _nft("add", "table", "inet", "netscan", check=True)
            # Create chain with type filter — hook both input and output
            _nft(
                "add", "chain", "inet", "netscan", "block",
                "{", "type", "filter", "hook", "input", "priority", "0", ";",
                "policy", "accept", ";", "}",
                check=True,
            )
            _nft(
                "add", "chain", "inet", "netscan", "block_out",
                "{", "type", "filter", "hook", "output", "priority", "0", ";",
                "policy", "accept", ";", "}",
                check=True,
            )
        return True
    except Exception as exc:
        logger.error("Failed to create nftables table/chain: %s", exc)
        return False


def _nft_add_rules(ip_address: str, reason: str) -> bool:
    """Add nftables DROP rules for *ip_address* (input + output)."""
    try:
        if not _ensure_nft_table():
            return False

        comment = reason[:60].replace('"', "")  # nft comment limit

        # Check INPUT rule already exists
        r = _nft("list", "table", "inet", "netscan")
        if ip_address in (r.stdout or ""):
            logger.debug("nftables rule already exists for %s", ip_address)
            return True

        # Add INPUT drop
        _nft(
            "add", "rule", "inet", "netscan", "block",
            "ip", "saddr", ip_address, "drop",
            "comment", f'"{comment}"',
        )
        # Add OUTPUT drop
        _nft(
            "add", "rule", "inet", "netscan", "block_out",
            "ip", "daddr", ip_address, "drop",
            "comment", f'"{comment}"',
        )
        return True
    except Exception as exc:
        logger.error("nftables add error for %s: %s", ip_address, exc)
        return False


def _nft_remove_rules(ip_address: str) -> bool:
    """Remove all nftables rules matching *ip_address*."""
    try:
        # Flush all rules in netscan chains that match this IP
        # The safest approach: list rules with handles, then delete matching ones
        for chain in ("block", "block_out"):
            r = _nft("-a", "list", "chain", "inet", "netscan", chain)
            if r.returncode != 0:
                continue
            for line in r.stdout.splitlines():
                if ip_address in line and "handle" in line:
                    # Extract handle number
                    parts = line.strip().split()
                    try:
                        handle_idx = parts.index("handle") + 1
                        handle = parts[handle_idx]
                        _nft("delete", "rule", "inet", "netscan", chain, "handle", handle)
                    except (ValueError, IndexError):
                        pass
        return True
    except Exception as exc:
        logger.error("nftables remove error for %s: %s", ip_address, exc)
        return False


# ---------------------------------------------------------------------------
# iptables helpers
# ---------------------------------------------------------------------------

def _ipt(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["iptables", *args],
        capture_output=True,
        text=True,
    )


def _iptables_add_rules(ip_address: str, reason: str) -> bool:
    """Add iptables INPUT + OUTPUT DROP rules for *ip_address*."""
    try:
        comment = reason[:255].replace("'", "")
        for chain, flag in [("INPUT", "-s"), ("OUTPUT", "-d")]:
            # -C checks existence (exit 0 = exists, exit 1 = missing)
            check = _ipt("-C", chain, flag, ip_address, "-j", "DROP")
            if check.returncode != 0:
                add = _ipt(
                    "-A", chain, flag, ip_address,
                    "-j", "DROP",
                    "-m", "comment", "--comment", comment,
                )
                if add.returncode != 0:
                    logger.error(
                        "iptables add failed (%s %s): %s",
                        chain, ip_address, add.stderr.strip(),
                    )
                    return False
        return True
    except Exception as exc:
        logger.error("iptables add error for %s: %s", ip_address, exc)
        return False


def _iptables_remove_rules(ip_address: str) -> bool:
    """Remove iptables DROP rules for *ip_address*."""
    try:
        for chain, flag in [("INPUT", "-s"), ("OUTPUT", "-d")]:
            # Keep deleting until the rule no longer exists
            while True:
                r = _ipt("-D", chain, flag, ip_address, "-j", "DROP")
                if r.returncode != 0:
                    break  # Rule gone (or never existed)
        return True
    except Exception as exc:
        logger.error("iptables remove error for %s: %s", ip_address, exc)
        return False


# ---------------------------------------------------------------------------
# DNS-over-HTTPS (DoH) interception
# ---------------------------------------------------------------------------
# Modern browsers (Chrome, Firefox) use DoH by default, which bypasses
# /etc/hosts entirely and lets users reach gambling/blocked sites.
# Blocking port 443 to known DoH resolvers forces browsers to fall back
# to system DNS where /etc/hosts and our blocks apply.

_DOH_RESOLVERS: list[str] = [
    # Cloudflare DoH
    "1.1.1.1", "1.0.0.1",
    "104.16.248.249", "104.16.249.249",
    # Google DoH
    "8.8.8.8", "8.8.4.4",
    "142.250.0.0/15",  # google dns over https anycast
    # NextDNS
    "45.90.28.0/23",
    # Quad9
    "9.9.9.9", "149.112.112.112",
    # OpenDNS
    "208.67.222.222", "208.67.220.220",
]


def block_doh() -> bool:
    """Block DNS-over-HTTPS to force browsers to use system DNS.

    Drops outbound TCP/UDP port 443 AND port 853 (DoT) to known DoH/DoT
    resolvers so the browser cannot bypass /etc/hosts.

    Returns True if rules were applied.
    """
    if not _PRIVILEGES_OK:
        logger.warning("Cannot block DoH — not running as root.")
        return False

    resolver_ips = [r for r in _DOH_RESOLVERS if "/" not in r]  # plain IPs only

    success = True
    for ip in resolver_ips:
        if _USE_NFTABLES:
            # Block TCP/UDP 443 (DoH) and 853 (DoT) outbound to resolver
            for proto in ("tcp", "udp"):
                for port in ("443", "853"):
                    try:
                        r = _nft("list", "table", "inet", "netscan")
                        rule_exists = ip in (r.stdout or "") and port in (r.stdout or "")
                        if not rule_exists:
                            _ensure_nft_table()
                            _nft(
                                "add", "rule", "inet", "netscan", "block_out",
                                "ip", "daddr", ip, proto, "dport", port,
                                "drop", "comment", f'"DoH-block-{ip}"',
                            )
                    except Exception as exc:
                        logger.error("nft DoH block error %s:%s: %s", ip, port, exc)
                        success = False
        elif _USE_IPTABLES:
            for proto in ("tcp", "udp"):
                for port in ("443", "853"):
                    check = _ipt("-C", "OUTPUT", "-d", ip,
                                 "-p", proto, "--dport", port, "-j", "DROP")
                    if check.returncode != 0:
                        add = _ipt("-A", "OUTPUT", "-d", ip,
                                   "-p", proto, "--dport", port, "-j", "DROP",
                                   "-m", "comment", "--comment", "netscan-doh-block")
                        if add.returncode != 0:
                            success = False

    if success:
        logger.warning(
            "🔒 DoH INTERCEPTION ACTIVE — browsers will use system DNS "
            "(where /etc/hosts domain blocks apply). Blocked %d resolver IPs.",
            len(resolver_ips),
        )
    return success


def unblock_doh() -> bool:
    """Remove DoH interception rules."""
    if not _PRIVILEGES_OK:
        return False

    resolver_ips = [r for r in _DOH_RESOLVERS if "/" not in r]
    for ip in resolver_ips:
        if _USE_NFTABLES:
            _nft_remove_rules(ip)
        elif _USE_IPTABLES:
            for proto in ("tcp", "udp"):
                for port in ("443", "853"):
                    while True:
                        r = _ipt("-D", "OUTPUT", "-d", ip,
                                 "-p", proto, "--dport", port, "-j", "DROP")
                        if r.returncode != 0:
                            break
    logger.warning("✅ DoH interception removed.")
    return True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def block_ip(
    ip_address: str,
    reason: str = "High Risk Detection",
    threat_type: str | None = None,
    risk_score: float = 0.0,
    session=None,
) -> bool:
    """
    Block *ip_address* at the OS firewall layer and record it in the DB.

    Uses nftables if available, falls back to iptables.
    Requires root privileges (uid 0) or CAP_NET_ADMIN.

    session — optional SQLAlchemy Session for DB persistence.
    Returns True if the OS rule was applied (or already existed).
    """
    if not _PRIVILEGES_OK:
        logger.debug("Block skipped (no root): %s", ip_address)
        return False

    if not is_safe_to_block(ip_address):
        logger.warning(
            "⛔ Block skipped — %s is a protected/private IP and will not be auto-blocked.",
            ip_address,
        )
        return False

    # ── Prevent duplicate blocking (saves OS calls and rule explosion) ──
    from app.db.models import BlockedIP
    if session is not None:
        if session.query(BlockedIP).filter_by(ip_address=ip_address, status="blocked").first():
            logger.debug("IP %s is already blocked in DB (skipping firewall command)", ip_address)
            return True
    else:
        from app.db.db_session import SessionLocal
        with SessionLocal() as s:
            if s.query(BlockedIP).filter_by(ip_address=ip_address, status="blocked").first():
                logger.debug("IP %s is already blocked in DB (skipping firewall command)", ip_address)
                return True

    safe_reason = reason.replace("'", "").replace('"', "")

    if _USE_NFTABLES:
        success = _nft_add_rules(ip_address, safe_reason)
    elif _USE_IPTABLES:
        success = _iptables_add_rules(ip_address, safe_reason)
    else:
        logger.error("No firewall backend available — cannot block %s", ip_address)
        return False

    if success:
        logger.warning(
            "🚫 FIREWALL BLOCK APPLIED — %s blocked. Reason: %s", ip_address, safe_reason
        )
        _persist_block(ip_address, reason, threat_type, risk_score, session=session)
    else:
        logger.error("Firewall block FAILED for %s — OS command error.", ip_address)

    return success


def block_ips(
    ip_addresses: Iterable[str],
    reason: str = "High Risk Detection",
    threat_type: str | None = None,
    risk_score: float = 0.0,
    session=None,
) -> int:
    """Block multiple IPs at once. Returns count of successful blocks."""
    count = 0
    for ip in set(ip_addresses):
        if block_ip(ip, reason, threat_type, risk_score, session=session):
            count += 1
    return count


def unblock_ip(ip_address: str, *, note: str = "", unblocked_by: str = "admin") -> bool:
    """Remove OS firewall block rules and mark DB record as unblocked."""
    if not _PRIVILEGES_OK:
        return False

    if _USE_NFTABLES:
        success = _nft_remove_rules(ip_address)
    elif _USE_IPTABLES:
        success = _iptables_remove_rules(ip_address)
    else:
        logger.error("No firewall backend available — cannot unblock %s", ip_address)
        return False

    _mark_unblocked(ip_address, note=note, unblocked_by=unblocked_by)

    if success:
        logger.warning("✅ FIREWALL UNBLOCK — %s unblocked by %s.", ip_address, unblocked_by)
    else:
        logger.error("Failed to remove firewall rule for %s.", ip_address)
    return success


# ---------------------------------------------------------------------------
# DB persistence (internal helpers)
# ---------------------------------------------------------------------------

def _persist_block(
    ip_address: str,
    reason: str,
    threat_type: str | None,
    risk_score: float,
    session=None,
) -> None:
    """Record the block in the blocked_ips table."""
    try:
        from app.db.models import BlockedIP

        def _do_insert(s):
            existing = (
                s.query(BlockedIP)
                .filter(BlockedIP.ip_address == ip_address, BlockedIP.status == "blocked")
                .first()
            )
            if not existing:
                s.add(BlockedIP(
                    ip_address=ip_address,
                    reason=reason,
                    threat_type=threat_type,
                    risk_score=risk_score,
                    blocked_by="auto",
                    status="blocked",
                    blocked_at=datetime.utcnow(),
                ))

        if session is not None:
            _do_insert(session)
        else:
            from app.db.db_session import SessionLocal
            _session = SessionLocal()
            try:
                _do_insert(_session)
                _session.commit()
            except Exception as exc:
                _session.rollback()
                logger.error("Failed to persist block record for %s: %s", ip_address, exc)
            finally:
                _session.close()
    except Exception as exc:
        logger.error("DB import error in _persist_block: %s", exc)


def _mark_unblocked(ip_address: str, *, note: str, unblocked_by: str) -> None:
    """Update the most recent active block record to 'unblocked'."""
    try:
        from app.db.db_session import SessionLocal
        from app.db.models import BlockedIP
        session = SessionLocal()
        try:
            record = (
                session.query(BlockedIP)
                .filter(BlockedIP.ip_address == ip_address, BlockedIP.status == "blocked")
                .order_by(BlockedIP.blocked_at.desc())
                .first()
            )
            if record:
                record.status       = "unblocked"
                record.unblocked_at = datetime.utcnow()
                record.unblocked_by = unblocked_by
                record.unblock_note = note
                session.commit()
        except Exception as exc:
            session.rollback()
            logger.error("Failed to update block record for %s: %s", ip_address, exc)
        finally:
            session.close()
    except Exception as exc:
        logger.error("DB import error in _mark_unblocked: %s", exc)
