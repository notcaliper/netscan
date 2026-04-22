"""Real-time DNS fast-path for NetScan.

Runs classify_domain() directly inside the Scapy packet callback — before
the sliding window even completes. Detection latency drops from ~3–5 s to
< 100 ms for any DNS-classified threat (gambling, piracy, VPN, torrent).

Architecture:
  PacketSource callback
      └── RealTimeDNSInterceptor.on_packet(pkt)
              └── classify_domain()  [in-memory, ~0 ms]
                      └── if restricted → block_domain() + block_doh() immediately
                              └── notify pipeline (deduplicated)
"""
from __future__ import annotations

import logging
import threading
from typing import Callable

logger = logging.getLogger("netscan.dns_fastpath")


class RealTimeDNSInterceptor:
    """Intercepts DNS queries at packet-capture time and acts immediately.

    Shared singleton — attach to the LiveCaptureService or PacketSource.
    Thread-safe via a seen-domains cache (dedup within the current session).
    """

    def __init__(self, dns_intel, notifier, alert_callback: Callable | None = None):
        """
        dns_intel      — DNSIntelligenceModule instance (already initialised)
        notifier       — Notifier instance
        alert_callback — optional callable(src_ip, domain, result) for extra handling
        """
        self._intel = dns_intel
        self._notifier = notifier
        self._alert_cb = alert_callback
        self._seen: set[tuple[str, str]] = set()   # (src_ip, domain) dedup
        self._lock = threading.Lock()

    def on_packet(self, src_ip: str, dns_query: str | None) -> None:
        """Call this for every captured packet. Runs in the sniffer thread.

        If the packet carries a DNS query for a restricted domain, blocks it
        immediately — no window wait.
        """
        if not dns_query:
            return

        key = (src_ip, dns_query.lower())
        with self._lock:
            if key in self._seen:
                return          # already handled this session
            self._seen.add(key)

        # classify_domain is pure in-memory — ~0 ms, safe to call from sniffer thread
        try:
            classification = self._intel.classify_domain(dns_query)
        except Exception as exc:
            logger.debug("Fast-path classify error for %s: %s", dns_query, exc)
            return

        if classification["category"] == "normal":
            return

        category  = classification["category"]
        risk      = classification["risk_score"]
        reason    = classification["reason"]

        logger.warning(
            "⚡ FAST-PATH DNS BLOCK — %s queried %s [%s risk=%.2f] %s",
            src_ip, dns_query, category.upper(), risk, reason,
        )

        # Act immediately — these are all fast local operations
        self._block_domain_now(src_ip, dns_query, category, reason, risk)

        # Fire alert notification (non-blocking)
        try:
            severity = "critical" if risk >= 0.80 else "high"
            title = f"⚡ Fast-Path DNS Block: {category.upper()}"
            summary = (
                f"Device {src_ip} queried restricted domain '{dns_query}'. "
                f"Blocked immediately. Reason: {reason}"
            )
            self._notifier.notify(title, summary, severity)
        except Exception as exc:
            logger.debug("Fast-path notify error: %s", exc)

        if self._alert_cb:
            try:
                self._alert_cb(src_ip, dns_query, classification)
            except Exception as exc:
                logger.debug("Fast-path alert_callback error: %s", exc)

    def _block_domain_now(
        self, src_ip: str, domain: str, category: str, reason: str, risk: float
    ) -> None:
        """Apply blocking actions synchronously in the sniffer thread."""
        try:
            from app.blocking.domain_blocker import block_domain
            block_domain(domain, reason=f"FastPath [{category}]: {reason}")
        except Exception as exc:
            logger.error("Fast-path domain block error for %s: %s", domain, exc)

        # Block the Cloudflare / CDN IP we know from *this* packet if available
        # (resolved_ip is obtained later by the full pipeline — skip DNS resolve here
        # to keep fast-path latency < 5 ms)

        # For gambling/piracy: also intercept DoH immediately so subsequent
        # requests by the browser can't bypass /etc/hosts
        if category in ("gambling", "piracy", "vpn", "tor", "gambling_access",
                         "pirated_content", "vpn_usage", "tor_usage"):
            try:
                from app.blocking.firewall import block_doh
                block_doh()
            except Exception as exc:
                logger.debug("Fast-path DoH block error: %s", exc)

    def clear_session(self) -> None:
        """Reset the dedup cache (call when capture restarts)."""
        with self._lock:
            self._seen.clear()
