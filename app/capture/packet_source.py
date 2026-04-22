from __future__ import annotations

import logging
import os
import socket
import sys
import time
from dataclasses import dataclass
from typing import Iterable, Iterator, Optional

from app.capture.types import PacketMeta

logger = logging.getLogger("netscan.capture")


@dataclass(frozen=True)
class CaptureSettings:
    mode: str  # "scapy"
    interface: str | None = None
    bpf_filter: str | None = None


def _norm_proto(p: str | None) -> str:
    if not p:
        return "other"
    p = p.lower()
    if p in {"tcp", "udp", "icmp"}:
        return p
    return "other"


# Interface name prefixes to skip — virtual/tunnel/container adapters
_SKIP_IFACE_PREFIXES = [
    "lo", "docker", "virbr", "veth", "br-", "tun", "tap",
    "dummy", "bond", "vlan", "ovs-", "flannel", "cni",
]

# Linux physical interface scoring (higher = more preferred)
_PREFERRED_IFACE_PATTERNS: list[tuple[str, int]] = [
    ("eth",  10),   # classic ethernet (eth0, eth1)
    ("ens",  10),   # systemd predictable: pci ethernet
    ("enp",  10),   # systemd predictable: pci ethernet
    ("eno",   9),   # systemd predictable: onboard
    ("enx",   8),   # systemd predictable: mac-based
    ("wlan",  7),   # classic wifi
    ("wlp",   7),   # systemd predictable: pci wifi
    ("wlx",   6),   # systemd predictable: mac-based wifi
]


def auto_detect_interface() -> str | None:
    """
    Find the best active physical network interface on Linux.

    Scoring rules (higher is better):
    - Must have a real routable IPv4 address (not 127.x, 169.254.x)
    - Skips loopback, docker, veth, tun, tap, bridge, virbr adapters
    - Prefers eth/ens/enp (Ethernet) > wlan/wlp (WiFi)
    """
    try:
        import psutil

        candidates: list[tuple[int, str, str]] = []  # (score, name, ip)

        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()

        for iface_name, iface_addrs in addrs.items():
            # Must be up
            if iface_name in stats and not stats[iface_name].isup:
                continue

            # Skip virtual/tunnel interfaces
            lower = iface_name.lower()
            if any(lower.startswith(p) for p in _SKIP_IFACE_PREFIXES):
                continue

            # Find a real IPv4 address
            ip = ""
            for addr in iface_addrs:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    break
            if not ip or ip.startswith("127.") or ip.startswith("169.254."):
                continue

            # Score by interface name prefix
            score = 1
            for prefix, bonus in _PREFERRED_IFACE_PATTERNS:
                if lower.startswith(prefix):
                    score = bonus
                    break

            candidates.append((score, iface_name, ip))

        if candidates:
            candidates.sort(key=lambda x: x[0], reverse=True)
            score, name, ip = candidates[0]
            logger.info(
                "Auto-detected interface: %s (%s) [score=%d]", name, ip, score
            )
            return name

    except Exception as e:
        logger.warning("Could not auto-detect interface via psutil: %s", e)

    # Fallback: try scapy's interface list
    try:
        from scapy.all import conf
        for iface in conf.ifaces.values():
            ip   = str(getattr(iface, "ip", "") or "")
            name = str(getattr(iface, "name", "") or "")
            lower = name.lower()
            if not ip or ip.startswith("127.") or ip.startswith("169.254."):
                continue
            if any(lower.startswith(p) for p in _SKIP_IFACE_PREFIXES):
                continue
            logger.info("Auto-detected interface (scapy fallback): %s (%s)", name, ip)
            return name
    except Exception as e:
        logger.warning("Scapy fallback interface detection failed: %s", e)

    return None


def _extract_tls_sni(data: bytes) -> str | None:
    """Best-effort extraction of TLS SNI from a raw TCP payload (ClientHello)."""
    try:
        # TLS record: ContentType(1) + Version(2) + Length(2) + HandshakeType(1)
        if len(data) < 6 or data[0] != 0x16:  # 0x16 = Handshake
            return None
        # Handshake type 0x01 = ClientHello
        if data[5] != 0x01:
            return None
        # Walk through ClientHello to find SNI extension
        # Skip: HandshakeType(1) + Length(3) + ClientVersion(2) + Random(32)
        pos = 5 + 1 + 3 + 2 + 32
        if pos + 1 >= len(data):
            return None
        session_id_len = data[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(data):
            return None
        cipher_suites_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2 + cipher_suites_len
        if pos + 1 > len(data):
            return None
        comp_methods_len = data[pos]
        pos += 1 + comp_methods_len
        if pos + 2 > len(data):
            return None
        extensions_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        end = pos + extensions_len
        while pos + 4 <= end and pos + 4 <= len(data):
            ext_type = int.from_bytes(data[pos:pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            if ext_type == 0x0000:  # SNI extension
                # SNI list length (2) + type (1) + name length (2)
                if pos + 5 <= len(data):
                    name_len = int.from_bytes(data[pos + 3:pos + 5], "big")
                    if pos + 5 + name_len <= len(data):
                        return data[pos + 5:pos + 5 + name_len].decode("ascii", errors="ignore")
            pos += ext_len
    except Exception:
        pass
    return None


class PacketSource:
    """
    Metadata-only packet source using Scapy.

    Uses libpcap on Linux for efficient kernel-level BPF filtering.
    Requires root or CAP_NET_RAW capability.
    """

    def __init__(self, settings: CaptureSettings):
        self.settings = settings

    def packets(self) -> Iterator[PacketMeta]:
        mode = (self.settings.mode or "scapy").lower()
        if mode == "scapy":
            yield from self._scapy_packets()
            return
        raise ValueError(f"Unknown capture mode: {self.settings.mode}")

    def _scapy_packets(self) -> Iterator[PacketMeta]:
        """Live capture using Scapy — works on Windows with Npcap, no tshark needed."""
        try:
            from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw  # type: ignore
        except Exception as e:
            raise RuntimeError(
                "Scapy is not installed. Install it with: pip install scapy"
            ) from e

        iface = self.settings.interface
        if not iface:
            iface = auto_detect_interface()
        if not iface:
            raise ValueError(
                "No network interface specified and auto-detection failed. "
                "Pass --interface <name> explicitly (e.g. --interface eth0)."
            )

        logger.info("Starting Scapy live capture on interface: %s", iface)

        # Require root or CAP_NET_RAW for raw socket capture
        if os.getuid() != 0:
            logger.warning(
                "Packet capture may fail without root / CAP_NET_RAW. "
                "Re-run with: sudo %s", " ".join(sys.argv)
            )

        import queue
        pkt_queue: queue.Queue = queue.Queue(maxsize=10000)
        _stop = False

        def _callback(pkt):
            if _stop:
                return
            try:
                if not pkt.haslayer(IP):
                    return
                ip_layer = pkt[IP]
                src_ip = str(ip_layer.src)
                dst_ip = str(ip_layer.dst)
                length_bytes = int(len(pkt))
                ts = float(pkt.time)

                protocol = "other"
                src_port: Optional[int] = None
                dst_port: Optional[int] = None

                if pkt.haslayer(TCP):
                    protocol = "tcp"
                    src_port = int(pkt[TCP].sport)
                    dst_port = int(pkt[TCP].dport)
                elif pkt.haslayer(UDP):
                    protocol = "udp"
                    src_port = int(pkt[UDP].sport)
                    dst_port = int(pkt[UDP].dport)

                dns_query = None
                if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                    qname = pkt[DNSQR].qname
                    if qname:
                        dns_query = qname.decode("utf-8", errors="ignore").rstrip(".")

                # TLS SNI extraction (from ClientHello)
                tls_sni = None
                if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                    tls_sni = _extract_tls_sni(bytes(pkt[Raw].load))

                meta = PacketMeta(
                    ts=ts,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=_norm_proto(protocol),
                    src_port=src_port,
                    dst_port=dst_port,
                    length_bytes=length_bytes,
                    dns_query=dns_query,
                    tls_sni=tls_sni,
                )
                pkt_queue.put_nowait(meta)
            except Exception:
                pass  # Skip malformed packets

        import threading
        _error_holder: list[Exception | None] = [None]

        def _sniff_worker():
            try:
                sniff_kwargs: dict = dict(iface=iface, prn=_callback, store=False)

                # BPF filter for IP traffic only — efficient kernel-level filtering on Linux
                bpf = self.settings.bpf_filter or "ip or ip6"
                sniff_kwargs["filter"] = bpf

                from scapy.all import sniff
                sniff(**sniff_kwargs)
            except Exception as e:
                err_msg = str(e).lower()
                if "permission denied" in err_msg or "operation not permitted" in err_msg:
                    msg = (
                        "Packet capture failed — permission denied. "
                        "Run as root:  sudo python3 cli.py live  "
                        "or grant capability:  sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)"
                    )
                    logger.error(msg)
                    _error_holder[0] = RuntimeError(msg)
                else:
                    logger.error("Scapy sniff thread failed: %s", e, exc_info=True)
                    _error_holder[0] = e

        sniff_thread = threading.Thread(
            target=_sniff_worker,
            daemon=True,
            name="scapy-sniffer",
        )
        sniff_thread.start()
        logger.info("Scapy sniffer thread started on %s", iface)

        try:
            while True:
                # Check if sniff thread died
                err = _error_holder[0]
                if err is not None:
                    raise RuntimeError(f"Scapy capture failed: {err}") from err
                try:
                    meta = pkt_queue.get(timeout=0.5)
                    yield meta
                except queue.Empty:
                    continue
        finally:
            _stop = True



