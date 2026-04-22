from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PacketMeta:
    ts: float  # seconds since epoch
    src_ip: str
    dst_ip: str
    protocol: str  # "tcp"|"udp"|"icmp"|"other"
    src_port: int | None
    dst_port: int | None
    length_bytes: int

    # Optional metadata-only “names”
    dns_query: str | None = None
    tls_sni: str | None = None

