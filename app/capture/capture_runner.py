from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Iterable, Iterator, List

from app.capture.flow_aggregator import FlowAggregator
from app.capture.packet_source import CaptureSettings, PacketSource
from app.capture.types import PacketMeta
from app.config import load_config


@dataclass(frozen=True)
class CaptureOutput:
    window_start_ts: float
    window_end_ts: float
    packets: list[PacketMeta]


def run_capture_loop(
    *,
    mode: str = "scapy",
    interface: str | None = None,
    bpf_filter: str | None = None,
    dns_interceptor=None,
) -> Iterator[CaptureOutput]:
    """
    Sliding-window capture yielding PacketMeta batches every slide interval.

    dns_interceptor — optional RealTimeDNSInterceptor; if provided, every
                      DNS-carrying packet is classified immediately before
                      being added to the window buffer. This gives < 100 ms
                      detection latency for domain-based threats instead of
                      waiting for the full slide interval (3–5 s).
    """
    cfg = load_config().raw
    window_s = int(cfg["app"]["window_seconds"])
    slide_s = int(cfg["app"]["slide_seconds"])

    settings = CaptureSettings(mode=mode, interface=interface, bpf_filter=bpf_filter)
    src = PacketSource(settings)

    buf: Deque[PacketMeta] = deque()
    window_start = time.time()
    next_emit = window_start + slide_s

    for pkt in src.packets():
        now = time.time()

        # ── Real-time DNS fast-path ──────────────────────────────────────────
        # Runs classify_domain() inline — pure in-memory, ~0 ms.
        # Blocks domain + fires DoH interception immediately, before the
        # window even finishes. The window still runs for ML/rule scoring.
        if dns_interceptor is not None and pkt.dns_query:
            try:
                dns_interceptor.on_packet(pkt.src_ip, pkt.dns_query)
            except Exception:
                pass  # Never let fast-path crash the capture loop

        buf.append(pkt)

        # Drop old packets
        cutoff = now - window_s
        while buf and buf[0].ts < cutoff:
            buf.popleft()

        if now >= next_emit:
            window_end = now
            window_start_ts = window_end - window_s
            batch = [p for p in buf if window_start_ts <= p.ts < window_end]
            yield CaptureOutput(window_start_ts=window_start_ts, window_end_ts=window_end, packets=batch)
            next_emit = now + slide_s

