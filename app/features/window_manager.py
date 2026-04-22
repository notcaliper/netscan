"""Sliding window manager for the detection pipeline."""
from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Iterator

from app.capture.types import PacketMeta

logger = logging.getLogger("netscan.window")


@dataclass
class WindowBatch:
    """A completed time-window of packets ready for feature extraction."""
    window_start_ts: float
    window_end_ts: float
    packets: list[PacketMeta]


class WindowManager:
    """
    Accumulates raw PacketMeta objects and yields ``WindowBatch``
    instances every *slide_seconds*, each covering *window_seconds*
    of data (sliding window).
    """

    def __init__(self, window_seconds: int = 20, slide_seconds: int = 10):
        self.window_seconds = window_seconds
        self.slide_seconds = slide_seconds
        self._buffer: Deque[PacketMeta] = deque()
        self._next_emit: float | None = None

    def add_packet(self, pkt: PacketMeta) -> WindowBatch | None:
        """
        Ingest one packet.  Returns a ``WindowBatch`` when the slide
        interval has elapsed, else ``None``.
        """
        now = pkt.ts
        self._buffer.append(pkt)

        if self._next_emit is None:
            self._next_emit = now + self.slide_seconds
            return None

        # Evict stale packets
        cutoff = now - self.window_seconds
        while self._buffer and self._buffer[0].ts < cutoff:
            self._buffer.popleft()

        if now >= self._next_emit:
            window_end = now
            window_start = window_end - self.window_seconds
            batch = [p for p in self._buffer if window_start <= p.ts < window_end]
            self._next_emit = now + self.slide_seconds
            logger.debug(
                "Window emitted: %d packets, %.1fs window",
                len(batch),
                self.window_seconds,
            )
            return WindowBatch(
                window_start_ts=window_start,
                window_end_ts=window_end,
                packets=batch,
            )

        return None

    def flush(self) -> WindowBatch | None:
        """Force-emit whatever is in the buffer (for shutdown / test)."""
        if not self._buffer:
            return None
        now = self._buffer[-1].ts
        window_start = now - self.window_seconds
        batch = [p for p in self._buffer if p.ts >= window_start]
        self._buffer.clear()
        return WindowBatch(
            window_start_ts=window_start,
            window_end_ts=now,
            packets=batch,
        )
