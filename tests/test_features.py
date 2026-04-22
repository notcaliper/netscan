"""Tests for feature extraction and flow aggregation."""
from __future__ import annotations

import time

import pytest

from app.capture.flow_aggregator import FlowAggregator
from app.capture.types import PacketMeta
from app.features.feature_extractor import FeatureExtractor
from app.features.feature_types import FeatureVector
from app.features.window_manager import WindowManager


def _make_packets(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "1.2.3.4",
    protocol: str = "tcp",
    dst_port: int = 443,
    count: int = 10,
    base_ts: float | None = None,
) -> list[PacketMeta]:
    base = base_ts or time.time()
    return [
        PacketMeta(
            ts=base + i * 0.1,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=50000 + i,
            dst_port=dst_port,
            length_bytes=800 + i * 10,
        )
        for i in range(count)
    ]


class TestFlowAggregator:
    def test_single_device(self):
        pkts = _make_packets(count=20, base_ts=100.0)
        agg = FlowAggregator(window_seconds=20)
        fvs = agg.aggregate_window(pkts, 100.0, 120.0)
        assert len(fvs) == 1
        fv = fvs[0]
        assert fv.src_ip == "10.0.0.1"
        assert fv.tcp_flow_count == 20
        assert fv.total_bytes_sent > 0
        assert fv.distinct_dst_ports == 1

    def test_multiple_devices(self):
        pkts = _make_packets("10.0.0.1", count=10, base_ts=100.0) + \
               _make_packets("10.0.0.2", count=5, base_ts=100.0)
        agg = FlowAggregator(window_seconds=20)
        fvs = agg.aggregate_window(pkts, 100.0, 120.0)
        ips = {fv.src_ip for fv in fvs}
        assert ips == {"10.0.0.1", "10.0.0.2"}

    def test_out_of_window_ignored(self):
        pkts = _make_packets(count=5, base_ts=50.0)  # before window
        agg = FlowAggregator(window_seconds=20)
        fvs = agg.aggregate_window(pkts, 100.0, 120.0)
        assert len(fvs) == 0


class TestFeatureExtractor:
    def test_extract_enriches(self):
        pkts = _make_packets(count=10, base_ts=100.0)
        ext = FeatureExtractor(window_seconds=20)
        fvs = ext.extract(pkts, 100.0, 120.0)
        assert len(fvs) == 1
        assert isinstance(fvs[0], FeatureVector)

    def test_numeric_vector_length(self):
        fv = FeatureVector(
            window_start=__import__("datetime").datetime(2026, 1, 1),
            window_end=__import__("datetime").datetime(2026, 1, 1),
            src_ip="10.0.0.1",
        )
        vec = fv.to_numeric_vector()
        assert len(vec) == 16
        assert all(isinstance(v, float) for v in vec)


class TestWindowManager:
    def test_window_emits_after_slide(self):
        wm = WindowManager(window_seconds=10, slide_seconds=5)
        results = []
        for i in range(200):
            pkt = PacketMeta(
                ts=100.0 + i * 0.1,
                src_ip="10.0.0.1",
                dst_ip="1.2.3.4",
                protocol="tcp",
                src_port=50000,
                dst_port=443,
                length_bytes=500,
            )
            batch = wm.add_packet(pkt)
            if batch is not None:
                results.append(batch)
        assert len(results) >= 1

    def test_flush(self):
        wm = WindowManager(window_seconds=10, slide_seconds=5)
        pkt = PacketMeta(
            ts=100.0, src_ip="10.0.0.1", dst_ip="1.2.3.4",
            protocol="tcp", src_port=50000, dst_port=443, length_bytes=500,
        )
        wm.add_packet(pkt)
        batch = wm.flush()
        assert batch is not None
        assert len(batch.packets) == 1
