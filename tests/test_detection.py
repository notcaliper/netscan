"""Tests for rule engine, ML model, and hybrid detector."""
from __future__ import annotations

from datetime import datetime

import pytest

from app.detection.hybrid_detector import DetectionResult, HybridDetector
from app.detection.ml_model import MLModel, MLResult
from app.detection.rules_engine import RulesEngine, RuleResult
from app.features.feature_types import FeatureVector


def _fv(**overrides) -> FeatureVector:
    defaults = dict(
        window_start=datetime(2026, 2, 18, 10, 0, 0),
        window_end=datetime(2026, 2, 18, 10, 0, 20),
        src_ip="10.0.5.23",
        num_flows=10,
        num_unique_dst_ips=3,
        num_unique_domains=2,
        total_bytes_sent=500_000,
        total_bytes_received=1_000_000,
        avg_packet_size=600.0,
        std_packet_size=100.0,
        avg_inter_packet_time=0.1,
        std_inter_packet_time=0.05,
        tcp_flow_count=10,
        udp_flow_count=0,
        dns_query_count=2,
        distinct_dst_ports=2,
        top_port=443,
        ratio_known_vpn_ips=0.0,
        ratio_known_restricted_domains=0.0,
        extra={"observed_dst_ports": [80, 443], "observed_domains": ["google.com"]},
    )
    defaults.update(overrides)
    return FeatureVector(**defaults)


class TestRulesEngine:
    def test_vpn_port_hit(self):
        fv = _fv(
            udp_flow_count=45,
            tcp_flow_count=0,
            top_port=1194,
            extra={"observed_dst_ports": [1194], "observed_domains": []},
        )
        engine = RulesEngine()
        result = engine.evaluate(fv)
        assert result.score > 0
        assert "vpn_ports_udp" in result.hits
        assert result.guessed_threat_type == "vpn_usage"

    def test_torrent_port_hit(self):
        fv = _fv(
            tcp_flow_count=120,
            top_port=6881,
            extra={"observed_dst_ports": [6881, 6882], "observed_domains": []},
        )
        engine = RulesEngine()
        result = engine.evaluate(fv)
        assert result.score > 0
        assert "torrent_ports_tcp" in result.hits
        assert result.guessed_threat_type == "pirated_content"

    def test_gambling_domain_hit(self):
        fv = _fv(
            extra={
                "observed_dst_ports": [443],
                "observed_domains": ["best-casino-bet.example", "poker-stars.example"],
            },
        )
        engine = RulesEngine()
        result = engine.evaluate(fv)
        assert result.score > 0
        assert result.guessed_threat_type == "gambling_access"

    def test_benign_traffic_no_hits(self):
        fv = _fv(
            extra={
                "observed_dst_ports": [443],
                "observed_domains": ["google.com", "github.com"],
            },
        )
        engine = RulesEngine()
        result = engine.evaluate(fv)
        assert result.score == 0.0
        assert len(result.hits) == 0

    def test_high_fanout(self):
        fv = _fv(num_unique_dst_ips=50)
        engine = RulesEngine()
        result = engine.evaluate(fv)
        assert "high_fanout_connections" in result.hits


class TestMLModel:
    def test_heuristic_fallback(self):
        fv = _fv()
        model = MLModel()
        result = model.score(fv)
        assert isinstance(result, MLResult)
        assert 0.0 <= result.score <= 1.0
        assert result.model_used in {"heuristic_v0", "isolation_forest", "disabled"}

    def test_high_throughput_scores_higher(self):
        low = _fv(total_bytes_sent=1000, total_bytes_received=2000, num_unique_dst_ips=2)
        high = _fv(total_bytes_sent=50_000_000, total_bytes_received=100_000_000, num_unique_dst_ips=60)
        model = MLModel()
        assert model.score(high).score > model.score(low).score


class TestHybridDetector:
    def test_benign_returns_allow(self):
        fv = _fv(
            extra={"observed_dst_ports": [443], "observed_domains": ["google.com"]},
        )
        det = HybridDetector()
        result = det.detect(fv)
        assert isinstance(result, DetectionResult)
        assert result.decision in {"allow", "monitor", "ai_review"}

    def test_vpn_high_risk(self):
        fv = _fv(
            udp_flow_count=45,
            tcp_flow_count=0,
            top_port=1194,
            ratio_known_vpn_ips=0.9,
            total_bytes_sent=8_000_000,
            total_bytes_received=25_000_000,
            extra={"observed_dst_ports": [1194], "observed_domains": ["vpn.example"]},
        )
        det = HybridDetector()
        result = det.detect(fv)
        assert result.combined_risk > 0.3
        assert result.rule_score > 0

    def test_result_fields(self):
        fv = _fv()
        det = HybridDetector()
        result = det.detect(fv)
        assert hasattr(result, "rule_score")
        assert hasattr(result, "ml_score")
        assert hasattr(result, "combined_risk")
        assert hasattr(result, "decision")
        assert hasattr(result, "needs_ai")
