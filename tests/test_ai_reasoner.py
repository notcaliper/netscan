"""Tests for AI reasoner components."""
from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from app.ai_reasoner.gemini_client import GeminiClient, GeminiResponse
from app.ai_reasoner.prompt_builder import build_analysis_prompt
from app.ai_reasoner.ai_decision_logic import AIDecisionLogic, AIAssessmentResult
from app.detection.hybrid_detector import DetectionResult
from app.features.feature_types import FeatureVector


def _fv(**kw) -> FeatureVector:
    defaults = dict(
        window_start=datetime(2026, 2, 18, 10, 0, 0),
        window_end=datetime(2026, 2, 18, 10, 0, 20),
        src_ip="10.0.5.23",
        num_flows=45,
        num_unique_dst_ips=3,
        num_unique_domains=1,
        total_bytes_sent=8_000_000,
        total_bytes_received=25_000_000,
        avg_packet_size=1300.0,
        std_packet_size=50.0,
        avg_inter_packet_time=0.01,
        std_inter_packet_time=0.002,
        tcp_flow_count=0,
        udp_flow_count=45,
        dns_query_count=1,
        distinct_dst_ports=1,
        top_port=1194,
        ratio_known_vpn_ips=0.9,
        ratio_known_restricted_domains=0.0,
        extra={"observed_dst_ports": [1194], "observed_domains": ["vpn-node.example.com"]},
    )
    defaults.update(kw)
    return FeatureVector(**defaults)


def _dr(**kw) -> DetectionResult:
    defaults = dict(
        rule_score=0.55,
        ml_score=0.7,
        combined_risk=0.65,
        decision="ai_review",
        needs_ai=True,
        guessed_threat_type="vpn_usage",
        rule_hits={"vpn_ports_udp": {"score": 0.55}},
        ml_model_used="heuristic_v0",
    )
    defaults.update(kw)
    return DetectionResult(**defaults)


class TestPromptBuilder:
    def test_prompt_contains_feature_data(self):
        fv = _fv()
        prompt = build_analysis_prompt(fv)
        assert "10.0.5.23" in prompt
        assert "1194" in prompt
        assert "threat_type" in prompt
        assert "SYSTEM INSTRUCTIONS" in prompt

    def test_prompt_with_history(self):
        fv = _fv()
        prompt = build_analysis_prompt(fv, recent_history="Device used VPN 3 times today.")
        assert "Device used VPN 3 times today." in prompt


class TestGeminiClient:
    def test_disabled_returns_error(self):
        client = GeminiClient()
        client.enabled = False
        result = client.call_sync("test prompt")
        assert not result.success
        assert "disabled" in result.error.lower()

    def test_parse_json_block_plain(self):
        text = '{"threat_type": "vpn_usage", "severity": "high"}'
        parsed = GeminiClient._parse_json_block(text)
        assert parsed["threat_type"] == "vpn_usage"

    def test_parse_json_block_with_fences(self):
        text = '```json\n{"threat_type": "benign"}\n```'
        parsed = GeminiClient._parse_json_block(text)
        assert parsed["threat_type"] == "benign"

    def test_parse_json_block_embedded(self):
        text = 'Here is the analysis:\n{"threat_type": "other", "severity": "low"}\nDone.'
        parsed = GeminiClient._parse_json_block(text)
        assert parsed["threat_type"] == "other"


class TestAIDecisionLogic:
    def test_should_escalate_when_needs_ai(self):
        logic = AIDecisionLogic()
        dr = _dr(needs_ai=True)
        assert logic.should_escalate(dr) is True

    def test_should_not_escalate_when_not_needed(self):
        logic = AIDecisionLogic()
        dr = _dr(needs_ai=False)
        assert logic.should_escalate(dr) is False

    @patch.object(GeminiClient, "call_sync")
    def test_assess_sync_success(self, mock_call):
        mock_call.return_value = GeminiResponse(
            raw_text='{"threat_type":"vpn_usage","severity":"high","explanation":"VPN detected","recommended_action":"Block"}',
            parsed={
                "threat_type": "vpn_usage",
                "severity": "high",
                "explanation": "VPN detected",
                "recommended_action": "Block",
            },
            success=True,
        )
        logic = AIDecisionLogic()
        result = logic.assess_sync(_fv(), _dr())
        assert result.success
        assert result.threat_type == "vpn_usage"
        assert result.severity == "high"

    @patch.object(GeminiClient, "call_sync")
    def test_assess_sync_failure_fallback(self, mock_call):
        mock_call.return_value = GeminiResponse(
            raw_text="", parsed={}, success=False, error="API error"
        )
        logic = AIDecisionLogic()
        result = logic.assess_sync(_fv(), _dr())
        assert not result.success
        assert result.threat_type == "vpn_usage"  # falls back to guessed
