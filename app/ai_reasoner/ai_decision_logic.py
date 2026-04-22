"""Orchestrates when and how to call Gemini for uncertain detections."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from app.ai_reasoner.gemini_client import GeminiClient, GeminiResponse
from app.ai_reasoner.prompt_builder import build_analysis_prompt
from app.detection.hybrid_detector import DetectionResult
from app.features.feature_types import FeatureVector

logger = logging.getLogger("netscan.ai_logic")


@dataclass(frozen=True)
class AIAssessmentResult:
    """Structured output from Gemini reasoning."""
    threat_type: str
    severity: str
    explanation: str
    recommended_action: str
    raw_response: dict[str, Any]
    success: bool


class AIDecisionLogic:
    """
    Decides whether an uncertain detection should be sent to Gemini,
    and parses the response into an ``AIAssessmentResult``.
    """

    def __init__(self) -> None:
        self.client = GeminiClient()

    def should_escalate(self, dr: DetectionResult) -> bool:
        """Return True if this detection warrants AI review."""
        return dr.needs_ai

    def assess_sync(
        self,
        fv: FeatureVector,
        dr: DetectionResult,
        *,
        recent_history: str | None = None,
    ) -> AIAssessmentResult:
        """
        Build prompt, call Gemini (blocking), and return structured result.
        """
        prompt = build_analysis_prompt(fv, recent_history=recent_history)
        logger.info("Calling Gemini for %s (combined_risk=%.2f)", fv.src_ip, dr.combined_risk)

        resp: GeminiResponse = self.client.call_sync(prompt)

        if not resp.success or not resp.parsed:
            logger.warning(
                "Gemini call failed or returned empty for %s: %s",
                fv.src_ip,
                resp.error,
            )
            return AIAssessmentResult(
                threat_type=dr.guessed_threat_type or "unknown",
                severity="medium",
                explanation=f"AI review could not be completed: {resp.error}",
                recommended_action="Manual review recommended.",
                raw_response={"error": resp.error, "raw_text": resp.raw_text},
                success=False,
            )

        parsed = resp.parsed
        return AIAssessmentResult(
            threat_type=parsed.get("threat_type", "unknown"),
            severity=parsed.get("severity", "medium"),
            explanation=parsed.get("explanation", ""),
            recommended_action=parsed.get("recommended_action", ""),
            raw_response=parsed,
            success=True,
        )

    async def assess_async(
        self,
        fv: FeatureVector,
        dr: DetectionResult,
        *,
        recent_history: str | None = None,
    ) -> AIAssessmentResult:
        """Async variant of :meth:`assess_sync`."""
        prompt = build_analysis_prompt(fv, recent_history=recent_history)
        logger.info("Calling Gemini (async) for %s (combined_risk=%.2f)", fv.src_ip, dr.combined_risk)

        resp: GeminiResponse = await self.client.call_async(prompt)

        if not resp.success or not resp.parsed:
            return AIAssessmentResult(
                threat_type=dr.guessed_threat_type or "unknown",
                severity="medium",
                explanation=f"AI review could not be completed: {resp.error}",
                recommended_action="Manual review recommended.",
                raw_response={"error": resp.error, "raw_text": resp.raw_text},
                success=False,
            )

        parsed = resp.parsed
        return AIAssessmentResult(
            threat_type=parsed.get("threat_type", "unknown"),
            severity=parsed.get("severity", "medium"),
            explanation=parsed.get("explanation", ""),
            recommended_action=parsed.get("recommended_action", ""),
            raw_response=parsed,
            success=True,
        )
