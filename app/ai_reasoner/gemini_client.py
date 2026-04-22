"""Low-level HTTP wrapper for Google Gemini API."""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any

import httpx

from app.config import load_config

logger = logging.getLogger("netscan.gemini")


@dataclass(frozen=True)
class GeminiResponse:
    """Parsed Gemini API response."""
    raw_text: str
    parsed: dict[str, Any]
    success: bool
    error: str | None = None


class GeminiClient:
    """Thin wrapper around the Gemini REST API (``generateContent``)."""

    def __init__(self) -> None:
        cfg = load_config().raw.get("gemini", {})
        self.enabled: bool = bool(cfg.get("enabled", False))
        self.api_key: str = os.environ.get(cfg.get("api_key_env", "GEMINI_API_KEY"), "")
        self.base_url: str = cfg.get("base_url", "https://generativelanguage.googleapis.com")
        self.api_version: str = cfg.get("api_version", "v1beta")
        self.model: str = cfg.get("model", "gemini-2.0-flash")
        self.timeout: int = int(cfg.get("timeout_seconds", 15))

    @property
    def _endpoint(self) -> str:
        return (
            f"{self.base_url}/{self.api_version}/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )

    async def call_async(self, prompt: str) -> GeminiResponse:
        """Send *prompt* to Gemini and return the parsed result."""
        if not self.enabled:
            return GeminiResponse(
                raw_text="", parsed={}, success=False, error="Gemini is disabled in config"
            )
        if not self.api_key:
            return GeminiResponse(
                raw_text="", parsed={}, success=False, error="GEMINI_API_KEY not set"
            )

        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 1024,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    self._endpoint,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as exc:
            logger.error("Gemini HTTP error: %s", exc)
            return GeminiResponse(raw_text="", parsed={}, success=False, error=str(exc))
        except Exception as exc:
            logger.error("Gemini request failed: %s", exc)
            return GeminiResponse(raw_text="", parsed={}, success=False, error=str(exc))

        raw_text = self._extract_text(data)
        parsed = self._parse_json_block(raw_text)
        return GeminiResponse(raw_text=raw_text, parsed=parsed, success=True)

    def call_sync(self, prompt: str) -> GeminiResponse:
        """Blocking variant of :meth:`call_async`."""
        if not self.enabled:
            return GeminiResponse(
                raw_text="", parsed={}, success=False, error="Gemini is disabled in config"
            )
        if not self.api_key:
            return GeminiResponse(
                raw_text="", parsed={}, success=False, error="GEMINI_API_KEY not set"
            )

        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 1024,
            },
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(
                    self._endpoint,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as exc:
            logger.error("Gemini HTTP error: %s", exc)
            return GeminiResponse(raw_text="", parsed={}, success=False, error=str(exc))
        except Exception as exc:
            logger.error("Gemini request failed: %s", exc)
            return GeminiResponse(raw_text="", parsed={}, success=False, error=str(exc))

        raw_text = self._extract_text(data)
        parsed = self._parse_json_block(raw_text)
        return GeminiResponse(raw_text=raw_text, parsed=parsed, success=True)

    # ------------------------------------------------------------------
    @staticmethod
    def _extract_text(data: dict) -> str:
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError):
            return ""

    @staticmethod
    def _parse_json_block(text: str) -> dict[str, Any]:
        """Try to pull a JSON object out of the model's response text."""
        # Strip markdown fences if present
        cleaned = text.strip()
        if cleaned.startswith("```"):
            lines = cleaned.splitlines()
            lines = [l for l in lines if not l.strip().startswith("```")]
            cleaned = "\n".join(lines).strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            # Try to find a JSON block inside the text
            start = cleaned.find("{")
            end = cleaned.rfind("}")
            if start != -1 and end != -1:
                try:
                    return json.loads(cleaned[start : end + 1])
                except json.JSONDecodeError:
                    pass
        return {}
