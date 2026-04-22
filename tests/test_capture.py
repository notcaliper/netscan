"""Tests for capture and packet source."""
from __future__ import annotations

import pytest

from app.capture.packet_source import CaptureSettings, PacketSource
from app.capture.types import PacketMeta


def test_invalid_mode_raises():
    settings = CaptureSettings(mode="unknown_mode")
    src = PacketSource(settings)
    with pytest.raises(ValueError, match="Unknown capture mode"):
        list(src.packets())
