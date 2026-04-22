from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class AppConfig:
    raw: dict[str, Any]

    @property
    def window_seconds(self) -> int:
        return int(self.raw["app"]["window_seconds"])

    @property
    def slide_seconds(self) -> int:
        return int(self.raw["app"]["slide_seconds"])

    @property
    def db_url(self) -> str:
        if os.environ.get("NETSCAN_TEST"):
            return "sqlite:///:memory:"
        return str(self.raw["db"]["url"])


# ── Cached config loader ──────────────────────────────────────────────────
# Avoids re-reading + re-parsing YAML from disk on every call.
# The cache is invalidated when the file's mtime changes OR after _TTL seconds.

_CONFIG_CACHE: dict[str, tuple[AppConfig, float, float]] = {}  # path -> (config, mtime, loaded_at)
_TTL = 60.0  # seconds before checking mtime again


def load_config(config_path: str | Path | None = None) -> AppConfig:
    path = Path(config_path) if config_path else Path("config/app_config.yaml")
    key = str(path.resolve())
    now = time.monotonic()

    cached = _CONFIG_CACHE.get(key)
    if cached is not None:
        cfg, last_mtime, loaded_at = cached
        # Fast path: if within TTL, skip stat() call entirely
        if (now - loaded_at) < _TTL:
            return cfg
        # TTL expired — check if file actually changed
        try:
            current_mtime = path.stat().st_mtime
        except OSError:
            return cfg  # file disappeared; return stale config
        if current_mtime == last_mtime:
            # File unchanged — refresh the timer
            _CONFIG_CACHE[key] = (cfg, last_mtime, now)
            return cfg

    # Cache miss or file changed — reload
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    mtime = path.stat().st_mtime
    cfg = AppConfig(raw=data)
    _CONFIG_CACHE[key] = (cfg, mtime, now)
    return cfg


def invalidate_config_cache() -> None:
    """Force reload on next call. Useful after config edits."""
    _CONFIG_CACHE.clear()
