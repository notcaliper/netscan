"""Cached singleton loaders for YAML config files."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_app_config: dict[str, Any] | None = None
_rules_config: dict[str, Any] | None = None


def get_config(path: str | Path = "config/app_config.yaml") -> dict[str, Any]:
    """Load and cache the main application config."""
    global _app_config
    if _app_config is None:
        _app_config = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return _app_config


def get_rules(path: str | Path = "config/rules.yaml") -> dict[str, Any]:
    """Load and cache rules config."""
    global _rules_config
    if _rules_config is None:
        _rules_config = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return _rules_config


def reload_configs() -> None:
    """Force-reload configs on next access (e.g. after editing YAML)."""
    global _app_config, _rules_config
    _app_config = None
    _rules_config = None
