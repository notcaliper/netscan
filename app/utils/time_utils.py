"""Time-related utility helpers."""
from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return current UTC time (naive, for DB storage)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def ts_to_datetime(ts: float) -> datetime:
    """Convert a UNIX timestamp to a naive-UTC datetime."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)


def datetime_to_ts(dt: datetime) -> float:
    """Convert a naive-UTC datetime to a UNIX timestamp."""
    return dt.replace(tzinfo=timezone.utc).timestamp()


def format_window(start: datetime, end: datetime) -> str:
    """Pretty-print a time window for logs / alerts."""
    fmt = "%Y-%m-%dT%H:%M:%S"
    return f"{start.strftime(fmt)} → {end.strftime(fmt)}"
