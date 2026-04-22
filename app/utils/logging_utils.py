from __future__ import annotations

import logging


def setup_logging(level: int = logging.WARNING) -> None:
    """
    Configure root logging.

    Console  → WARNING and above  (clean output, only alerts & errors)
    File     → DEBUG and above    (full detail in netscan.log)
    """
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

