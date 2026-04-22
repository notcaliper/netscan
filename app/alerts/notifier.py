"""Notification channels: console, email, Telegram.

Notifications are dispatched asynchronously via a background thread so the
capture pipeline never blocks on slow SMTP or HTTP calls.
"""
from __future__ import annotations

import logging
import os
import queue
import smtplib
import threading
from email.mime.text import MIMEText
from typing import Any

from app.config import load_config

logger = logging.getLogger("netscan.notifier")


class Notifier:
    """Dispatches alert notifications through configured channels.

    All I/O-bound channels (email, Telegram) are pushed to a background
    worker thread so the caller never blocks.
    """

    def __init__(self) -> None:
        cfg = load_config().raw.get("alerting", {})
        self.console_enabled: bool = cfg.get("console", True)
        self.db_enabled: bool = cfg.get("store_in_db", True)

        email_cfg = cfg.get("email", {})
        self.email_enabled: bool = email_cfg.get("enabled", False)
        self.smtp_host: str = email_cfg.get("smtp_host", "")
        self.smtp_port: int = int(email_cfg.get("smtp_port", 587))
        self.email_sender: str = email_cfg.get("sender", "")
        self.email_password: str = os.environ.get(email_cfg.get("password_env", ""), "")
        self.email_recipients: list[str] = email_cfg.get("recipients", [])

        tg_cfg = cfg.get("telegram", {})
        self.telegram_enabled: bool = tg_cfg.get("enabled", False)
        self.telegram_token: str = os.environ.get(tg_cfg.get("bot_token_env", ""), "")
        self.telegram_chat_id: str = str(tg_cfg.get("chat_id", ""))

        # Background worker for async I/O notifications
        self._queue: queue.Queue[tuple[str, str, str] | None] = queue.Queue(maxsize=500)
        self._worker = threading.Thread(target=self._dispatch_loop, daemon=True, name="notifier")
        self._worker.start()

    def notify(
        self,
        title: str,
        summary: str,
        severity: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Push a notification through all enabled channels."""
        # Console is fast — do inline
        if self.console_enabled:
            self._console(title, summary, severity)
        # Email + Telegram are I/O-bound — push to background
        if self.email_enabled or self.telegram_enabled:
            try:
                self._queue.put_nowait((title, summary, severity))
            except queue.Full:
                logger.warning("Notification queue full — dropping alert: %s", title)

    # ------------------------------------------------------------------
    # Background dispatch
    # ------------------------------------------------------------------

    def _dispatch_loop(self) -> None:
        """Worker loop that drains the queue and sends I/O-bound notifications."""
        while True:
            item = self._queue.get()
            if item is None:
                break  # shutdown signal
            title, summary, severity = item
            if self.email_enabled:
                self._email(title, summary, severity)
            if self.telegram_enabled:
                self._telegram(title, summary, severity)

    # ------------------------------------------------------------------
    # Channels
    # ------------------------------------------------------------------

    def _console(self, title: str, summary: str, severity: str) -> None:
        sev_colors = {
            "critical": "\033[91m",  # red
            "high": "\033[93m",      # yellow
            "medium": "\033[94m",    # blue
            "low": "\033[92m",       # green
        }
        reset = "\033[0m"
        color = sev_colors.get(severity, "")
        logger.warning(
            "%s[ALERT %s] %s%s — %s",
            color,
            severity.upper(),
            title,
            reset,
            summary[:200],
        )

    def _email(self, title: str, summary: str, severity: str) -> None:
        if not self.email_recipients:
            return
        try:
            body = f"Severity: {severity}\n\n{summary}"
            msg = MIMEText(body, "plain", "utf-8")
            msg["Subject"] = f"[NetScan] {title}"
            msg["From"] = self.email_sender
            msg["To"] = ", ".join(self.email_recipients)
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15) as server:
                server.starttls()
                server.login(self.email_sender, self.email_password)
                server.sendmail(self.email_sender, self.email_recipients, msg.as_string())
            logger.info("Email alert sent: %s", title)
        except Exception as exc:
            logger.error("Failed to send email alert: %s", exc)

    def _telegram(self, title: str, summary: str, severity: str) -> None:
        try:
            import requests

            text = f"🚨 *{severity.upper()}*: {title}\n\n{summary[:500]}"
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            requests.post(
                url,
                json={
                    "chat_id": self.telegram_chat_id,
                    "text": text,
                    "parse_mode": "Markdown",
                },
                timeout=10,
            )
            logger.info("Telegram alert sent: %s", title)
        except Exception as exc:
            logger.error("Failed to send Telegram alert: %s", exc)
