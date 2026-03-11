"""
Notifier — NetScaler SSL Certificate Automation
Sends notifications via SMTP and/or Microsoft Teams webhook.
"""

from __future__ import annotations

import logging
import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import requests

logger = logging.getLogger(__name__)


class Notifier:
    def __init__(self, cfg: dict):
        self.smtp_cfg  = cfg.get("smtp", {})
        self.teams_url = cfg.get("teams_webhook_url", "")
        self.recipients = cfg.get("recipients", [])

    def send_success(self, job) -> None:
        subject = f"[SUCCESS] SSL Cert Update Complete | {job.target_certkey} | {job.total_deployed} ADCs"
        body = self._success_body(job)
        self._send(subject, body, colour="#22c55e", title="SSL Certificate Update SUCCESSFUL")

    def send_failure(self, job) -> None:
        subject = f"[FAILURE] SSL Cert Update ROLLED BACK | {job.target_certkey}"
        body = self._failure_body(job)
        self._send(subject, body, colour="#ef4444", title="SSL Certificate Update FAILED — Rolled Back")

    def send_rejection(self, job) -> None:
        subject = f"[REJECTED] SSL Cert TCM Rejected | {job.target_certkey} | {job.tcm_ticket_id}"
        body = f"TCM ticket {job.tcm_ticket_id} was rejected. Job {job.job_id} aborted. No changes applied."
        self._send(subject, body, colour="#f59e0b", title="SSL Cert Change Rejected")

    def send_expiry_alert(self, job) -> None:
        subject = f"[EXPIRED] SSL Cert TCM Approval TTL Exceeded | {job.target_certkey}"
        body = (
            f"TCM ticket {job.tcm_ticket_id} was not approved within 48 hours.\n"
            f"Job {job.job_id} has been auto-aborted.\n"
            f"Please re-submit the change request."
        )
        self._send(subject, body, colour="#f97316", title="SSL Cert Approval TTL Expired")

    def _send(self, subject: str, body: str, colour: str = "#4a9eed", title: str = "") -> None:
        errors = []
        if self.smtp_cfg:
            try:
                self._send_smtp(subject, body)
            except Exception as exc:
                errors.append(f"SMTP: {exc}")
                logger.error("SMTP notification failed: %s", exc)

        if self.teams_url:
            try:
                self._send_teams(title or subject, body, colour)
            except Exception as exc:
                errors.append(f"Teams: {exc}")
                logger.error("Teams notification failed: %s", exc)

        if not self.smtp_cfg and not self.teams_url:
            logger.warning("No notification channels configured. Message: %s", subject)

    def _send_smtp(self, subject: str, body: str) -> None:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = self.smtp_cfg.get("from", "noreply@automation.local")
        msg["To"]      = ", ".join(self.recipients)
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(
            self.smtp_cfg.get("host", "localhost"),
            self.smtp_cfg.get("port", 25),
        ) as server:
            if self.smtp_cfg.get("tls"):
                server.starttls()
            if self.smtp_cfg.get("username"):
                server.login(self.smtp_cfg["username"], self.smtp_cfg["password"])
            server.send_message(msg)
        logger.info("SMTP notification sent: %s", subject)

    def _send_teams(self, title: str, body: str, colour: str) -> None:
        """Send an Adaptive Card to Microsoft Teams via incoming webhook."""
        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type":    "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type":   "TextBlock",
                                "text":   title,
                                "weight": "Bolder",
                                "size":   "Medium",
                                "color":  "Accent",
                            },
                            {
                                "type": "TextBlock",
                                "text": body,
                                "wrap": True,
                            },
                            {
                                "type": "TextBlock",
                                "text": f"Sent: {datetime.now(timezone.utc).isoformat()}",
                                "size": "Small",
                                "isSubtle": True,
                            },
                        ],
                    },
                }
            ],
        }
        resp = requests.post(self.teams_url, json=card, timeout=15)
        resp.raise_for_status()
        logger.info("Teams notification sent: %s", title)

    @staticmethod
    def _success_body(job) -> str:
        wave_lines = "\n".join(
            f"  Wave {k}: {v}" for k, v in (job.wave_results or {}).items()
        )
        return (
            f"SSL Certificate update completed successfully.\n\n"
            f"Job ID:         {job.job_id}\n"
            f"CertKey:        {job.target_certkey}\n"
            f"ADCs Updated:   {job.total_deployed}\n"
            f"TCM Ticket:     {job.tcm_ticket_id}\n"
            f"Completed At:   {datetime.now(timezone.utc).isoformat()}\n\n"
            f"Wave Summary:\n{wave_lines}"
        )

    @staticmethod
    def _failure_body(job) -> str:
        return (
            f"SSL Certificate update FAILED and was rolled back.\n\n"
            f"Job ID:       {job.job_id}\n"
            f"CertKey:      {job.target_certkey}\n"
            f"TCM Ticket:   {job.tcm_ticket_id}\n"
            f"Status:       {job.status}\n"
            f"Abort Reason: {job.abort_reason or 'See wave_results in state store'}\n\n"
            f"Action Required: Review job state and re-submit change request."
        )
