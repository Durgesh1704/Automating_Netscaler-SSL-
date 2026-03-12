"""
TCM Integration — NetScaler SSL Certificate Automation
Handles ITSM change ticket creation, polling, and closure.

Design:
  - Ticket creation and state persistence happen in a SINGLE call.
  - The main process NEVER sleeps waiting for approval.
  - A SEPARATE scheduled poller (run_poller.sh → tcm_poller.py) checks status.
  - 48-hour TTL: unapproved tickets auto-expire with an alert.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)

TCM_TTL_HOURS = 48


class TCMStatus(str):
    PENDING   = "pending"
    APPROVED  = "approved"
    REJECTED  = "rejected"
    CANCELLED = "cancelled"
    CLOSED    = "closed"


@dataclass
class TCMTicket:
    ticket_id:    str
    url:          str
    status:       str
    created_at:   datetime
    approved_at:  datetime | None = None
    rejected_at:  datetime | None = None


class ITSMClient(ABC):
    """Abstract base — implement for ServiceNow or Jira."""

    @abstractmethod
    def create_change(self, title: str, description: str, attachments: list[str]) -> TCMTicket:
        ...

    @abstractmethod
    def get_status(self, ticket_id: str) -> str:
        ...

    @abstractmethod
    def close_ticket(self, ticket_id: str, resolution: str) -> None:
        ...

    @abstractmethod
    def add_comment(self, ticket_id: str, comment: str) -> None:
        ...


class ServiceNowClient(ITSMClient):
    """
    ServiceNow Change Management integration via REST API.
    Targets the /api/now/table/change_request endpoint.
    """

    def __init__(self, instance: str, username: str, password: str):
        self.base_url = f"https://{instance}.service-now.com/api/now"
        self.auth     = (username, password)
        self.headers  = {
            "Content-Type": "application/json",
            "Accept":       "application/json",
        }

    def create_change(
        self,
        title:       str,
        description: str,
        attachments: list[str] = None,
    ) -> TCMTicket:
        payload = {
            "short_description": title,
            "description":       description,
            "type":              "standard",
            "category":          "Network",
            "risk":              "low",
            "impact":            "2",
            "priority":          "3",
            "assignment_group":  "Network Engineering",
        }

        resp = requests.post(
            f"{self.base_url}/table/change_request",
            json=payload,
            auth=self.auth,
            headers=self.headers,
            timeout=30,
        )
        resp.raise_for_status()
        data      = resp.json()["result"]
        ticket_id = data["sys_id"]
        number    = data["number"]

        logger.info("Created ServiceNow change: %s (sys_id=%s)", number, ticket_id)

        # Attach pre-flight report as text attachment
        if attachments:
            for attachment_text in attachments:
                self._attach_text(ticket_id, "preflight_report.txt", attachment_text)

        return TCMTicket(
            ticket_id=ticket_id,
            url=f"https://{self.base_url.split('/')[2]}/nav_to.do?uri=change_request.do?sys_id={ticket_id}",
            status=TCMStatus.PENDING,
            created_at=datetime.now(timezone.utc),
        )

    def get_status(self, ticket_id: str) -> str:
        resp = requests.get(
            f"{self.base_url}/table/change_request/{ticket_id}",
            params={"sysparm_fields": "state,approval"},
            auth=self.auth,
            headers=self.headers,
            timeout=20,
        )
        resp.raise_for_status()
        result   = resp.json()["result"]
        approval = result.get("approval", "")
        state    = result.get("state", "")

        if approval == "approved":
            return TCMStatus.APPROVED
        if approval in ("rejected", "cancelled") or state == "6":  # 6 = Closed/Cancelled
            return TCMStatus.REJECTED
        return TCMStatus.PENDING

    def close_ticket(self, ticket_id: str, resolution: str) -> None:
        resp = requests.patch(
            f"{self.base_url}/table/change_request/{ticket_id}",
            json={
                "state":              "3",    # Closed
                "close_code":         "successful",
                "close_notes":        resolution,
                "work_end":           datetime.now(timezone.utc).isoformat(),
            },
            auth=self.auth,
            headers=self.headers,
            timeout=30,
        )
        resp.raise_for_status()
        logger.info("Closed ServiceNow change %s", ticket_id)

    def add_comment(self, ticket_id: str, comment: str) -> None:
        requests.post(
            f"{self.base_url}/table/change_request/{ticket_id}",
            json={"work_notes": comment},
            auth=self.auth,
            headers=self.headers,
            timeout=20,
        ).raise_for_status()

    def _attach_text(self, ticket_id: str, filename: str, content: str) -> None:
        requests.post(
            f"{self.base_url}/attachment/file",
            params={
                "table_name":     "change_request",
                "table_sys_id":   ticket_id,
                "file_name":      filename,
            },
            data=content.encode(),
            headers={**self.headers, "Content-Type": "text/plain"},
            auth=self.auth,
            timeout=30,
        )


class TCMManager:
    """
    Orchestrates TCM ticket lifecycle: create, poll (via poller), close.
    """

    def __init__(self, itsm_client: ITSMClient):
        self.itsm = itsm_client

    def create_change_ticket(
        self,
        job_id:        str,
        cert_cn:       str,
        certkey_name:  str,
        preflight_log: str,
        uat_summary:   str,
        adc_count:     int,
    ) -> TCMTicket:
        """
        Creates the ITSM change ticket and returns immediately.
        The calling orchestrator persists ticket_id to the state store and EXITS.
        A separate poller handles approval wait.
        """
        title = (
            f"[AUTO] SSL Cert Update | {cert_cn} | {certkey_name} | "
            f"{adc_count} ADCs | {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
        )
        description = self._build_description(
            job_id, cert_cn, certkey_name, adc_count, preflight_log, uat_summary
        )

        ticket = self.itsm.create_change(
            title=title,
            description=description,
            attachments=[preflight_log, uat_summary],
        )
        logger.info(
            "TCM ticket created: %s (TTL=%dh) | URL: %s",
            ticket.ticket_id, TCM_TTL_HOURS, ticket.url,
        )
        return ticket

    def check_approval(self, ticket_id: str, created_at: datetime) -> str:
        """
        Called by the SEPARATE poller (not the main orchestrator).
        Returns: "approved" | "rejected" | "pending" | "expired"
        """
        now = datetime.now(timezone.utc)
        age_hours = (now - created_at).total_seconds() / 3600

        if age_hours > TCM_TTL_HOURS:
            logger.warning(
                "TCM ticket %s has exceeded %dh TTL (age=%.1fh). Auto-expiring.",
                ticket_id, TCM_TTL_HOURS, age_hours,
            )
            return "expired"

        status = self.itsm.get_status(ticket_id)
        logger.info(
            "TCM ticket %s status=%s (age=%.1fh / %dh TTL)",
            ticket_id, status, age_hours, TCM_TTL_HOURS,
        )
        return status

    def close_with_summary(
        self,
        ticket_id:   str,
        job_id:      str,
        wave_results: dict,
        total_deployed: int,
    ) -> None:
        """Auto-closes the TCM ticket after successful PROD_WAVE_3."""
        resolution = self._build_resolution(job_id, wave_results, total_deployed)
        self.itsm.close_ticket(ticket_id, resolution)

    @staticmethod
    def _build_description(
        job_id: str, cert_cn: str, certkey_name: str,
        adc_count: int, preflight_log: str, uat_summary: str,
    ) -> str:
        return f"""
AUTOMATED SSL CERTIFICATE UPDATE
=================================
Job ID:       {job_id}
Certificate:  {cert_cn}
CertKey Name: {certkey_name}
Target ADCs:  {adc_count}
Requested:    {datetime.now(timezone.utc).isoformat()}
TTL:          {TCM_TTL_HOURS} hours (auto-expires if not approved)

--- PRE-FLIGHT DELTA REPORT ---
{preflight_log}

--- UAT VALIDATION SUMMARY ---
{uat_summary}

This change was generated automatically by the NetScaler SSL Automation platform.
Approval triggers deployment in 3 waves: Canary (5%) → Regional (25%) → Full Fleet (100%).
Rollback payload is pre-generated and available for immediate execution if any wave fails.
""".strip()

    @staticmethod
    def _build_resolution(job_id: str, wave_results: dict, total_deployed: int) -> str:
        return (
            f"Automated SSL cert update completed successfully.\n"
            f"Job ID: {job_id}\n"
            f"Total ADCs updated: {total_deployed}\n"
            f"Wave results: {wave_results}\n"
            f"Completed at: {datetime.now(timezone.utc).isoformat()}"
        )
