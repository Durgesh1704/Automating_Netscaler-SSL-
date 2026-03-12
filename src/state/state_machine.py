"""
State Machine — NetScaler SSL Certificate Automation
Manages job lifecycle, persistent state, and valid transitions.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .store import StateStore

logger = logging.getLogger(__name__)


class JobStatus(str, Enum):
    DETECTED         = "DETECTED"
    INSPECTED        = "INSPECTED"
    DELTA_ANALYZED   = "DELTA_ANALYZED"
    UAT_DEPLOYED     = "UAT_DEPLOYED"
    UAT_VALIDATED    = "UAT_VALIDATED"
    TCM_PENDING      = "TCM_PENDING"
    TCM_APPROVED     = "TCM_APPROVED"
    PROD_WAVE_1      = "PROD_WAVE_1"
    PROD_WAVE_2      = "PROD_WAVE_2"
    PROD_WAVE_3      = "PROD_WAVE_3"
    COMPLETED        = "COMPLETED"
    # Failure states
    VALIDATION_FAILED = "VALIDATION_FAILED"
    ROLLBACK          = "ROLLBACK"
    ROLLED_BACK       = "ROLLED_BACK"
    TCM_REJECTED      = "TCM_REJECTED"
    ABORTED           = "ABORTED"


# Valid transitions: source → set of allowed targets
VALID_TRANSITIONS: dict[JobStatus, set[JobStatus]] = {
    JobStatus.DETECTED:          {JobStatus.INSPECTED, JobStatus.ABORTED},
    JobStatus.INSPECTED:         {JobStatus.DELTA_ANALYZED, JobStatus.ABORTED},
    JobStatus.DELTA_ANALYZED:    {JobStatus.UAT_DEPLOYED, JobStatus.ABORTED},
    JobStatus.UAT_DEPLOYED:      {JobStatus.UAT_VALIDATED, JobStatus.VALIDATION_FAILED},
    JobStatus.UAT_VALIDATED:     {JobStatus.TCM_PENDING, JobStatus.VALIDATION_FAILED},
    JobStatus.TCM_PENDING:       {JobStatus.TCM_APPROVED, JobStatus.TCM_REJECTED, JobStatus.ABORTED},
    JobStatus.TCM_APPROVED:      {JobStatus.PROD_WAVE_1},
    JobStatus.PROD_WAVE_1:       {JobStatus.PROD_WAVE_2, JobStatus.VALIDATION_FAILED},
    JobStatus.PROD_WAVE_2:       {JobStatus.PROD_WAVE_3, JobStatus.VALIDATION_FAILED},
    JobStatus.PROD_WAVE_3:       {JobStatus.COMPLETED, JobStatus.VALIDATION_FAILED},
    JobStatus.COMPLETED:         set(),  # Terminal
    JobStatus.VALIDATION_FAILED: {JobStatus.ROLLBACK},
    JobStatus.ROLLBACK:          {JobStatus.ROLLED_BACK},
    JobStatus.ROLLED_BACK:       set(),  # Terminal
    JobStatus.TCM_REJECTED:      {JobStatus.ABORTED},
    JobStatus.ABORTED:           set(),  # Terminal
}

TERMINAL_STATES = {JobStatus.COMPLETED, JobStatus.ROLLED_BACK, JobStatus.ABORTED}


@dataclass
class StateTransition:
    from_status: JobStatus
    to_status:   JobStatus
    timestamp:   datetime
    reason:      str = ""
    actor:       str = "orchestrator"


@dataclass
class CertJob:
    job_id:             str
    cert_bundle_path:   str
    target_certkey:     str
    status:             JobStatus              = JobStatus.DETECTED
    ts_created:         datetime               = field(default_factory=lambda: datetime.now(timezone.utc))
    ts_updated:         datetime               = field(default_factory=lambda: datetime.now(timezone.utc))
    cert_sha256:        str | None          = None   # Dedup key
    chain_map:          dict | None         = None   # Output of inspector
    delta_report:       dict | None         = None   # Output of delta engine
    uat_job_id:         str | None          = None
    uat_validation:     dict | None         = None
    tcm_ticket_id:      str | None          = None
    tcm_age_hours:      float                  = 0.0
    rollback_payload:   dict | None         = None   # Pre-generated in TCM_APPROVED
    wave_results:       dict                   = field(default_factory=dict)
    total_deployed:     int                    = 0
    history:            list[StateTransition]  = field(default_factory=list)
    abort_reason:       str                    = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["ts_created"] = self.ts_created.isoformat()
        d["ts_updated"] = self.ts_updated.isoformat()
        d["history"] = [
            {
                "from_status": t.from_status.value,
                "to_status":   t.to_status.value,
                "timestamp":   t.timestamp.isoformat(),
                "reason":      t.reason,
                "actor":       t.actor,
            }
            for t in self.history
        ]
        return d


class StateMachine:
    """
    Manages state transitions for a CertJob.
    All transitions are validated against VALID_TRANSITIONS.
    History is appended on every transition for full audit trail.
    """

    def __init__(self, store: StateStore):
        self.store = store

    def create_job(self, cert_bundle_path: str, target_certkey: str, cert_sha256: str) -> CertJob:
        """Create a new job. Raises if a non-terminal job with same SHA256 exists (dedup)."""
        existing = self.store.find_by_sha256(cert_sha256)
        if existing and existing.status not in TERMINAL_STATES:
            raise DuplicateJobError(
                f"Active job {existing.job_id} already exists for cert {cert_sha256}"
            )

        job = CertJob(
            job_id=str(uuid.uuid4()),
            cert_bundle_path=cert_bundle_path,
            target_certkey=target_certkey,
            cert_sha256=cert_sha256,
        )
        self.store.save(job)
        logger.info("Created job %s for certkey=%s", job.job_id, target_certkey)
        return job

    def transition(
        self,
        job: CertJob,
        to_status: JobStatus,
        reason: str = "",
        actor: str = "orchestrator",
    ) -> CertJob:
        """Validate and apply a state transition. Persists to store."""
        allowed = VALID_TRANSITIONS.get(job.status, set())
        if to_status not in allowed:
            raise InvalidTransitionError(
                f"Cannot transition {job.status} → {to_status}. "
                f"Allowed: {[s.value for s in allowed]}"
            )

        transition = StateTransition(
            from_status=job.status,
            to_status=to_status,
            timestamp=datetime.now(timezone.utc),
            reason=reason,
            actor=actor,
        )
        job.history.append(transition)
        job.status = to_status
        job.ts_updated = datetime.now(timezone.utc)

        self.store.save(job)
        logger.info(
            "Job %s: %s → %s | reason=%s",
            job.job_id, transition.from_status.value, to_status.value, reason
        )
        return job


class InvalidTransitionError(Exception):
    pass


class DuplicateJobError(Exception):
    pass
