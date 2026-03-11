"""
State Store — Persistent job storage backed by SQLite (dev) or PostgreSQL (prod).
All state is externalised — processes are fully stateless.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .state_machine import CertJob, JobStatus, StateTransition

logger = logging.getLogger(__name__)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS cert_jobs (
    job_id           TEXT PRIMARY KEY,
    cert_sha256      TEXT UNIQUE,
    target_certkey   TEXT NOT NULL,
    cert_bundle_path TEXT NOT NULL,
    status           TEXT NOT NULL,
    ts_created       TEXT NOT NULL,
    ts_updated       TEXT NOT NULL,
    payload          TEXT NOT NULL   -- full JSON blob
);
CREATE INDEX IF NOT EXISTS idx_status     ON cert_jobs(status);
CREATE INDEX IF NOT EXISTS idx_sha256     ON cert_jobs(cert_sha256);
CREATE INDEX IF NOT EXISTS idx_ts_updated ON cert_jobs(ts_updated);
"""


class StateStore:
    """
    Thin persistence layer. Stores the full CertJob as a JSON blob
    alongside indexed columns for efficient querying.

    Swap the _connect() implementation for psycopg2 to use PostgreSQL in prod.
    """

    def __init__(self, db_path: str = "state/jobs.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        with self._connect() as conn:
            conn.executescript(_CREATE_TABLE)

    # ------------------------------------------------------------------ #
    # Write                                                                #
    # ------------------------------------------------------------------ #

    def save(self, job: CertJob) -> None:
        payload = json.dumps(job.to_dict(), default=str)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO cert_jobs
                    (job_id, cert_sha256, target_certkey, cert_bundle_path,
                     status, ts_created, ts_updated, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    status     = excluded.status,
                    ts_updated = excluded.ts_updated,
                    payload    = excluded.payload
                """,
                (
                    job.job_id,
                    job.cert_sha256,
                    job.target_certkey,
                    job.cert_bundle_path,
                    job.status.value,
                    job.ts_created.isoformat(),
                    job.ts_updated.isoformat(),
                    payload,
                ),
            )
        logger.debug("Saved job %s status=%s", job.job_id, job.status.value)

    def store_rollback(self, job_id: str, rollback_payload: dict) -> None:
        """Persist pre-generated rollback payload separately for fast retrieval."""
        job = self.get(job_id)
        if job:
            job.rollback_payload = rollback_payload
            self.save(job)

    # ------------------------------------------------------------------ #
    # Read                                                                 #
    # ------------------------------------------------------------------ #

    def get(self, job_id: str) -> Optional[CertJob]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM cert_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return self._deserialise(row["payload"]) if row else None

    def find_by_sha256(self, sha256: str) -> Optional[CertJob]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM cert_jobs WHERE cert_sha256 = ?", (sha256,)
            ).fetchone()
        return self._deserialise(row["payload"]) if row else None

    def get_jobs_by_status(self, status: JobStatus) -> list[CertJob]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM cert_jobs WHERE status = ?", (status.value,)
            ).fetchall()
        return [self._deserialise(r["payload"]) for r in rows]

    def get_all(self, limit: int = 100) -> list[CertJob]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM cert_jobs ORDER BY ts_updated DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._deserialise(r["payload"]) for r in rows]

    # ------------------------------------------------------------------ #
    # Internal                                                             #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _deserialise(payload_json: str) -> CertJob:
        d = json.loads(payload_json)

        history = [
            StateTransition(
                from_status=JobStatus(t["from_status"]),
                to_status=JobStatus(t["to_status"]),
                timestamp=datetime.fromisoformat(t["timestamp"]),
                reason=t.get("reason", ""),
                actor=t.get("actor", "orchestrator"),
            )
            for t in d.pop("history", [])
        ]

        d["status"] = JobStatus(d["status"])
        d["ts_created"] = datetime.fromisoformat(d["ts_created"])
        d["ts_updated"] = datetime.fromisoformat(d["ts_updated"])

        job = CertJob(**{k: v for k, v in d.items() if k != "history"})
        job.history = history
        return job
