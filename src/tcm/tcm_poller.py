"""
TCM Poller — NetScaler SSL Certificate Automation
Standalone process scheduled via cron (every 15 min).
Checks approval status of all TCM_PENDING jobs and triggers production rollout.

This is intentionally a SEPARATE process from the orchestrator — it reads
state from the store, makes a single API call, and exits. No sleeping.

Cron entry (every 15 min):
  */15 * * * * /opt/netscaler-ssl-auto/scripts/run_poller.sh >> /var/log/tcm_poller.log 2>&1
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone

import yaml

from src.state.state_machine import StateMachine, JobStatus
from src.state.store import StateStore
from src.tcm.tcm_manager import TCMManager, ServiceNowClient
from src.notifier.notifier import Notifier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("tcm_poller")


def load_config(path: str = "config/settings.yaml") -> dict:
    """Load config resolving ${ENV_VAR} placeholders from environment."""
    import os
    import re

    with open(path) as f:
        raw = f.read()

    lines_no_comments = []
    for line in raw.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            lines_no_comments.append("")
        elif " #" in line:
            lines_no_comments.append(line[: line.index(" #")])
        else:
            lines_no_comments.append(line)
    raw_no_comments = "\n".join(lines_no_comments)

    placeholders = re.findall(r"\$\{([^}]+)\}", raw_no_comments)
    missing = [v for v in placeholders if v not in os.environ]
    if missing:
        raise EnvironmentError(
            f"Missing required environment variables: {missing}\n"
            + "\n".join(f"  export {v}=<value>" for v in missing)
        )

    resolved = re.sub(
        r"\$\{([^}]+)\}",
        lambda m: os.environ.get(m.group(1), m.group(0)),
        raw,
    )
    return yaml.safe_load(resolved)


def poll(cfg: dict) -> int:
    store = StateStore(db_path=cfg.get("state_db", "state/jobs.db"))
    sm    = StateMachine(store)

    itsm = ServiceNowClient(
        instance=cfg["itsm"]["servicenow_instance"],
        username=cfg["itsm"]["username"],
        password=cfg["itsm"]["password"],
    )
    tcm_manager = TCMManager(itsm_client=itsm)
    notifier    = Notifier(cfg=cfg.get("notifications", {}))

    pending_jobs = store.get_jobs_by_status(JobStatus.TCM_PENDING)
    logger.info("TCM Poller: %d pending jobs found.", len(pending_jobs))

    for job in pending_jobs:
        if not job.tcm_ticket_id:
            logger.warning("Job %s has no TCM ticket ID — skipping.", job.job_id)
            continue

        status = tcm_manager.check_approval(
            ticket_id=job.tcm_ticket_id,
            created_at=job.ts_created,
        )

        if status == "approved":
            logger.info("Job %s APPROVED. Triggering production rollout.", job.job_id)
            sm.transition(job, JobStatus.TCM_APPROVED, reason="TCM approved via poller")

            # Kick off the production rollout as a subprocess
            # (avoids running long-lived code inside the poller)
            import subprocess
            result = subprocess.run(
                [
                    sys.executable, "src/orchestrator.py",
                    "--cert-bundle",    job.cert_bundle_path,
                    "--target-certkey", job.target_certkey,
                    "--resume-job",     job.job_id,
                ],
                capture_output=False,
            )
            if result.returncode != 0:
                logger.error("Production rollout for job %s exited with code %d",
                             job.job_id, result.returncode)

        elif status == "rejected":
            logger.warning("Job %s REJECTED by TCM.", job.job_id)
            job = sm.transition(job, JobStatus.TCM_REJECTED, reason="TCM rejected")
            sm.transition(job, JobStatus.ABORTED, reason="TCM rejected — no changes applied")
            notifier.send_rejection(job)

        elif status == "expired":
            logger.warning("Job %s TCM TTL expired. Auto-aborting.", job.job_id)
            sm.transition(job, JobStatus.ABORTED, reason="TCM approval TTL exceeded")
            notifier.send_expiry_alert(job)

        else:
            logger.info("Job %s still pending approval.", job.job_id)

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TCM Approval Poller")
    parser.add_argument("--config", default="config/settings.yaml")
    args = parser.parse_args()
    cfg = load_config(args.config)
    sys.exit(poll(cfg))
