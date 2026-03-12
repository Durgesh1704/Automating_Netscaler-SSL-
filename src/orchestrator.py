"""
Orchestrator — NetScaler SSL Certificate Automation
Main entry point. Drives the state machine through the full lifecycle.

Usage:
    python orchestrator.py --cert-bundle /path/to/bundle.pem \
                           --target-certkey cert_vpn_prod \
                           --vserver-type VPN
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import sys
from pathlib import Path

import yaml

from src.delta.delta_engine import DeltaEngine
from src.executor.adm_client import ADMClient, JobBuilder
from src.executor.wave_executor import DEFAULT_WAVE_STRATEGY, WaveExecutor, WaveResult
from src.inspector.inspector import Inspector
from src.notifier.notifier import Notifier
from src.state.state_machine import JobStatus, StateMachine
from src.state.store import StateStore
from src.tcm.tcm_manager import ServiceNowClient, TCMManager
from src.validator.tls_validator import TLSValidator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("orchestrator")


def load_config(path: str = "config/settings.yaml") -> dict:
    """
    Load YAML config and resolve any ${ENV_VAR} placeholders from the environment.

    Example in settings.yaml:
        password: ${ADM_PASSWORD}

    Raises EnvironmentError if a referenced variable is not set.
    """
    import os
    import re

    with open(path) as f:
        raw = f.read()

    # Strip YAML comments before scanning for placeholders
    # so ${VAR_NAME} in comment text is not treated as a real reference
    lines_no_comments = []
    for line in raw.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            lines_no_comments.append("")   # blank out full-comment lines
        elif " #" in line:
            lines_no_comments.append(line[: line.index(" #")])  # strip inline comment
        else:
            lines_no_comments.append(line)
    raw_no_comments = "\n".join(lines_no_comments)

    # Find all ${VAR_NAME} placeholders in non-comment content
    placeholders = re.findall(r"\$\{([^}]+)\}", raw_no_comments)
    missing = [v for v in placeholders if v not in os.environ]
    if missing:
        raise OSError(
            f"Missing required environment variables: {missing}\n"
            f"Set them before running, e.g.:\n"
            + "\n".join(f"  export {v}=<value>" for v in missing)
        )

    # Substitute placeholders in the FULL raw (comments are harmless after validation)
    resolved = re.sub(
        r"\$\{([^}]+)\}",
        lambda m: os.environ.get(m.group(1), m.group(0)),   # leave unmatched as-is
        raw,
    )
    return yaml.safe_load(resolved)


def build_clients(cfg: dict):
    """Instantiate all integration clients from config."""
    adm = ADMClient(
        host=cfg["adm"]["host"],
        username=cfg["adm"]["username"],
        password=cfg["adm"]["password"],
        verify_ssl=cfg["adm"].get("verify_ssl", True),
    )
    itsm = ServiceNowClient(
        instance=cfg["itsm"]["servicenow_instance"],
        username=cfg["itsm"]["username"],
        password=cfg["itsm"]["password"],
    )
    return adm, itsm


def run(args: argparse.Namespace, cfg: dict) -> int:
    """
    Full orchestration run. Returns exit code: 0=success, 1=failure.
    """
    # ------------------------------------------------------------------ #
    # Initialise                                                           #
    # ------------------------------------------------------------------ #
    store   = StateStore(db_path=cfg.get("state_db", "state/jobs.db"))
    sm      = StateMachine(store)
    adm, itsm = build_clients(cfg)

    inspector    = Inspector(known_vip_sans=cfg.get("known_vip_sans", []))
    delta_engine = DeltaEngine(adm_client=adm)
    validator    = TLSValidator(timeout=cfg.get("tls_timeout", 10))
    job_builder  = JobBuilder()
    tcm_manager  = TCMManager(itsm_client=itsm)

    bundle_pem = Path(args.cert_bundle).read_bytes()

    # ------------------------------------------------------------------ #
    # DETECTED                                                             #
    # ------------------------------------------------------------------ #
    cert_sha256 = hashlib.sha256(bundle_pem).hexdigest()
    job = sm.create_job(
        cert_bundle_path=args.cert_bundle,
        target_certkey=args.target_certkey,
        cert_sha256=cert_sha256,
    )
    logger.info("Job %s created | sha256=%s...", job.job_id, cert_sha256[:16])

    # ------------------------------------------------------------------ #
    # INSPECTED                                                            #
    # ------------------------------------------------------------------ #
    try:
        chain_map = inspector.inspect(bundle_pem)
        job.chain_map = {
            "leaf": chain_map.leaf.__dict__,
            "intermediates": [im.__dict__ for im in chain_map.intermediates],
            "root": chain_map.root.__dict__ if chain_map.root else None,
            "bundle_sha256": chain_map.bundle_sha256,
            "vserver_type": args.vserver_type,
        }
        job = sm.transition(job, JobStatus.INSPECTED, reason="Bundle inspected successfully")
    except Exception as exc:
        logger.error("Inspection failed: %s", exc)
        sm.transition(job, JobStatus.ABORTED, reason=f"Inspection error: {exc}")
        return 1

    # ------------------------------------------------------------------ #
    # DELTA ANALYZED                                                       #
    # ------------------------------------------------------------------ #
    try:
        delta_report = delta_engine.analyze(chain_map, args.target_certkey)
        job.delta_report = {
            "scenario_a": [r.__dict__ for r in delta_report.scenario_a],
            "scenario_b": [r.__dict__ for r in delta_report.scenario_b],
            "no_change":  [r.__dict__ for r in delta_report.no_change],
            "errors":     delta_report.errors,
        }
        job = sm.transition(job, JobStatus.DELTA_ANALYZED, reason="Delta analysis complete")
    except Exception as exc:
        logger.error("Delta analysis failed: %s", exc)
        sm.transition(job, JobStatus.ABORTED, reason=f"Delta error: {exc}")
        return 1

    if delta_report.total_requiring_update == 0:
        logger.info("No ADCs require update. Job complete.")
        sm.transition(job, JobStatus.ABORTED, reason="No ADCs require update")
        return 0

    # ------------------------------------------------------------------ #
    # UAT DEPLOYED                                                         #
    # ------------------------------------------------------------------ #
    uat_adcs = cfg.get("uat_adcs", [])
    if not uat_adcs:
        logger.warning("No UAT ADCs configured — skipping UAT phase.")
    else:
        try:
            uat_payload = job_builder.build_update_payload(
                adc_ids=uat_adcs,
                certkey_name=args.target_certkey,
                chain_map=chain_map,
                scenario="B" if delta_report.scenario_b else "A",
                vserver_type=args.vserver_type,
            )
            uat_result = adm.run_job(uat_payload)
            job.uat_job_id = uat_result.job_id
            job = sm.transition(job, JobStatus.UAT_DEPLOYED, reason="UAT job submitted")

            # ------------------------------------------------------------------ #
            # UAT VALIDATED                                                       #
            # ------------------------------------------------------------------ #
            uat_vips = cfg.get("uat_vips", [])
            val_report = validator.validate_all(
                vips=uat_vips,
                expected_issuer=chain_map.intermediates[0].cn if chain_map.intermediates else None,
                failure_threshold=0,
            )
            job.uat_validation = {
                "passed_all": val_report.passed_all,
                "results": [r.__dict__ for r in val_report.results],
            }

            if not val_report.passed_all:
                logger.error("UAT validation FAILED.")
                sm.transition(job, JobStatus.VALIDATION_FAILED, reason="UAT TLS validation failed")
                return 1

            job = sm.transition(job, JobStatus.UAT_VALIDATED, reason="UAT validation passed")
        except Exception as exc:
            logger.error("UAT phase error: %s", exc)
            sm.transition(job, JobStatus.VALIDATION_FAILED, reason=str(exc))
            return 1

    # ------------------------------------------------------------------ #
    # TCM PENDING                                                          #
    # ------------------------------------------------------------------ #
    preflight_log = delta_report.to_preflight_log()
    if job.uat_validation and job.uat_validation.get("results"):
        uat_summary = "\n".join(
            "  [PASS] {vip}:{port} | chain_depth={chain_depth} | issuer={issuer_cn} | expires={expiry} ({days_to_expiry}d)".format(**r)
            if r.get("passed") else
            "  [FAIL] {vip}:{port} | {failure_reason}".format(**r)
            for r in job.uat_validation["results"]
        )
    else:
        uat_summary = "UAT skipped"

    ticket = tcm_manager.create_change_ticket(
        job_id=job.job_id,
        cert_cn=chain_map.leaf.cn,
        certkey_name=args.target_certkey,
        preflight_log=preflight_log,
        uat_summary=str(uat_summary),
        adc_count=delta_report.total_requiring_update,
    )
    job.tcm_ticket_id = ticket.ticket_id
    job = sm.transition(job, JobStatus.TCM_PENDING, reason=f"TCM ticket: {ticket.ticket_id}")

    logger.info(
        "Job %s is now TCM_PENDING. "
        "The TCM poller (run_poller.sh) will check approval every 15 minutes. "
        "Exiting main process.",
        job.job_id,
    )
    # The main process exits here. The poller handles approval and calls
    # continue_after_approval() when TCM_APPROVED.
    return 0


def continue_after_approval(job_id: str, cfg: dict) -> int:
    """
    Called by tcm_poller.py after TCM approval is detected.
    Resumes from TCM_APPROVED → waves → COMPLETED.
    """
    store  = StateStore(db_path=cfg.get("state_db", "state/jobs.db"))
    sm     = StateMachine(store)
    job    = store.get(job_id)
    if not job:
        logger.error("Job %s not found in state store.", job_id)
        return 1

    adm, itsm    = build_clients(cfg)
    validator    = TLSValidator()
    job_builder  = JobBuilder()
    wave_executor = WaveExecutor(adm, job_builder, validator)
    tcm_manager  = TCMManager(itsm_client=itsm)
    notifier = Notifier(cfg=cfg.get("notifications", {}))

    # ------------------------------------------------------------------ #
    # TCM APPROVED — pre-generate rollback                                 #
    # ------------------------------------------------------------------ #
    # Fetch original cert from ADC for rollback
    original_certkey = adm.get_certkey(
        adm.list_managed_adcs(tags={"env": "prod", "tier": "canary"})[0]["id"],
        job.target_certkey,
    )
    rollback_payload = job_builder.build_rollback_payload(
        adc_ids=[a["id"] for a in adm.list_managed_adcs(tags={"env": "prod"})],
        certkey_name=job.target_certkey,
        original_cert_pem="",  # Fetched from SCV or ADM store in production
        original_im_certkey=original_certkey.get("linked_certkey") if original_certkey else None,
    )
    job.rollback_payload = rollback_payload
    job = sm.transition(job, JobStatus.TCM_APPROVED, reason="TCM approved. Rollback pre-generated.")

    # ------------------------------------------------------------------ #
    # Production Waves                                                     #
    # ------------------------------------------------------------------ #
    for wave_cfg in DEFAULT_WAVE_STRATEGY:
        wave_status = JobStatus[f"PROD_WAVE_{wave_cfg.wave_number}"]
        job = sm.transition(job, wave_status, reason=f"Starting {wave_cfg.name} wave")

        result: WaveResult = wave_executor.execute(job, wave_cfg)
        job.wave_results[f"wave_{wave_cfg.wave_number}"] = result.__dict__
        job.total_deployed += result.deployed_count
        store.save(job)

        if result.status == "HALTED":
            job = sm.transition(
                job, JobStatus.VALIDATION_FAILED,
                reason=f"Wave {wave_cfg.wave_number} gate failed: {result.failed_nodes}",
            )
            job = sm.transition(job, JobStatus.ROLLBACK, reason="Initiating pre-generated rollback")
            job = sm.transition(job, JobStatus.ROLLED_BACK, reason="Rollback complete")
            notifier.send_failure(job)
            return 1

    # ------------------------------------------------------------------ #
    # COMPLETED                                                            #
    # ------------------------------------------------------------------ #
    job = sm.transition(job, JobStatus.COMPLETED, reason="All waves passed.")
    tcm_manager.close_with_summary(
        ticket_id=job.tcm_ticket_id,
        job_id=job.job_id,
        wave_results=job.wave_results,
        total_deployed=job.total_deployed,
    )
    notifier.send_success(job)
    logger.info("Job %s COMPLETED. %d ADCs updated.", job.job_id, job.total_deployed)
    return 0


def main():
    parser = argparse.ArgumentParser(description="NetScaler SSL Cert Automation Orchestrator")
    parser.add_argument("--cert-bundle",   required=True, help="Path to PEM cert bundle")
    parser.add_argument("--target-certkey",required=True, help="ADC certkey name (e.g. cert_vpn_prod)")
    parser.add_argument("--vserver-type",  default="SSL",  help="VPN | AOVPN | SSL_BRIDGE | SSL")
    parser.add_argument("--config",        default="config/settings.yaml")
    parser.add_argument("--resume-job",    help="Resume an existing job from TCM_APPROVED state")
    args = parser.parse_args()

    cfg = load_config(args.config)

    if args.resume_job:
        sys.exit(continue_after_approval(args.resume_job, cfg))
    else:
        sys.exit(run(args, cfg))


if __name__ == "__main__":
    main()
