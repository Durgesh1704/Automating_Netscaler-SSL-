"""
Wave Executor — NetScaler SSL Certificate Automation
Manages production deployment in configurable waves with automated gate checks.

Wave Strategy (default):
  Wave 1 — Canary:   5% of fleet (~12 ADCs), threshold: >1 failure = halt
  Wave 2 — Regional: 25% of fleet (~62 ADCs), threshold: >3 failures = halt
  Wave 3 — Full:     100% of fleet (~250 ADCs), threshold: >5% of wave = halt

ADC targeting uses ADM tags (not hardcoded lists) so the fleet is always current.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..executor.adm_client import ADMClient, JobBuilder, JobResult
from ..state.state_machine import CertJob, JobStatus
from ..validator.tls_validator import TLSValidator, ValidationReport

logger = logging.getLogger(__name__)


@dataclass
class WaveConfig:
    wave_number:       int
    name:              str
    pct_of_fleet:      float             # 0.0 – 1.0
    tags:              dict              # ADM tags to select target ADCs
    failure_threshold: int               # Max failures before halt
    next_status:       JobStatus


@dataclass
class WaveResult:
    wave_number:    int
    status:         str               # "PASSED" | "HALTED"
    adc_count:      int
    deployed_count: int
    failed_nodes:   list[dict]        = field(default_factory=list)
    validation:     dict | None    = None


DEFAULT_WAVE_STRATEGY = [
    WaveConfig(
        wave_number=1,
        name="Canary",
        pct_of_fleet=0.05,
        tags={"env": "prod", "tier": "canary"},
        failure_threshold=1,
        next_status=JobStatus.PROD_WAVE_2,
    ),
    WaveConfig(
        wave_number=2,
        name="Regional",
        pct_of_fleet=0.25,
        tags={"env": "prod", "region": "emea"},
        failure_threshold=3,
        next_status=JobStatus.PROD_WAVE_3,
    ),
    WaveConfig(
        wave_number=3,
        name="Full Fleet",
        pct_of_fleet=1.0,
        tags={"env": "prod"},
        failure_threshold=0,   # Set dynamically as 5% of wave size
        next_status=JobStatus.COMPLETED,
    ),
]


class WaveExecutor:
    """
    Executes a single production wave: deploy → validate → gate.
    On gate failure, calls rollback immediately using pre-generated payload.
    """

    def __init__(
        self,
        adm_client:  ADMClient,
        job_builder: JobBuilder,
        validator:   TLSValidator,
    ):
        self.adm     = adm_client
        self.builder = job_builder
        self.validator = validator

    def execute(
        self,
        job:         CertJob,
        wave_config: WaveConfig,
    ) -> WaveResult:
        """
        Deploy to wave ADCs, validate, apply gate logic.
        Returns WaveResult with status PASSED or HALTED.
        """
        # Resolve target ADCs from ADM tags (dynamic — never hardcoded)
        all_adcs = self.adm.list_managed_adcs(tags=wave_config.tags)
        adc_count = len(all_adcs)
        adc_ids   = [a["id"] for a in all_adcs]

        # Wave 3: set failure threshold dynamically (5% of wave)
        threshold = wave_config.failure_threshold
        if wave_config.wave_number == 3 and threshold == 0:
            threshold = max(1, int(adc_count * 0.05))

        logger.info(
            "Wave %d (%s): deploying to %d ADCs | failure_threshold=%d",
            wave_config.wave_number, wave_config.name, adc_count, threshold,
        )

        # Determine scenario per ADC group from delta_report
        # For simplicity, we use Scenario B if any ADC in wave needs it
        delta = job.delta_report or {}
        scenario_b_ids = {r["adc_id"] for r in delta.get("scenario_b", [])}
        wave_has_scenario_b = any(aid in scenario_b_ids for aid in adc_ids)
        scenario = "B" if wave_has_scenario_b else "A"

        # Build and run ADM job
        payload = self.builder.build_update_payload(
            adc_ids=adc_ids,
            certkey_name=job.target_certkey,
            chain_map=_ChainMapProxy(job.chain_map),
            scenario=scenario,
            vserver_type=job.chain_map.get("vserver_type", "SSL") if job.chain_map else "SSL",
        )

        job_result: JobResult = self.adm.run_job(payload)

        # Collect VIPs for validation
        vips = self._resolve_vips(all_adcs)
        expected_issuer = (
            job.chain_map["intermediates"][0]["cn"]
            if job.chain_map and job.chain_map.get("intermediates")
            else None
        )

        val_report: ValidationReport = self.validator.validate_all(
            vips=vips,
            expected_issuer=expected_issuer,
            failure_threshold=threshold,
        )

        failed_nodes = [
            {"adc_id": n.adc_id, "error": n.error}
            for n in job_result.failed_nodes
        ]
        failed_vips = [r.vip for r in val_report.failed]
        all_failures = len(failed_nodes) + len(failed_vips)

        if all_failures > threshold:
            logger.error(
                "Wave %d GATE FAILED: %d failures > threshold %d. Initiating rollback.",
                wave_config.wave_number, all_failures, threshold,
            )
            self._execute_rollback(job, adc_ids)
            return WaveResult(
                wave_number=wave_config.wave_number,
                status="HALTED",
                adc_count=adc_count,
                deployed_count=job_result.success_count,
                failed_nodes=failed_nodes,
                validation={"failed_vips": failed_vips},
            )

        logger.info(
            "Wave %d PASSED: %d/%d ADCs deployed successfully.",
            wave_config.wave_number, job_result.success_count, adc_count,
        )
        return WaveResult(
            wave_number=wave_config.wave_number,
            status="PASSED",
            adc_count=adc_count,
            deployed_count=job_result.success_count,
            failed_nodes=failed_nodes,
            validation={"failed_vips": failed_vips},
        )

    def _execute_rollback(self, job: CertJob, adc_ids: list[str]) -> None:
        """Execute the pre-generated rollback payload immediately."""
        if not job.rollback_payload:
            logger.critical(
                "ROLLBACK REQUESTED but no pre-generated payload found for job %s! "
                "Manual intervention required.",
                job.job_id,
            )
            return

        logger.warning("Executing rollback for job %s on %d ADCs", job.job_id, len(adc_ids))
        try:
            result = self.adm.run_job(job.rollback_payload)
            failed = len(result.failed_nodes)
            if failed == 0:
                logger.info("Rollback completed successfully.")
            else:
                logger.error("Rollback completed with %d node failures!", failed)
        except Exception as exc:
            logger.critical("Rollback execution failed: %s", exc)

    @staticmethod
    def _resolve_vips(adcs: list[dict]) -> list[dict]:
        """Extract primary VIP from each ADC for validation."""
        return [
            {"host": adc.get("primary_vip") or adc.get("ip_address"), "port": 443}
            for adc in adcs
            if adc.get("primary_vip") or adc.get("ip_address")
        ]


class _ChainMapProxy:
    """Thin adapter to make a chain_map dict look like ChainMap dataclass."""
    def __init__(self, d: dict):
        self._d = d or {}

    @property
    def leaf(self):
        return type("Leaf", (), {
            "pem": self._d.get("leaf", {}).get("pem", ""),
            "cn":  self._d.get("leaf", {}).get("cn", ""),
        })()

    @property
    def intermediates(self):
        return [
            type("IM", (), {"pem": im.get("pem", ""), "cn": im.get("cn", "")})()
            for im in self._d.get("intermediates", [])
        ]
