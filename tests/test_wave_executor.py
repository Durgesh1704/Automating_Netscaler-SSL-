from __future__ import annotations

from datetime import datetime, timezone

from src.executor.adm_client import JobResult, NodeResult
from src.executor.wave_executor import WaveConfig, WaveExecutor
from src.state.state_machine import CertJob, JobStatus


class MockADM:
    def __init__(self, adcs, results):
        self._adcs = adcs
        self._results = list(results)
        self.run_calls = []

    def list_managed_adcs(self, tags=None):
        return self._adcs

    def run_job(self, payload):
        self.run_calls.append(payload)
        return self._results.pop(0)


class MockBuilder:
    def __init__(self):
        self.calls = []

    def build_update_payload(self, **kwargs):
        self.calls.append(kwargs)
        return {"payload": "deploy", "scenario": kwargs["scenario"]}


class MockValidator:
    def __init__(self, reports):
        self._reports = list(reports)
        self.calls = []

    def validate_all(self, **kwargs):
        self.calls.append(kwargs)
        return self._reports.pop(0)


class _Report:
    def __init__(self, failed):
        self.failed = failed


def _job() -> CertJob:
    now = datetime.now(timezone.utc)
    return CertJob(
        job_id="job-1",
        cert_bundle_path="/tmp/bundle.pem",
        target_certkey="cert_vpn_prod",
        status=JobStatus.PROD_WAVE_1,
        ts_created=now,
        ts_updated=now,
        chain_map={
            "leaf": {"cn": "vpn.corp.com", "pem": "leafpem"},
            "intermediates": [{"cn": "Test Intermediate", "pem": "impem"}],
            "vserver_type": "SSL",
        },
        delta_report={"scenario_b": [{"adc_id": "adc-b"}]},
        rollback_payload={"payload": "rollback"},
    )


def test_wave_passes_when_failures_within_threshold():
    adcs = [{"id": "adc-a", "ip_address": "127.0.0.1"}, {"id": "adc-b", "ip_address": "127.0.0.2"}]
    deploy_result = JobResult(
        job_id="deploy-1",
        overall="PARTIAL",
        node_results=[NodeResult(adc_id="adc-a", status="SUCCESS"), NodeResult(adc_id="adc-b", status="FAILED", error="x")],
    )
    adm = MockADM(adcs, [deploy_result])
    builder = MockBuilder()
    validator = MockValidator([_Report(failed=[])])

    cfg = WaveConfig(1, "Canary", 0.05, {"env": "prod"}, failure_threshold=1, next_status=JobStatus.PROD_WAVE_2)
    result = WaveExecutor(adm, builder, validator).execute(_job(), cfg)

    assert result.status == "PASSED"
    assert result.deployed_count == 1
    assert len(adm.run_calls) == 1
    assert builder.calls[0]["scenario"] == "B"


def test_wave_halts_and_rolls_back_when_failures_exceed_threshold():
    adcs = [{"id": "adc-a", "primary_vip": "127.0.0.1"}, {"id": "adc-b", "primary_vip": "127.0.0.2"}]
    deploy_result = JobResult(
        job_id="deploy-1",
        overall="PARTIAL",
        node_results=[NodeResult(adc_id="adc-a", status="FAILED", error="x"), NodeResult(adc_id="adc-b", status="FAILED", error="y")],
    )
    rollback_result = JobResult(
        job_id="rb-1",
        overall="SUCCESS",
        node_results=[NodeResult(adc_id="adc-a", status="SUCCESS"), NodeResult(adc_id="adc-b", status="SUCCESS")],
    )

    adm = MockADM(adcs, [deploy_result, rollback_result])
    builder = MockBuilder()
    validator = MockValidator([_Report(failed=[type("R", (), {"vip": "127.0.0.1"})()])])

    cfg = WaveConfig(1, "Canary", 0.05, {"env": "prod"}, failure_threshold=1, next_status=JobStatus.PROD_WAVE_2)
    result = WaveExecutor(adm, builder, validator).execute(_job(), cfg)

    assert result.status == "HALTED"
    assert len(adm.run_calls) == 2  # deploy + rollback


def test_wave3_uses_dynamic_failure_threshold_for_validator_gate():
    adcs = [{"id": f"adc-{i}", "ip_address": f"10.0.0.{i}"} for i in range(1, 41)]
    deploy_result = JobResult(
        job_id="deploy-1",
        overall="SUCCESS",
        node_results=[NodeResult(adc_id=a["id"], status="SUCCESS") for a in adcs],
    )
    adm = MockADM(adcs, [deploy_result])
    builder = MockBuilder()
    validator = MockValidator([_Report(failed=[type("R", (), {"vip": "10.0.0.1"})(), type("R", (), {"vip": "10.0.0.2"})()])])

    cfg = WaveConfig(3, "Full Fleet", 1.0, {"env": "prod"}, failure_threshold=0, next_status=JobStatus.COMPLETED)
    result = WaveExecutor(adm, builder, validator).execute(_job(), cfg)

    assert validator.calls[0]["failure_threshold"] == 2  # 5% of 40
    assert result.status == "PASSED"  # failures equal threshold is still allowed
