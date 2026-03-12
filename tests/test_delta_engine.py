from __future__ import annotations

from datetime import datetime, timezone

from src.delta.delta_engine import DeltaEngine, Scenario
from src.inspector.inspector import ChainMap, CertInfo, CertRole


class MockADMClient:
    def __init__(self, adcs, certkeys, errors=None):
        self._adcs = adcs
        self._certkeys = certkeys
        self._errors = errors or set()

    def list_managed_adcs(self):
        return self._adcs

    def get_certkey(self, adc_id, certkey_name):
        if adc_id in self._errors:
            raise RuntimeError(f"boom-{adc_id}")
        return self._certkeys.get(adc_id)


def _cert(role: CertRole, cn: str, serial: int, aki: str | None, ski: str | None) -> CertInfo:
    now = datetime.now(timezone.utc)
    return CertInfo(
        role=role,
        cn=cn,
        serial=serial,
        serial_hex=hex(serial),
        aki=aki,
        ski=ski,
        not_before=now,
        not_after=now,
        sans=["vpn.corp.com"],
        issuer_cn="issuer",
        sha256="a" * 64,
        pem="pem",
    )


def _chain_map() -> ChainMap:
    leaf = _cert(CertRole.LEAF, "leaf", 101, "im-ski", "leaf-ski")
    im = _cert(CertRole.INTERMEDIATE, "im", 202, "root-ski", "im-ski")
    root = _cert(CertRole.ROOT, "root", 303, None, "root-ski")
    return ChainMap(leaf=leaf, intermediates=[im], root=root, bundle_sha256="b" * 64)


def test_analyze_routes_adcs_to_a_b_no_change_and_errors():
    adcs = [
        {"id": "adc-a", "name": "ADC A"},
        {"id": "adc-b", "name": "ADC B"},
        {"id": "adc-nc", "name": "ADC NC"},
        {"id": "adc-miss", "name": "ADC Missing"},
        {"id": "adc-err", "name": "ADC Err"},
    ]
    certkeys = {
        "adc-a": {"leaf_serial": 1, "intermediate_serial": 202},
        "adc-b": {"leaf_serial": 2, "intermediate_serial": 999},
        "adc-nc": {"leaf_serial": 101, "intermediate_serial": 202},
        "adc-miss": None,
    }
    engine = DeltaEngine(MockADMClient(adcs, certkeys, errors={"adc-err"}))

    report = engine.analyze(_chain_map(), target_certkey="cert_vpn_prod")

    assert len(report.scenario_a) == 1
    assert report.scenario_a[0].adc_id == "adc-a"
    assert report.scenario_a[0].scenario == Scenario.A

    assert len(report.scenario_b) == 2
    assert {r.adc_id for r in report.scenario_b} == {"adc-b", "adc-miss"}

    assert len(report.no_change) == 1
    assert report.no_change[0].adc_id == "adc-nc"

    assert len(report.errors) == 1
    assert report.errors[0]["adc_id"] == "adc-err"
    assert report.total_requiring_update == 3
