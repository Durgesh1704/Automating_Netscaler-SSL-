"""
Delta Engine — NetScaler SSL Certificate Automation
Compares the incoming cert chain against the live chain on each target ADC via ADM Nitro.

Decision Matrix:
  Scenario A — Leaf swap only   (Intermediate serial unchanged)
  Scenario B — Full chain swap  (New/different Intermediate detected)
  No-Change  — ADC already serving this exact chain
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..inspector.inspector import ChainMap

logger = logging.getLogger(__name__)


class Scenario(str):
    A         = "A"          # Leaf swap only
    B         = "B"          # Full chain replacement
    NO_CHANGE = "NO_CHANGE"  # Already current


@dataclass
class ADCDeltaResult:
    adc_id:      str
    adc_name:    str
    scenario:    str   # "A", "B", "NO_CHANGE"
    live_serial: int | None = None
    new_serial:  int | None = None
    reason:      str = ""


@dataclass
class DeltaReport:
    scenario_a:  list[ADCDeltaResult] = field(default_factory=list)
    scenario_b:  list[ADCDeltaResult] = field(default_factory=list)
    no_change:   list[ADCDeltaResult] = field(default_factory=list)
    errors:      list[dict]           = field(default_factory=list)

    @property
    def total_requiring_update(self) -> int:
        return len(self.scenario_a) + len(self.scenario_b)

    def to_preflight_log(self) -> str:
        lines = [
            "=== PRE-FLIGHT DELTA REPORT ===",
            f"  Scenario A (Leaf swap only):   {len(self.scenario_a)} ADCs",
            f"  Scenario B (Full chain swap):  {len(self.scenario_b)} ADCs",
            f"  No change required:            {len(self.no_change)} ADCs",
            f"  Query errors:                  {len(self.errors)} ADCs",
            "",
        ]
        if self.scenario_b:
            lines.append("  [SCENARIO B — New Intermediate detected]")
            for r in self.scenario_b:
                lines.append(
                    f"    {r.adc_name} ({r.adc_id}): "
                    f"live_serial={hex(r.live_serial) if r.live_serial else 'N/A'} "
                    f"→ new_serial={hex(r.new_serial) if r.new_serial else 'N/A'}"
                )
        if self.errors:
            lines.append("")
            lines.append("  [ERRORS — ADCs not queried successfully]")
            for e in self.errors:
                lines.append(f"    {e}")
        return "\n".join(lines)


class DeltaEngine:
    """
    Queries ADM Nitro for live cert info on each managed ADC and computes
    Scenario A / B / NO_CHANGE for each.
    """

    def __init__(self, adm_client):
        """
        Args:
            adm_client: Instance of ADMClient (see executor/adm_client.py)
        """
        self.adm = adm_client

    def analyze(self, chain_map: ChainMap, target_certkey: str) -> DeltaReport:
        """
        Main entry point. Queries all managed ADCs and returns a DeltaReport.

        Args:
            chain_map:       Output from Inspector
            target_certkey:  Name of the certkey on the ADC (e.g. "cert_vpn_prod")
        """
        report = DeltaReport()
        adcs = self.adm.list_managed_adcs()

        logger.info(
            "Delta analysis starting: %d ADCs, certkey=%s", len(adcs), target_certkey
        )

        new_intermediate_serial = (
            chain_map.intermediates[0].serial if chain_map.intermediates else None
        )

        for adc in adcs:
            try:
                result = self._analyze_single(
                    adc, target_certkey, new_intermediate_serial, chain_map
                )
                if result.scenario == Scenario.A:
                    report.scenario_a.append(result)
                elif result.scenario == Scenario.B:
                    report.scenario_b.append(result)
                else:
                    report.no_change.append(result)

            except Exception as exc:
                logger.warning(
                    "Failed to query ADC %s (%s): %s", adc["id"], adc["name"], exc
                )
                report.errors.append({
                    "adc_id":   adc["id"],
                    "adc_name": adc["name"],
                    "error":    str(exc),
                })

        logger.info(
            "Delta complete: A=%d B=%d no_change=%d errors=%d",
            len(report.scenario_a), len(report.scenario_b),
            len(report.no_change), len(report.errors),
        )
        logger.info("\n%s", report.to_preflight_log())
        return report

    def _analyze_single(
        self,
        adc: dict,
        target_certkey: str,
        new_intermediate_serial: int | None,
        chain_map: ChainMap,
    ) -> ADCDeltaResult:
        """
        Queries a single ADC via ADM and classifies it into a scenario.
        """
        live = self.adm.get_certkey(adc["id"], target_certkey)

        if not live:
            # Certkey does not exist on this ADC — treat as full install (Scenario B)
            return ADCDeltaResult(
                adc_id=adc["id"],
                adc_name=adc["name"],
                scenario=Scenario.B,
                live_serial=None,
                new_serial=new_intermediate_serial,
                reason="Certkey not found on ADC — full install required.",
            )

        live_leaf_serial = live.get("leaf_serial")
        live_intermediate_serial = live.get("intermediate_serial")

        # Already current: leaf serial matches new leaf serial
        new_leaf_serial = chain_map.leaf.serial
        if live_leaf_serial == new_leaf_serial:
            return ADCDeltaResult(
                adc_id=adc["id"],
                adc_name=adc["name"],
                scenario=Scenario.NO_CHANGE,
                live_serial=live_intermediate_serial,
                new_serial=new_intermediate_serial,
                reason="Leaf serial already matches. No update needed.",
            )

        # Determine scenario by comparing intermediate serial
        if live_intermediate_serial == new_intermediate_serial:
            # Same intermediate — leaf swap only
            return ADCDeltaResult(
                adc_id=adc["id"],
                adc_name=adc["name"],
                scenario=Scenario.A,
                live_serial=live_intermediate_serial,
                new_serial=new_intermediate_serial,
                reason="Intermediate serial unchanged. Leaf swap only.",
            )
        else:
            # Different intermediate — full chain swap
            return ADCDeltaResult(
                adc_id=adc["id"],
                adc_name=adc["name"],
                scenario=Scenario.B,
                live_serial=live_intermediate_serial,
                new_serial=new_intermediate_serial,
                reason=(
                    f"New intermediate detected: "
                    f"{hex(live_intermediate_serial or 0)} → "
                    f"{hex(new_intermediate_serial or 0)}"
                ),
            )
