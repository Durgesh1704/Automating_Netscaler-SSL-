"""
ADM Executor — NetScaler SSL Certificate Automation
Builds and executes dynamic Nitro API payloads via Citrix ADM config_job endpoint.

Key design decisions:
  - Per-node result parsing (never trust parent job status alone)
  - -nodomaincheck flag is GATED on vserver type (VPN/AOVPN only)
  - Rollback payload is pre-generated before Wave 1 executes
  - Wave-based batching with configurable failure thresholds
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

NODOMAIN_CHECK_VSERVER_TYPES = {"VPN", "AOVPN", "SSL_BRIDGE"}


class VserverType(str, Enum):
    VPN        = "VPN"
    AOVPN      = "AOVPN"
    SSL_BRIDGE = "SSL_BRIDGE"
    SSL        = "SSL"


@dataclass
class NodeResult:
    adc_id:  str
    status:  str   # "SUCCESS" | "FAILED" | "PENDING"
    error:   str = ""

    @property
    def passed(self) -> bool:
        return self.status == "SUCCESS"


@dataclass
class JobResult:
    job_id:       str
    overall:      str              # "SUCCESS" | "PARTIAL" | "FAILED"
    node_results: list[NodeResult]

    @property
    def failed_nodes(self) -> list[NodeResult]:
        return [n for n in self.node_results if not n.passed]

    @property
    def success_count(self) -> int:
        return sum(1 for n in self.node_results if n.passed)


class ADMClient:
    """
    Citrix ADM Nitro API client.
    Handles authentication, retries, and per-node result parsing.
    """

    def __init__(self, host: str, username: str, password: str, verify_ssl: bool = True):
        self.base_url = f"https://{host}/nitro/v1"
        self.session  = self._build_session(username, password, verify_ssl)

    def _build_session(self, username: str, password: str, verify_ssl: bool) -> requests.Session:
        session = requests.Session()
        session.verify = verify_ssl
        session.headers.update({"Content-Type": "application/json"})

        retry = Retry(
            total=3,
            backoff_factor=1.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)

        # ADM session login
        resp = session.post(
            f"{self.base_url}/config/login",
            json={"login": {"username": username, "password": password}},
            timeout=30,
        )
        resp.raise_for_status()
        token = resp.json().get("sessionid") or resp.cookies.get("NITRO_AUTH_TOKEN")
        if token:
            session.headers["Cookie"] = f"NITRO_AUTH_TOKEN={token}"
        return session

    # ------------------------------------------------------------------ #
    # ADC Discovery                                                        #
    # ------------------------------------------------------------------ #

    def list_managed_adcs(self, tags: Optional[dict] = None) -> list[dict]:
        """
        Returns list of ADCs managed by ADM, optionally filtered by tags.
        tags: e.g. {"env": "prod", "tier": "gateway"}
        """
        resp = self.session.get(f"{self.base_url}/config/ns", timeout=30)
        resp.raise_for_status()
        adcs = resp.json().get("ns", [])

        if tags:
            adcs = [
                a for a in adcs
                if all(a.get("tags", {}).get(k) == v for k, v in tags.items())
            ]
        return adcs

    def get_certkey(self, adc_id: str, certkey_name: str) -> Optional[dict]:
        """
        Retrieves live certkey info from an ADC via ADM proxy.
        Returns dict with leaf_serial, intermediate_serial, or None if not found.
        """
        try:
            resp = self.session.get(
                f"{self.base_url}/config/sslcertkey/{certkey_name}",
                params={"ns_ip_address": adc_id},
                timeout=20,
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json().get("sslcertkey", [{}])[0]

            # Parse linked intermediate if present
            linked = data.get("linkcertkeyname")
            intermediate_serial = None
            if linked:
                linked_resp = self.session.get(
                    f"{self.base_url}/config/sslcertkey/{linked}",
                    params={"ns_ip_address": adc_id},
                    timeout=20,
                )
                if linked_resp.ok:
                    linked_data = linked_resp.json().get("sslcertkey", [{}])[0]
                    intermediate_serial = int(
                        linked_data.get("serial", "0"), 16
                    ) if linked_data.get("serial") else None

            return {
                "certkey_name":        certkey_name,
                "leaf_serial":         int(data.get("serial", "0"), 16) if data.get("serial") else None,
                "intermediate_serial": intermediate_serial,
                "linked_certkey":      linked,
            }
        except requests.RequestException as exc:
            logger.error("Failed to query certkey %s on %s: %s", certkey_name, adc_id, exc)
            raise

    # ------------------------------------------------------------------ #
    # Job Execution                                                         #
    # ------------------------------------------------------------------ #

    def run_job(self, payload: dict, poll_interval: int = 10, timeout: int = 600) -> JobResult:
        """
        Submits a config_job to ADM and polls until completion.
        Parses per-node results — does NOT trust the parent job status alone.
        """
        resp = self.session.post(
            f"{self.base_url}/config/config_job",
            json={"config_job": payload},
            timeout=60,
        )
        resp.raise_for_status()
        job_id = resp.json()["config_job"]["id"]
        logger.info("ADM job submitted: job_id=%s", job_id)

        # Poll for completion
        elapsed = 0
        while elapsed < timeout:
            time.sleep(poll_interval)
            elapsed += poll_interval
            status_resp = self.session.get(
                f"{self.base_url}/config/config_job/{job_id}",
                timeout=30,
            )
            status_resp.raise_for_status()
            job_data = status_resp.json()["config_job"]

            if job_data["status"] in ("completed", "failed", "partial"):
                return self._parse_job_result(job_id, job_data)

        raise TimeoutError(f"ADM job {job_id} did not complete within {timeout}s")

    @staticmethod
    def _parse_job_result(job_id: str, job_data: dict) -> JobResult:
        """
        CRITICAL: Parse per-node results, not just the parent job status.
        ADM marks job 'completed' when the last node responds, but individual
        node failures are buried in node_results[].
        """
        raw_nodes = job_data.get("node_results", [])
        node_results = [
            NodeResult(
                adc_id=n.get("ns_ip_address", "unknown"),
                status=n.get("status", "FAILED").upper(),
                error=n.get("message", ""),
            )
            for n in raw_nodes
        ]

        failed_count  = sum(1 for n in node_results if not n.passed)
        overall = (
            "SUCCESS" if failed_count == 0
            else "PARTIAL" if failed_count < len(node_results)
            else "FAILED"
        )

        logger.info(
            "Job %s result: %s | %d/%d nodes passed",
            job_id, overall,
            len(node_results) - failed_count, len(node_results),
        )
        for n in node_results:
            if not n.passed:
                logger.warning("  FAILED node %s: %s", n.adc_id, n.error)

        return JobResult(job_id=job_id, overall=overall, node_results=node_results)


class JobBuilder:
    """
    Builds dynamic Nitro API job payloads for ADM config_job endpoint.
    Supports Scenario A (leaf swap) and Scenario B (full chain swap).
    """

    @staticmethod
    def requires_nodomain_check(vserver_type: str) -> bool:
        """Gate -nodomaincheck to VPN/AOVPN/SSL_BRIDGE vservers ONLY."""
        return vserver_type.upper() in NODOMAIN_CHECK_VSERVER_TYPES

    def build_update_payload(
        self,
        adc_ids:        list[str],
        certkey_name:   str,
        chain_map,
        scenario:       str,
        vserver_type:   str = "SSL",
    ) -> dict:
        """
        Builds the multi-step job payload for ADM.

        Steps:
          1. upload_cert_store   — push files to ADM central store
          2. install_ns_ssl_cert — deploy from store to /nsconfig/ssl on ADCs
          3. update_ssl_certkey  — swap the leaf cert (with optional -nodomaincheck)
          4. add_ssl_certkey     — (Scenario B only) add new intermediate
          5. link_ssl_certkey    — (Scenario B only) link leaf → new intermediate
          6. save_config         — persist changes
        """
        use_nodomaincheck = self.requires_nodomain_check(vserver_type)
        files_to_upload = [chain_map.leaf.pem]
        if scenario == "B":
            for im in chain_map.intermediates:
                files_to_upload.append(im.pem)

        steps = [
            {
                "command":     "upload_cert_store",
                "cert_data":   files_to_upload,
                "description": "Upload cert files to ADM central store",
            },
            {
                "command":     "install_ns_ssl_cert",
                "targets":     adc_ids,
                "description": "Deploy cert files to /nsconfig/ssl on target ADCs",
            },
            {
                "command":       "update_ssl_certkey",
                "certkey_name":  certkey_name,
                "cert_file":     f"{chain_map.leaf.cn}.pem",
                "nodomaincheck": use_nodomaincheck,
                "description":   "Swap leaf certificate",
            },
        ]

        if scenario == "B" and chain_map.intermediates:
            new_im = chain_map.intermediates[0]
            im_certkey_name = f"intermediate_{new_im.cn.replace(' ', '_')}"
            steps.append({
                "command":      "add_ssl_certkey",
                "certkey_name": im_certkey_name,
                "cert_file":    f"{new_im.cn}.pem",
                "description":  f"Add new intermediate: {new_im.cn}",
            })
            steps.append({
                "command":        "link_ssl_certkey",
                "certkey_name":   certkey_name,
                "link_cert_name": im_certkey_name,
                "description":    f"Link leaf → {new_im.cn}",
            })

        steps.append({
            "command":     "save_config",
            "description": "Persist configuration on all updated ADCs",
        })

        return {
            "name":        f"ssl_cert_update_{certkey_name}",
            "target_adcs": adc_ids,
            "steps":       steps,
        }

    def build_rollback_payload(
        self,
        adc_ids:             list[str],
        certkey_name:        str,
        original_cert_pem:   str,
        original_im_certkey: Optional[str] = None,
    ) -> dict:
        """
        Pre-generates rollback payload. Called in TCM_APPROVED state,
        BEFORE any production wave executes.
        """
        steps = [
            {
                "command":     "upload_cert_store",
                "cert_data":   [original_cert_pem],
                "description": "Re-upload original cert to ADM store",
            },
            {
                "command":     "install_ns_ssl_cert",
                "targets":     adc_ids,
                "description": "Re-deploy original cert to ADCs",
            },
            {
                "command":       "update_ssl_certkey",
                "certkey_name":  certkey_name,
                "cert_file":     "original_leaf.pem",
                "nodomaincheck": True,
                "description":   "Restore original leaf cert",
            },
        ]

        if original_im_certkey:
            steps.append({
                "command":        "link_ssl_certkey",
                "certkey_name":   certkey_name,
                "link_cert_name": original_im_certkey,
                "description":    "Restore original intermediate link",
            })

        steps.append({"command": "save_config", "description": "Persist rollback"})

        return {
            "name":        f"ROLLBACK_{certkey_name}",
            "target_adcs": adc_ids,
            "steps":       steps,
        }
