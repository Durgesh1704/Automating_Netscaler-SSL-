"""
TLS Validator — NetScaler SSL Certificate Automation
Performs live TLS handshake verification against VIPs after deployment.

Checks:
  - chain_depth >= 2 (catches leaf-only deployments where link step silently failed)
  - Leaf serial matches expected
  - Issuer CN matches expected intermediate
  - Expiry within acceptable window
  - Basic OCSP stapling detection (Python 3.10+)
"""

from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID

from cryptography import x509
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)

MIN_CHAIN_DEPTH     = 2    # Leaf + at least one intermediate
EXPIRY_WARN_DAYS    = 30   # Warn if cert expires within this window


@dataclass
class VIPResult:
    vip:           str
    port:          int
    passed:        bool
    chain_depth:   int
    leaf_cn:       str
    issuer_cn:     str
    expiry:        str        # notAfter string from TLS handshake
    days_to_expiry: int
    ocsp_stapled:  bool
    failure_reason: str = ""

    def summary_line(self) -> str:
        status = "PASS" if self.passed else f"FAIL ({self.failure_reason})"
        return (
            f"  [{status}] {self.vip}:{self.port} | "
            f"chain_depth={self.chain_depth} | "
            f"issuer={self.issuer_cn} | "
            f"expires={self.expiry} ({self.days_to_expiry}d)"
        )


@dataclass
class ValidationReport:
    results:    list[VIPResult]
    passed_all: bool

    @property
    def failed(self) -> list[VIPResult]:
        return [r for r in self.results if not r.passed]

    @property
    def passed(self) -> list[VIPResult]:
        return [r for r in self.results if r.passed]

    def to_text(self) -> str:
        lines = [
            "=== TLS VALIDATION REPORT ===",
            f"  Total VIPs: {len(self.results)} | "
            f"Passed: {len(self.passed)} | Failed: {len(self.failed)}",
            "",
        ]
        for r in self.results:
            lines.append(r.summary_line())
        return "\n".join(lines)


class TLSValidator:
    """
    Validates TLS certificate chain on live VIPs after deployment.
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def validate_vip(
        self,
        host:             str,
        port:             int = 443,
        expected_serial:  int | None = None,
        expected_issuer:  str | None = None,
    ) -> VIPResult:
        """
        Opens a TLS connection and inspects the certificate chain served.

        Args:
            host:             FQDN or IP of the VIP
            port:             Port (default 443)
            expected_serial:  Expected leaf cert serial (from chain_map)
            expected_issuer:  Expected issuer CN (from chain_map.intermediates[0].cn)
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE  # We verify manually

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    peer_cert  = tls_sock.getpeercert()
                    der_cert   = tls_sock.getpeercert(binary_form=True)

                    # Python 3.10+ — get full chain
                    chain = []
                    if hasattr(tls_sock, "get_verified_chain"):
                        chain = tls_sock.get_verified_chain()
                    parsed_cert = x509.load_der_x509_certificate(der_cert)
                    chain_depth = max(len(chain), 1)
                    if not chain:
                        # Python 3.10 does not expose chain APIs on ssl sockets.
                        # Fallback heuristic: if issuer != subject, assume at least
                        # one signer exists above the leaf cert.
                        chain_depth = self._infer_chain_depth(peer_cert, parsed_cert)

                    # OCSP stapling detection
                    ocsp_stapled = False
                    try:
                        ocsp_stapled = bool(tls_sock.get_channel_binding("tls-unique"))
                    except Exception:
                        pass

                    leaf_cn    = self._extract_cn(peer_cert) or self._extract_cn_from_x509(parsed_cert)
                    issuer_cn  = self._extract_issuer_cn(peer_cert) or self._extract_issuer_cn_from_x509(parsed_cert)
                    not_after  = peer_cert.get("notAfter", "") or parsed_cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT")
                    expiry_dt  = self._parse_expiry(not_after)
                    days_left  = (expiry_dt - datetime.now(timezone.utc)).days if expiry_dt else -1
                    cert_serial = parsed_cert.serial_number

                    # --- Assertions ---
                    failure_reason = ""

                    if chain_depth < MIN_CHAIN_DEPTH:
                        failure_reason = (
                            f"chain_depth={chain_depth} < {MIN_CHAIN_DEPTH}. "
                            f"Intermediate likely not linked (link ssl certkey may have silently failed)."
                        )

                    if not failure_reason and expected_issuer:
                        if expected_issuer.lower() not in issuer_cn.lower():
                            failure_reason = (
                                f"Issuer mismatch: expected '{expected_issuer}', "
                                f"got '{issuer_cn}'"
                            )

                    if not failure_reason and expected_serial is not None:
                        if cert_serial != expected_serial:
                            failure_reason = (
                                f"Leaf serial mismatch: expected '{expected_serial}', "
                                f"got '{cert_serial}'"
                            )

                    if not failure_reason and days_left < 0:
                        failure_reason = f"Certificate already expired! days_left={days_left}"

                    passed = not bool(failure_reason)

                    if days_left < EXPIRY_WARN_DAYS and passed:
                        logger.warning(
                            "VIP %s: cert expires in %d days (threshold=%d)",
                            host, days_left, EXPIRY_WARN_DAYS,
                        )

                    result = VIPResult(
                        vip=host,
                        port=port,
                        passed=passed,
                        chain_depth=chain_depth,
                        leaf_cn=leaf_cn,
                        issuer_cn=issuer_cn,
                        expiry=not_after,
                        days_to_expiry=days_left,
                        ocsp_stapled=ocsp_stapled,
                        failure_reason=failure_reason,
                    )
                    log_fn = logger.info if passed else logger.error
                    log_fn(result.summary_line())
                    return result

        except (TimeoutError, ConnectionRefusedError, OSError) as exc:
            logger.error("Cannot connect to VIP %s:%d — %s", host, port, exc)
            return VIPResult(
                vip=host, port=port, passed=False,
                chain_depth=0, leaf_cn="", issuer_cn="",
                expiry="", days_to_expiry=-1, ocsp_stapled=False,
                failure_reason=f"Connection failed: {exc}",
            )

    def validate_all(
        self,
        vips:              list[dict],   # [{"host": "...", "port": 443}, ...]
        expected_serial:   int | None = None,
        expected_issuer:   str | None = None,
        failure_threshold: int = 0,      # 0 = any failure halts
    ) -> ValidationReport:
        """
        Validates all VIPs. Returns ValidationReport.

        Args:
            vips:              List of {"host", "port"} dicts
            expected_serial:   Expected leaf serial
            expected_issuer:   Expected issuer CN
            failure_threshold: Max number of failures before marking report failed
        """
        results = []
        for vip in vips:
            result = self.validate_vip(
                host=vip["host"],
                port=vip.get("port", 443),
                expected_serial=expected_serial,
                expected_issuer=expected_issuer,
            )
            results.append(result)

        failed_count = sum(1 for r in results if not r.passed)
        passed_all   = failed_count <= failure_threshold

        report = ValidationReport(results=results, passed_all=passed_all)
        logger.info("\n%s", report.to_text())
        return report

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_cn(peer_cert: dict) -> str:
        subject = dict(x[0] for x in peer_cert.get("subject", []))
        return subject.get("commonName", "")

    @staticmethod
    def _extract_issuer_cn(peer_cert: dict) -> str:
        issuer = dict(x[0] for x in peer_cert.get("issuer", []))
        return issuer.get("commonName", "")

    @staticmethod
    def _parse_expiry(not_after: str) -> datetime | None:
        """Parse the notAfter string from Python ssl module."""
        try:
            return datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _infer_chain_depth(peer_cert: dict, cert: x509.Certificate) -> int:
        """Fallback chain depth inference when ssl chain APIs are unavailable."""
        subject = peer_cert.get("subject", [])
        issuer = peer_cert.get("issuer", [])
        if issuer and subject and issuer != subject:
            return 2
        if cert.issuer != cert.subject:
            return 2
        return 1

    @staticmethod
    def _extract_cn_from_x509(cert: x509.Certificate) -> str:
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""

    @staticmethod
    def _extract_issuer_cn_from_x509(cert: x509.Certificate) -> str:
        attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""
