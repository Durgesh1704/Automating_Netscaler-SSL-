"""
Intelligent Inspector — NetScaler SSL Certificate Automation
Performs deep cryptographic analysis of a certificate bundle before any ADC touch.

Checks performed:
  1. Recursive chain walking (supports N-depth intermediates)
  2. SAN validation against known VIP scope
  3. notBefore future-dating rejection (>24h window)
  4. Chain ordering: Leaf → Intermediate(s) → Root
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID

logger = logging.getLogger(__name__)

NOT_BEFORE_TOLERANCE_HOURS = 24  # Reject leaf if notBefore > now + 24h


class CertRole(str, Enum):
    LEAF         = "LEAF"
    INTERMEDIATE = "INTERMEDIATE"
    ROOT         = "ROOT"


@dataclass
class CertInfo:
    role:        CertRole
    cn:          str
    serial:      int
    serial_hex:  str
    aki:         Optional[str]   # Authority Key Identifier
    ski:         Optional[str]   # Subject Key Identifier
    not_before:  datetime
    not_after:   datetime
    sans:        list[str]
    issuer_cn:   str
    sha256:      str             # Fingerprint of this cert
    pem:         str             # Raw PEM for upload to ADM

    @property
    def is_self_signed(self) -> bool:
        return self.aki == self.ski or self.aki is None

    @property
    def days_until_expiry(self) -> int:
        now = datetime.now(timezone.utc)
        return (self.not_after - now).days


@dataclass
class ChainMap:
    leaf:          CertInfo
    intermediates: list[CertInfo]   # Ordered: closest to leaf first
    root:          Optional[CertInfo]
    bundle_sha256: str              # SHA256 of raw bundle bytes — used as dedup key

    @property
    def chain_depth(self) -> int:
        return 1 + len(self.intermediates) + (1 if self.root else 0)

    @property
    def scenario(self) -> str:
        """Returns 'A' or 'B' — set after delta analysis, not here."""
        raise NotImplementedError("Scenario is determined by DeltaEngine, not Inspector.")


class InspectorError(Exception):
    pass


class FutureDatedCertError(InspectorError):
    pass


class ChainOrderError(InspectorError):
    pass


class SANMismatchError(InspectorError):
    pass


class Inspector:
    """
    Loads a PEM bundle (may contain multiple certs) and produces a ChainMap.
    """

    def __init__(self, known_vip_sans: Optional[list[str]] = None):
        """
        Args:
            known_vip_sans: List of SANs (DNS names / IPs) that the target
                            VIPs serve. If provided, the leaf cert MUST cover
                            at least one of them.
        """
        self.known_vip_sans = known_vip_sans or []

    def inspect(self, bundle_pem: bytes) -> ChainMap:
        """
        Main entry point. Returns a validated ChainMap.
        Raises InspectorError subclasses on any validation failure.
        """
        raw_certs = self._split_pem(bundle_pem)
        if not raw_certs:
            raise InspectorError("No certificates found in bundle.")

        cert_infos = [self._parse_cert(pem) for pem in raw_certs]

        # Classify each cert
        classified = self._classify_chain(cert_infos)

        leaf          = classified["leaf"]
        intermediates = classified["intermediates"]
        root          = classified.get("root")

        # Validation gates
        self._check_not_before(leaf)
        if self.known_vip_sans:
            self._check_san_scope(leaf)

        bundle_sha256 = hashlib.sha256(bundle_pem).hexdigest()
        chain_map = ChainMap(
            leaf=leaf,
            intermediates=intermediates,
            root=root,
            bundle_sha256=bundle_sha256,
        )

        logger.info(
            "Inspected bundle: leaf=%s depth=%d sha256=%s...",
            leaf.cn, chain_map.chain_depth, bundle_sha256[:16],
        )
        return chain_map

    # ------------------------------------------------------------------ #
    # Private helpers                                                      #
    # ------------------------------------------------------------------ #

    def _split_pem(self, bundle_pem: bytes) -> list[bytes]:
        """Split a multi-cert PEM bundle into individual PEM blocks."""
        delimiter = b"-----BEGIN CERTIFICATE-----"
        end       = b"-----END CERTIFICATE-----"
        parts = []
        chunks = bundle_pem.split(delimiter)
        for chunk in chunks[1:]:  # Skip empty first element
            if end in chunk:
                pem = delimiter + chunk[: chunk.index(end) + len(end)]
                parts.append(pem)
        return parts

    def _parse_cert(self, pem: bytes) -> CertInfo:
        cert = x509.load_pem_x509_certificate(pem, default_backend())

        # Subject Key Identifier
        try:
            ski_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            ski = ski_ext.value.key_identifier.hex()
        except x509.ExtensionNotFound:
            ski = None

        # Authority Key Identifier
        try:
            aki_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            aki = aki_ext.value.key_identifier.hex() if aki_ext.value.key_identifier else None
        except x509.ExtensionNotFound:
            aki = None

        # SANs
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = [str(name.value) for name in san_ext.value]
        except x509.ExtensionNotFound:
            sans = []

        cn = self._get_cn(cert)
        sha256 = cert.fingerprint(hashes.SHA256()).hex()

        return CertInfo(
            role=CertRole.LEAF,  # Placeholder; classified later
            cn=cn,
            serial=cert.serial_number,
            serial_hex=hex(cert.serial_number),
            aki=aki,
            ski=ski,
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            sans=sans,
            issuer_cn=self._get_cn(cert, subject=False),
            sha256=sha256,
            pem=pem.decode(),
        )

    def _get_cn(self, cert: x509.Certificate, subject: bool = True) -> str:
        name = cert.subject if subject else cert.issuer
        try:
            return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
            return str(name)

    def _classify_chain(self, certs: list[CertInfo]) -> dict:
        """
        Recursive chain classifier. Supports N-depth intermediates.
        Returns {"leaf": CertInfo, "intermediates": [...], "root": CertInfo|None}
        """
        # Root: self-signed
        roots = [c for c in certs if c.aki is None or c.aki == c.ski]

        # Leaf: not a CA cert (no BasicConstraints is_ca, or is_ca=False)
        # Intermediates: everything else
        # We identify the leaf as the cert whose SKI is not referenced as AKI by others
        ski_set = {c.ski for c in certs if c.ski}
        aki_set = {c.aki for c in certs if c.aki}

        # Leaf: its SKI is not an AKI for any other cert in bundle
        leaf_candidates = [c for c in certs if c.ski not in aki_set and c not in roots]

        if not leaf_candidates:
            # Fallback: pick cert with latest not_before that isn't self-signed
            leaf_candidates = [c for c in certs if c not in roots]

        if not leaf_candidates:
            raise ChainOrderError("Cannot identify leaf certificate in bundle.")

        leaf = sorted(leaf_candidates, key=lambda c: c.not_before, reverse=True)[0]
        leaf.role = CertRole.LEAF

        for r in roots:
            r.role = CertRole.ROOT

        intermediates = [c for c in certs if c not in roots and c is not leaf]
        for im in intermediates:
            im.role = CertRole.INTERMEDIATE

        # Order intermediates: closest to leaf first (by AKI chain)
        intermediates = self._order_intermediates(leaf, intermediates)

        return {
            "leaf": leaf,
            "intermediates": intermediates,
            "root": roots[0] if roots else None,
        }

    def _order_intermediates(
        self, leaf: CertInfo, intermediates: list[CertInfo]
    ) -> list[CertInfo]:
        """Order intermediates by following the AKI chain from the leaf."""
        ordered = []
        current_aki = leaf.aki
        remaining = list(intermediates)

        while remaining and current_aki:
            match = next((c for c in remaining if c.ski == current_aki), None)
            if not match:
                break
            ordered.append(match)
            remaining.remove(match)
            current_aki = match.aki

        # Append any unmatched intermediates at the end
        ordered.extend(remaining)
        return ordered

    def _check_not_before(self, leaf: CertInfo) -> None:
        now = datetime.now(timezone.utc)
        threshold = now + timedelta(hours=NOT_BEFORE_TOLERANCE_HOURS)
        if leaf.not_before > threshold:
            raise FutureDatedCertError(
                f"Leaf cert notBefore={leaf.not_before.isoformat()} is more than "
                f"{NOT_BEFORE_TOLERANCE_HOURS}h in the future. Rejecting to prevent "
                f"handshake failures."
            )

    def _check_san_scope(self, leaf: CertInfo) -> None:
        leaf_san_set = set(leaf.sans)
        overlap = leaf_san_set & set(self.known_vip_sans)
        if not overlap:
            raise SANMismatchError(
                f"Leaf cert SANs {leaf.sans} do not cover any known VIP SANs "
                f"{self.known_vip_sans}. Refusing deployment."
            )
        logger.info("SAN scope check passed. Matching SANs: %s", overlap)
