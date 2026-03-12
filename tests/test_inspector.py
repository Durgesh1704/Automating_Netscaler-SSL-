"""
tests/test_inspector.py
Tests for the Intelligent Inspector — chain walking, SAN check, notBefore gate.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.inspector.inspector import (
    CertRole,
    ChainMap,
    FutureDatedCertError,
    Inspector,
    InspectorError,
    SANMismatchError,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def serials() -> dict:
    return json.loads((FIXTURES / "serials.json").read_text())


@pytest.fixture(scope="module")
def bundle_pem() -> bytes:
    return (FIXTURES / "bundle.pem").read_bytes()


@pytest.fixture(scope="module")
def leaf_only_pem() -> bytes:
    return (FIXTURES / "leaf_only.pem").read_bytes()


@pytest.fixture(scope="module")
def future_dated_pem() -> bytes:
    # future_dated leaf bundled with intermediate + root
    leaf = (FIXTURES / "future_dated.pem").read_bytes()
    im   = (FIXTURES / "intermediate.pem").read_bytes()
    root = (FIXTURES / "root.pem").read_bytes()
    return leaf + im + root


# ------------------------------------------------------------------ #
# Happy path                                                           #
# ------------------------------------------------------------------ #

class TestHappyPath:
    def test_inspect_returns_chain_map(self, bundle_pem):
        inspector = Inspector()
        result = inspector.inspect(bundle_pem)
        assert isinstance(result, ChainMap)

    def test_chain_depth_is_three(self, bundle_pem):
        result = Inspector().inspect(bundle_pem)
        assert result.chain_depth == 3   # Leaf + Intermediate + Root

    def test_leaf_role_correct(self, bundle_pem):
        result = Inspector().inspect(bundle_pem)
        assert result.leaf.role == CertRole.LEAF

    def test_intermediate_role_correct(self, bundle_pem):
        result = Inspector().inspect(bundle_pem)
        assert len(result.intermediates) == 1
        assert result.intermediates[0].role == CertRole.INTERMEDIATE

    def test_root_role_correct(self, bundle_pem):
        result = Inspector().inspect(bundle_pem)
        assert result.root is not None
        assert result.root.role == CertRole.ROOT

    def test_leaf_serial_matches_fixture(self, bundle_pem, serials):
        result = Inspector().inspect(bundle_pem)
        assert result.leaf.serial == serials["leaf_serial"]

    def test_intermediate_serial_matches_fixture(self, bundle_pem, serials):
        result = Inspector().inspect(bundle_pem)
        assert result.intermediates[0].serial == serials["intermediate_serial"]

    def test_leaf_cn_correct(self, bundle_pem):
        result = Inspector().inspect(bundle_pem)
        assert result.leaf.cn == "vpn.corp.com"

    def test_intermediate_cn_correct(self, bundle_pem):
        result = Inspector().inspect(bundle_pem)
        assert "Intermediate" in result.intermediates[0].cn

    def test_bundle_sha256_is_set(self, bundle_pem):
        result = Inspector().inspect(bundle_pem)
        assert len(result.bundle_sha256) == 64   # SHA256 hex

    def test_leaf_sans_populated(self, bundle_pem):
        result = Inspector().inspect(bundle_pem)
        assert "vpn.corp.com" in result.leaf.sans

    def test_leaf_chain_ordering(self, bundle_pem):
        """Intermediates must be ordered closest-to-leaf first."""
        result = Inspector().inspect(bundle_pem)
        if result.intermediates:
            # Leaf's AKI should match first intermediate's SKI
            assert result.leaf.aki == result.intermediates[0].ski

    def test_days_until_expiry_positive(self, bundle_pem):
        result = Inspector().inspect(bundle_pem)
        assert result.leaf.days_until_expiry > 0


# ------------------------------------------------------------------ #
# SAN scope check                                                      #
# ------------------------------------------------------------------ #

class TestSANCheck:
    def test_matching_san_passes(self, bundle_pem):
        inspector = Inspector(known_vip_sans=["vpn.corp.com"])
        result = inspector.inspect(bundle_pem)
        assert result.leaf is not None

    def test_non_matching_san_raises(self, bundle_pem):
        inspector = Inspector(known_vip_sans=["totally-different.example.com"])
        with pytest.raises(SANMismatchError):
            inspector.inspect(bundle_pem)

    def test_no_known_vip_sans_skips_check(self, bundle_pem):
        """If known_vip_sans is empty, SAN check is skipped entirely."""
        inspector = Inspector(known_vip_sans=[])
        result = inspector.inspect(bundle_pem)
        assert result is not None

    def test_partial_san_overlap_passes(self, bundle_pem):
        """At least one matching SAN is sufficient."""
        inspector = Inspector(known_vip_sans=["vpn.corp.com", "no-match.example.com"])
        result = inspector.inspect(bundle_pem)
        assert result is not None


# ------------------------------------------------------------------ #
# notBefore future-dating gate                                         #
# ------------------------------------------------------------------ #

class TestNotBeforeGate:
    def test_future_dated_cert_rejected(self, future_dated_pem):
        inspector = Inspector()
        with pytest.raises(FutureDatedCertError) as exc_info:
            inspector.inspect(future_dated_pem)
        assert "notBefore" in str(exc_info.value)
        assert "future" in str(exc_info.value).lower()

    def test_valid_dated_cert_passes(self, bundle_pem):
        inspector = Inspector()
        result = inspector.inspect(bundle_pem)
        assert result is not None


# ------------------------------------------------------------------ #
# Edge cases                                                           #
# ------------------------------------------------------------------ #

class TestEdgeCases:
    def test_empty_bundle_raises(self):
        with pytest.raises(InspectorError):
            Inspector().inspect(b"not a cert")

    def test_leaf_only_bundle_no_crash(self, leaf_only_pem):
        """A leaf-only bundle (no chain) should parse without crashing."""
        result = Inspector().inspect(leaf_only_pem)
        assert result.leaf is not None
        assert result.intermediates == []
        assert result.chain_depth == 1   # Leaf only — no intermediate

    def test_same_bundle_same_sha256(self, bundle_pem):
        """SHA256 must be deterministic."""
        r1 = Inspector().inspect(bundle_pem)
        r2 = Inspector().inspect(bundle_pem)
        assert r1.bundle_sha256 == r2.bundle_sha256

    def test_different_bundles_different_sha256(self, bundle_pem, leaf_only_pem):
        r1 = Inspector().inspect(bundle_pem)
        r2 = Inspector().inspect(leaf_only_pem)
        assert r1.bundle_sha256 != r2.bundle_sha256
