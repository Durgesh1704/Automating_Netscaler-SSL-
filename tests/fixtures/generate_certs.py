"""
tests/fixtures/generate_certs.py
---------------------------------
Generates a test certificate chain (Root → Intermediate → Leaf)
for use in unit and integration tests.

Run once to regenerate:
    python tests/fixtures/generate_certs.py

Output files (git-tracked as test fixtures only):
    tests/fixtures/root.pem
    tests/fixtures/intermediate.pem
    tests/fixtures/leaf.pem
    tests/fixtures/bundle.pem          ← all three concatenated
    tests/fixtures/leaf_only.pem       ← leaf only (no chain)
    tests/fixtures/future_dated.pem    ← leaf with notBefore +48h (should be rejected)
"""

from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

FIXTURES = Path(__file__).parent
NOW = datetime.datetime.now(datetime.timezone.utc)


def _gen_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Corp"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def build_root() -> tuple:
    key = _gen_key()
    name = _name("Test Root CA")
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def build_intermediate(root_key, root_cert) -> tuple:
    key = _gen_key()
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("Test Intermediate CA G1"))
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False)
        .sign(root_key, hashes.SHA256())
    )
    return key, cert


def build_leaf(im_key, im_cert, sans: list[str] = None, future_dated: bool = False) -> tuple:
    key = _gen_key()
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(im_key.public_key())

    not_before = (NOW + datetime.timedelta(hours=48)) if future_dated else (NOW - datetime.timedelta(hours=1))
    not_after  = not_before + datetime.timedelta(days=365)

    san_names = sans or ["vpn.corp.com", "gateway.corp.com"]
    san_list  = [x509.DNSName(s) for s in san_names]

    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("vpn.corp.com"))
        .issuer_name(im_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False)
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .sign(im_key, hashes.SHA256())
    )
    return key, cert


def pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def main():
    print("Generating test certificate chain...")

    root_key, root_cert   = build_root()
    im_key,   im_cert     = build_intermediate(root_key, root_cert)
    leaf_key, leaf_cert   = build_leaf(im_key, im_cert)
    _,        future_cert = build_leaf(im_key, im_cert, future_dated=True)

    # Write individual certs
    (FIXTURES / "root.pem").write_bytes(pem(root_cert))
    (FIXTURES / "intermediate.pem").write_bytes(pem(im_cert))
    (FIXTURES / "leaf.pem").write_bytes(pem(leaf_cert))
    (FIXTURES / "future_dated.pem").write_bytes(pem(future_cert))
    (FIXTURES / "leaf_only.pem").write_bytes(pem(leaf_cert))

    # Full bundle: Leaf → Intermediate → Root
    bundle = pem(leaf_cert) + pem(im_cert) + pem(root_cert)
    (FIXTURES / "bundle.pem").write_bytes(bundle)

    # Record serials for test assertions
    serials = {
        "root_serial":         root_cert.serial_number,
        "intermediate_serial": im_cert.serial_number,
        "leaf_serial":         leaf_cert.serial_number,
        "future_serial":       future_cert.serial_number,
    }
    import json
    (FIXTURES / "serials.json").write_text(json.dumps(serials, indent=2))

    print(f"  root.pem          CN={root_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
    print(f"  intermediate.pem  CN={im_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
    print(f"  leaf.pem          CN={leaf_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
    print(f"  bundle.pem        (leaf + intermediate + root)")
    print(f"  future_dated.pem  notBefore=+48h (rejection test)")
    print("Done.")


if __name__ == "__main__":
    main()
