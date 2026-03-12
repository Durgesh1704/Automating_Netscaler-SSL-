from __future__ import annotations

import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src.validator.tls_validator import TLSValidator


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _build_ca(cn: str):
    key = _new_key()
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _build_leaf(cn: str, issuer_name: x509.Name, signer_key, is_ca=False):
    key = _new_key()
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=10))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .sign(signer_key, hashes.SHA256())
    )
    return key, cert


def _serve_tls(tmp_path: Path, cert: x509.Certificate, key, chain: list[x509.Certificate] | None = None):
    cert_path = tmp_path / "server.pem"
    key_path = tmp_path / "server.key"

    pem = cert.public_bytes(serialization.Encoding.PEM)
    if chain:
        pem += b"".join(c.public_bytes(serialization.Encoding.PEM) for c in chain)
    cert_path.write_bytes(pem)
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key_path))

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def _loop():
        while not stop.is_set():
            try:
                listener.settimeout(0.2)
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                with context.wrap_socket(conn, server_side=True) as tls_conn:
                    tls_conn.recv(1)
            except Exception:
                pass

    thread = threading.Thread(target=_loop, daemon=True)
    thread.start()

    def _shutdown():
        stop.set()
        listener.close()
        thread.join(timeout=1)

    return port, _shutdown


def test_validate_vip_passes_with_ca_signed_leaf(tmp_path):
    ca_key, ca_cert = _build_ca("Test Intermediate CA")
    leaf_key, leaf_cert = _build_leaf("127.0.0.1", ca_cert.subject, ca_key)
    port, shutdown = _serve_tls(tmp_path, leaf_cert, leaf_key, [ca_cert])

    try:
        result = TLSValidator(timeout=2).validate_vip(
            "127.0.0.1", port=port, expected_serial=leaf_cert.serial_number, expected_issuer="Intermediate"
        )
    finally:
        shutdown()

    assert result.passed is True
    assert result.chain_depth >= 2


def test_validate_vip_fails_on_self_signed_chain_depth(tmp_path):
    leaf_key, leaf_cert = _build_ca("self-signed.local")
    port, shutdown = _serve_tls(tmp_path, leaf_cert, leaf_key)

    try:
        result = TLSValidator(timeout=2).validate_vip("127.0.0.1", port=port)
    finally:
        shutdown()

    assert result.passed is False
    assert "chain_depth" in result.failure_reason


def test_validate_vip_fails_on_serial_mismatch(tmp_path):
    ca_key, ca_cert = _build_ca("Test Intermediate CA")
    leaf_key, leaf_cert = _build_leaf("127.0.0.1", ca_cert.subject, ca_key)
    port, shutdown = _serve_tls(tmp_path, leaf_cert, leaf_key, [ca_cert])

    try:
        result = TLSValidator(timeout=2).validate_vip("127.0.0.1", port=port, expected_serial=123456)
    finally:
        shutdown()

    assert result.passed is False
    assert "serial mismatch" in result.failure_reason.lower()
