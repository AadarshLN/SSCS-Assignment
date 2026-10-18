"""Tests for certificate parsing and artifact signature verification."""

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from util import extract_public_key, verify_artifact_signature


def _signature_and_cert(tlog_entry: dict[str, Any]) -> tuple[bytes, bytes]:
    body = json.loads(base64.b64decode(tlog_entry["canonicalizedBody"]))
    sig = base64.b64decode(body["spec"]["signature"]["content"])
    cert = base64.b64decode(body["spec"]["signature"]["publicKey"]["content"])
    return sig, cert


def test_extract_public_key_returns_pem(tlog_entry: dict[str, Any]) -> None:
    _, cert = _signature_and_cert(tlog_entry)
    public_key = extract_public_key(cert)
    assert public_key.startswith(b"-----BEGIN PUBLIC KEY-----")


def test_valid_signature_is_accepted(
    tlog_entry: dict[str, Any], artifact_path: str
) -> None:
    sig, cert = _signature_and_cert(tlog_entry)
    assert verify_artifact_signature(sig, extract_public_key(cert), artifact_path)


def test_tampered_artifact_is_rejected(
    tlog_entry: dict[str, Any], tmp_path: Path
) -> None:
    sig, cert = _signature_and_cert(tlog_entry)
    tampered = tmp_path / "artifact.md"
    tampered.write_text("tampered content\n")
    assert not verify_artifact_signature(sig, extract_public_key(cert), str(tampered))


def test_non_ec_public_key_is_rejected(tmp_path: Path) -> None:
    pem = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    artifact = tmp_path / "file.txt"
    artifact.write_text("data")
    assert not verify_artifact_signature(b"sig", pem, str(artifact))
