"""Tests for certificate loading and artifact signatures."""

import base64
import json

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from util import load_public_key, verify_artifact_signature


def signature_and_certificate(entry):
    body = json.loads(base64.b64decode(entry["body"]))
    signature = base64.b64decode(body["spec"]["signature"]["content"])
    certificate = base64.b64decode(body["spec"]["signature"]["publicKey"]["content"])
    return signature, certificate


def test_real_certificate_and_signature(entry, artifact_path):
    signature, certificate = signature_and_certificate(entry)
    key = load_public_key(certificate)

    assert isinstance(key, ec.EllipticCurvePublicKey)
    assert verify_artifact_signature(signature, key, str(artifact_path)) is None


def test_changed_artifact_is_rejected(entry, tmp_path):
    signature, certificate = signature_and_certificate(entry)
    key = load_public_key(certificate)
    changed = tmp_path / "changed-artifact.txt"
    changed.write_text("This is not the signed artifact.\n", encoding="utf-8")

    with pytest.raises(InvalidSignature):
        verify_artifact_signature(signature, key, str(changed))


@pytest.mark.parametrize(
    "encoding",
    [serialization.Encoding.PEM, serialization.Encoding.DER],
)
def test_plain_public_key_loading(entry, encoding):
    _, certificate = signature_and_certificate(entry)
    original = load_public_key(certificate)
    encoded = original.public_bytes(
        encoding=encoding,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    loaded = load_public_key(encoded)

    assert isinstance(loaded, ec.EllipticCurvePublicKey)
    assert loaded.public_numbers() == original.public_numbers()


def test_invalid_key_data_is_rejected():
    with pytest.raises(ValueError):
        load_public_key(b"not a certificate or public key")
