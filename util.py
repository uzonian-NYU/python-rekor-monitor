from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    load_der_public_key,
    load_pem_public_key,
)


def load_public_key(key_bytes: bytes):
    """Load a public key from a PEM certificate or a PEM/DER public key."""
    if key_bytes.lstrip().startswith(b"-----BEGIN CERTIFICATE-----"):
        return x509.load_pem_x509_certificate(key_bytes).public_key()

    try:
        return load_pem_public_key(key_bytes)
    except ValueError:
        return load_der_public_key(key_bytes)


def verify_artifact_signature(signature: bytes, public_key, artifact_filename: str) -> None:
    """Verify an artifact's ECDSA signature; raise an error if invalid."""
    with open(artifact_filename, "rb") as data_file:
        data = data_file.read()

    try:
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature:
        raise InvalidSignature("Artifact signature is invalid.") from None
