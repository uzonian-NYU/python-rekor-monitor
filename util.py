from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    load_der_public_key,
    load_pem_public_key,
)


def load_public_key(key_bytes):
    """Load a public key from PEM or DER (SubjectPublicKeyInfo) bytes."""
    try:
        return load_pem_public_key(key_bytes)
    except ValueError:
        return load_der_public_key(key_bytes)


def verify_artifact_signature(signature, public_key, artifact_filename):
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
