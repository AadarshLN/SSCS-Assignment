"""Certificate and artifact signature helpers."""

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def extract_public_key(cert: bytes) -> bytes:
    """Return the PEM-encoded public key from a PEM-encoded X.509 certificate."""
    certificate = x509.load_pem_x509_certificate(cert)
    public_key = certificate.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def verify_artifact_signature(
    signature: bytes, public_key: bytes, artifact_filename: str
) -> bool:
    """Return True only if signature is a valid ECDSA-SHA256 signature of the file."""
    loaded_key = load_pem_public_key(public_key)
    if not isinstance(loaded_key, ec.EllipticCurvePublicKey):
        print("Unsupported public key type:", type(loaded_key).__name__)
        return False

    with open(artifact_filename, "rb") as data_file:
        data = data_file.read()

    try:
        loaded_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print("Signature is invalid")
        return False
    return True
