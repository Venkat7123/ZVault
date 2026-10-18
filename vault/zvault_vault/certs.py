"""Erasure certificates signed with ML-DSA-65.

The signature proves the certificate is genuine and unaltered. It does not by itself
prove every copy was erased, so the certificate records, per location, whether erasure
was verified, failed, or could not be verified, plus the recovery-test evidence.

Following Apple Private Cloud Compute, the certificate names the measurement (hash) of
the code that produced it. On IBM Secure Execution that measurement would come from
hardware attestation; this LinuxONE has no Secure Execution, so it is computed in
software and labelled SIMULATED.
"""

import base64
import hashlib
import json
import os
from pathlib import Path

from .crypto import ossl

CERT_TYPE = "zvault_vault.erasure-certificate/v1"
SIGNATURE_ALG = "ML-DSA-65"
_ENCLAVE_MODULES = ["certs.py", "erasure.py", "attacks.py", "retention.py", "crypto/ossl.py", "crypto/hybrid.py",
                    "keys/service.py", "keys/soft_hsm.py", "store.py", "registry.py"]


def canonical(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def enclave_measurement() -> str:
    """SHA3-256 over the source of every module that runs inside the (simulated) enclave."""
    base = Path(__file__).resolve().parent
    h = hashlib.sha3_256()
    for rel in _ENCLAVE_MODULES:
        h.update(rel.encode() + b"\0" + (base / rel).read_bytes() + b"\0")
    return h.hexdigest()


class CertificateSigner:
    """Holds the ML-DSA-65 signing key. In production it lives inside Secure Execution."""

    def __init__(self, directory):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        path = self.dir / "signer.mldsa65.der"
        if path.exists():
            self._key = ossl.PKey.from_private_der(path.read_bytes(), SIGNATURE_ALG)
        else:
            self._key = ossl.PKey.generate(SIGNATURE_ALG)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(self._key.private_der())
        self.public_der = self._key.public_der()
        self.key_id = hashlib.sha3_256(self.public_der).hexdigest()[:16]
        self.measurement = enclave_measurement()

    def sign(self, body: dict) -> dict:
        document = dict(body)
        document["enclave"] = {
            "measurement_sha3_256": self.measurement,
            "attestation": "SIMULATED: no IBM Secure Execution on this host; measurement computed in software",
        }
        signature = ossl.sign(self._key, canonical(document))
        document["signature"] = {
            "algorithm": SIGNATURE_ALG,
            "key_id": self.key_id,
            "value": base64.b64encode(signature).decode(),
        }
        return document

    def sign_bytes(self, data: bytes) -> bytes:
        return ossl.sign(self._key, data)


def verify_certificate(document: dict, public_der: bytes) -> bool:
    """True only if the certificate was signed by this key and not changed since."""
    sig = document.get("signature") or {}
    if sig.get("algorithm") != SIGNATURE_ALG:
        return False
    body = {k: v for k, v in document.items() if k != "signature"}
    public = ossl.PKey.from_public_der(public_der, SIGNATURE_ALG)
    try:
        signature = base64.b64decode(sig["value"], validate=True)
    except (KeyError, ValueError):
        return False
    return ossl.verify(public, canonical(body), signature)
