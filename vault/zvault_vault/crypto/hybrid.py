"""Hybrid post-quantum key encapsulation and key wrapping.

OpenSSL 3.5 offers X25519MLKEM768 for TLS, but those keys cannot be serialized, and
a root key has to persist. So the hybrid is built from two serializable halves:

    X25519 (DHKEM, RFC 9180)  +  ML-KEM-768 (FIPS 203)

and the two shared secrets are combined in the style of the X-Wing IETF draft:

    secret = SHA3-256(label || ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519)

An attacker has to break both X25519 (classical) and ML-KEM-768 (post-quantum) to
recover the secret, so a key wrapped today stays safe against a future quantum
computer even if ML-KEM were later found weak against classical attacks.
"""

import hashlib
import hmac
import struct
from dataclasses import dataclass

from . import ossl

COMBINER_LABEL = b"zvault_vault/hybrid-kem/X25519+ML-KEM-768/v1"
WRAP_INFO = b"zvault_vault/key-wrap/v1"
HYBRID_ALGORITHM = "X25519+ML-KEM-768"


def hkdf_sha384(ikm: bytes, info: bytes, length: int = 32, salt: bytes = b"") -> bytes:
    """HKDF (RFC 5869) with SHA-384."""
    prk = hmac.new(salt or b"\x00" * 48, ikm, hashlib.sha384).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha384).digest()
        okm += block
        counter += 1
    return okm[:length]


def _pack(*parts: bytes) -> bytes:
    return b"".join(struct.pack(">I", len(p)) + p for p in parts)


def _unpack(blob: bytes, count: int) -> list[bytes]:
    parts, offset = [], 0
    for _ in range(count):
        if offset + 4 > len(blob):
            raise ossl.DecryptionError("malformed hybrid blob")
        (n,) = struct.unpack_from(">I", blob, offset)
        offset += 4
        parts.append(blob[offset:offset + n])
        offset += n
    if offset != len(blob) or any(len(p) == 0 for p in parts):
        raise ossl.DecryptionError("malformed hybrid blob")
    return parts


@dataclass
class HybridPublicKey:
    mlkem: ossl.PKey
    x25519: ossl.PKey

    def to_bytes(self) -> bytes:
        return _pack(self.mlkem.public_der(), self.x25519.public_der())

    @classmethod
    def from_bytes(cls, blob: bytes) -> "HybridPublicKey":
        m, x = _unpack(blob, 2)
        return cls(ossl.PKey.from_public_der(m, "ML-KEM-768"), ossl.PKey.from_public_der(x, "X25519"))


@dataclass
class HybridPrivateKey:
    mlkem: ossl.PKey
    x25519: ossl.PKey

    @classmethod
    def generate(cls) -> "HybridPrivateKey":
        return cls(ossl.PKey.generate("ML-KEM-768"), ossl.PKey.generate("X25519"))

    def public_key(self) -> HybridPublicKey:
        return HybridPublicKey(
            ossl.PKey.from_public_der(self.mlkem.public_der(), "ML-KEM-768"),
            ossl.PKey.from_public_der(self.x25519.public_der(), "X25519"),
        )

    def to_bytes(self) -> bytes:
        return _pack(self.mlkem.private_der(), self.x25519.private_der())

    @classmethod
    def from_bytes(cls, blob: bytes) -> "HybridPrivateKey":
        m, x = _unpack(blob, 2)
        return cls(ossl.PKey.from_private_der(m, "ML-KEM-768"), ossl.PKey.from_private_der(x, "X25519"))


def _combine(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    return hashlib.sha3_256(COMBINER_LABEL + ss_m + ss_x + ct_x + pk_x).digest()


def encapsulate(public: HybridPublicKey) -> tuple[bytes, bytes]:
    """Returns (ciphertext, 32-byte shared secret)."""
    ct_m, ss_m = ossl.kem_encapsulate(public.mlkem)
    ct_x, ss_x = ossl.kem_encapsulate(public.x25519)
    return _pack(ct_m, ct_x), _combine(ss_m, ss_x, ct_x, public.x25519.public_der())


def decapsulate(private: HybridPrivateKey, ciphertext: bytes) -> bytes:
    ct_m, ct_x = _unpack(ciphertext, 2)
    ss_m = ossl.kem_decapsulate(private.mlkem, ct_m)
    ss_x = ossl.kem_decapsulate(private.x25519, ct_x)
    return _combine(ss_m, ss_x, ct_x, private.x25519.public_der())


def wrap_key(public: HybridPublicKey, key: bytes, context: bytes) -> bytes:
    """Wrap a symmetric key so only the hybrid private-key holder can unwrap it.

    `context` (e.g. customer id + key version) is bound into both the derived wrapping
    key and the AES-GCM associated data, so a wrapped key cannot be swapped between
    customers.
    """
    ct, secret = encapsulate(public)
    wrapping_key = hkdf_sha384(secret, WRAP_INFO + b"|" + context)
    return _pack(ct, ossl.aes_gcm_encrypt(wrapping_key, key, aad=context))


def unwrap_key(private: HybridPrivateKey, blob: bytes, context: bytes) -> bytes:
    ct, sealed = _unpack(blob, 2)
    wrapping_key = hkdf_sha384(decapsulate(private, ct), WRAP_INFO + b"|" + context)
    return ossl.aes_gcm_decrypt(wrapping_key, sealed, aad=context)
