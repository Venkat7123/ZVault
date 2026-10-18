"""Thin ctypes binding to the operating system's OpenSSL 3.5+ libcrypto.

Using the system library (not a bundled one) matters on IBM LinuxONE: RHEL's
OpenSSL runs AES on the CPACF instructions of the IBM Z processor and ships the
NIST post-quantum algorithms ML-KEM (FIPS 203) and ML-DSA (FIPS 204).

Only the handful of calls ZVault needs are bound here.
"""

import ctypes
import ctypes.util
import os
from ctypes import POINTER, byref, c_char_p, c_int, c_long, c_size_t, c_ubyte, c_ulong, c_void_p

MIN_VERSION = 0x30500000  # OpenSSL 3.5.0: first release with ML-KEM and ML-DSA

GCM_NONCE_LEN = 12
GCM_TAG_LEN = 16
_EVP_CTRL_GCM_GET_TAG = 0x10
_EVP_CTRL_GCM_SET_TAG = 0x11
_RSA_PKCS1_OAEP_PADDING = 4


class OpenSSLError(Exception):
    """An OpenSSL call failed; the message carries OpenSSL's own error queue."""


class DecryptionError(OpenSSLError):
    """Ciphertext or its authentication tag did not verify (wrong key or tampered data)."""


def _candidates():
    yield os.environ.get("ZVAULT_LIBCRYPTO")
    yield "libcrypto.so.3"
    yield ctypes.util.find_library("crypto")
    if os.name == "nt":
        # Windows: OpenSSL ships as libcrypto-3-x64.dll; Git for Windows bundles a 3.5+ build
        yield "libcrypto-3-x64.dll"
        yield "libcrypto-3.dll"
        for root in (os.environ.get("ProgramFiles"), os.environ.get("ProgramW6432"), os.environ.get("LOCALAPPDATA")):
            if not root:
                continue
            for sub in (("Git", "mingw64", "bin"), ("OpenSSL-Win64", "bin"), ("Programs", "Git", "mingw64", "bin")):
                yield os.path.join(root, *sub, "libcrypto-3-x64.dll")


def _load_libcrypto():
    too_old = []
    for name in _candidates():
        if not name:
            continue
        try:
            lib = ctypes.CDLL(name)
            lib.OpenSSL_version_num.restype = c_ulong
        except (OSError, AttributeError):
            continue
        if lib.OpenSSL_version_num() >= MIN_VERSION:
            return lib
        too_old.append(f"{name} ({lib.OpenSSL_version_num():#x})")
    hint = f"; older versions found: {', '.join(too_old)}" if too_old else ""
    raise OpenSSLError(f"libcrypto (OpenSSL 3.5+) not found; set ZVAULT_LIBCRYPTO to its path{hint}")


_lib = _load_libcrypto()

_SIGNATURES = {
    "OpenSSL_version_num": (c_ulong, []),
    "OpenSSL_version": (c_char_p, [c_int]),
    "ERR_get_error": (c_ulong, []),
    "ERR_error_string_n": (None, [c_ulong, c_char_p, c_size_t]),
    "RAND_bytes": (c_int, [c_void_p, c_int]),
    # symmetric
    "EVP_aes_256_gcm": (c_void_p, []),
    "EVP_CIPHER_CTX_new": (c_void_p, []),
    "EVP_CIPHER_CTX_free": (None, [c_void_p]),
    "EVP_CIPHER_CTX_ctrl": (c_int, [c_void_p, c_int, c_int, c_void_p]),
    "EVP_EncryptInit_ex": (c_int, [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p]),
    "EVP_EncryptUpdate": (c_int, [c_void_p, c_void_p, POINTER(c_int), c_void_p, c_int]),
    "EVP_EncryptFinal_ex": (c_int, [c_void_p, c_void_p, POINTER(c_int)]),
    "EVP_DecryptInit_ex": (c_int, [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p]),
    "EVP_DecryptUpdate": (c_int, [c_void_p, c_void_p, POINTER(c_int), c_void_p, c_int]),
    "EVP_DecryptFinal_ex": (c_int, [c_void_p, c_void_p, POINTER(c_int)]),
    # asymmetric keys
    "EVP_PKEY_CTX_new_from_name": (c_void_p, [c_void_p, c_char_p, c_char_p]),
    "EVP_PKEY_CTX_new_from_pkey": (c_void_p, [c_void_p, c_void_p, c_char_p]),
    "EVP_PKEY_CTX_free": (None, [c_void_p]),
    "EVP_PKEY_CTX_set_kem_op": (c_int, [c_void_p, c_char_p]),
    "EVP_PKEY_CTX_set_rsa_keygen_bits": (c_int, [c_void_p, c_int]),
    "EVP_PKEY_CTX_set_rsa_padding": (c_int, [c_void_p, c_int]),
    "EVP_PKEY_keygen_init": (c_int, [c_void_p]),
    "EVP_PKEY_generate": (c_int, [c_void_p, POINTER(c_void_p)]),
    "EVP_PKEY_free": (None, [c_void_p]),
    "EVP_PKEY_encapsulate_init": (c_int, [c_void_p, c_void_p]),
    "EVP_PKEY_encapsulate": (c_int, [c_void_p, c_void_p, POINTER(c_size_t), c_void_p, POINTER(c_size_t)]),
    "EVP_PKEY_decapsulate_init": (c_int, [c_void_p, c_void_p]),
    "EVP_PKEY_decapsulate": (c_int, [c_void_p, c_void_p, POINTER(c_size_t), c_void_p, c_size_t]),
    "EVP_PKEY_encrypt_init": (c_int, [c_void_p]),
    "EVP_PKEY_encrypt": (c_int, [c_void_p, c_void_p, POINTER(c_size_t), c_void_p, c_size_t]),
    "EVP_PKEY_decrypt_init": (c_int, [c_void_p]),
    "EVP_PKEY_decrypt": (c_int, [c_void_p, c_void_p, POINTER(c_size_t), c_void_p, c_size_t]),
    "EVP_MD_CTX_new": (c_void_p, []),
    "EVP_MD_CTX_free": (None, [c_void_p]),
    "EVP_DigestSignInit_ex": (c_int, [c_void_p, c_void_p, c_char_p, c_void_p, c_char_p, c_void_p, c_void_p]),
    "EVP_DigestSign": (c_int, [c_void_p, c_void_p, POINTER(c_size_t), c_void_p, c_size_t]),
    "EVP_DigestVerifyInit_ex": (c_int, [c_void_p, c_void_p, c_char_p, c_void_p, c_char_p, c_void_p, c_void_p]),
    "EVP_DigestVerify": (c_int, [c_void_p, c_void_p, c_size_t, c_void_p, c_size_t]),
    # DER serialization
    "i2d_PrivateKey": (c_int, [c_void_p, POINTER(POINTER(c_ubyte))]),
    "i2d_PUBKEY": (c_int, [c_void_p, POINTER(POINTER(c_ubyte))]),
    "d2i_AutoPrivateKey_ex": (c_void_p, [c_void_p, POINTER(POINTER(c_ubyte)), c_long, c_void_p, c_char_p]),
    "d2i_PUBKEY_ex": (c_void_p, [c_void_p, POINTER(POINTER(c_ubyte)), c_long, c_void_p, c_char_p]),
}

for _name, (_res, _args) in _SIGNATURES.items():
    _fn = getattr(_lib, _name)
    _fn.restype = _res
    _fn.argtypes = _args

if _lib.OpenSSL_version_num() < MIN_VERSION:
    raise OpenSSLError(f"{_lib.OpenSSL_version(0).decode()} found; ZVault needs OpenSSL 3.5 or newer")


def version() -> str:
    return _lib.OpenSSL_version(0).decode()


def _error(what: str, cls=OpenSSLError) -> OpenSSLError:
    reasons = []
    while code := _lib.ERR_get_error():
        buf = ctypes.create_string_buffer(256)
        _lib.ERR_error_string_n(code, buf, len(buf))
        reasons.append(buf.value.decode())
    return cls(f"{what} failed" + (f": {'; '.join(reasons)}" if reasons else ""))


def _check(ok, what: str):
    if ok != 1:
        raise _error(what)


def random_bytes(n: int) -> bytes:
    buf = ctypes.create_string_buffer(n)
    _check(_lib.RAND_bytes(buf, n), "RAND_bytes")
    return buf.raw


# --- AES-256-GCM ------------------------------------------------------------------------

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypt with AES-256-GCM. Returns nonce || ciphertext || tag."""
    if len(key) != 32:
        raise ValueError("AES-256 needs a 32-byte key")
    nonce = random_bytes(GCM_NONCE_LEN)
    ctx = _lib.EVP_CIPHER_CTX_new()
    try:
        _check(_lib.EVP_EncryptInit_ex(ctx, _lib.EVP_aes_256_gcm(), None, key, nonce), "EVP_EncryptInit_ex")
        n = c_int()
        if aad:
            _check(_lib.EVP_EncryptUpdate(ctx, None, byref(n), aad, len(aad)), "GCM aad")
        out = ctypes.create_string_buffer(len(plaintext) + 16)
        _check(_lib.EVP_EncryptUpdate(ctx, out, byref(n), plaintext, len(plaintext)), "EVP_EncryptUpdate")
        written = n.value
        _check(_lib.EVP_EncryptFinal_ex(ctx, ctypes.byref(out, written), byref(n)), "EVP_EncryptFinal_ex")
        written += n.value
        tag = ctypes.create_string_buffer(GCM_TAG_LEN)
        _check(_lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag), "GCM get tag")
        return nonce + out.raw[:written] + tag.raw
    finally:
        _lib.EVP_CIPHER_CTX_free(ctx)


def aes_gcm_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Decrypt nonce || ciphertext || tag. Raises DecryptionError if anything was altered."""
    if len(key) != 32:
        raise ValueError("AES-256 needs a 32-byte key")
    if len(blob) < GCM_NONCE_LEN + GCM_TAG_LEN:
        raise DecryptionError("ciphertext too short")
    nonce, body, tag = blob[:GCM_NONCE_LEN], blob[GCM_NONCE_LEN:-GCM_TAG_LEN], blob[-GCM_TAG_LEN:]
    ctx = _lib.EVP_CIPHER_CTX_new()
    try:
        _check(_lib.EVP_DecryptInit_ex(ctx, _lib.EVP_aes_256_gcm(), None, key, nonce), "EVP_DecryptInit_ex")
        n = c_int()
        if aad:
            _check(_lib.EVP_DecryptUpdate(ctx, None, byref(n), aad, len(aad)), "GCM aad")
        out = ctypes.create_string_buffer(len(body) + 16)
        _check(_lib.EVP_DecryptUpdate(ctx, out, byref(n), body, len(body)), "EVP_DecryptUpdate")
        written = n.value
        _check(_lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag), "GCM set tag")
        if _lib.EVP_DecryptFinal_ex(ctx, ctypes.byref(out, written), byref(n)) != 1:
            raise _error("AES-GCM authentication", DecryptionError)
        return out.raw[:written + n.value]
    finally:
        _lib.EVP_CIPHER_CTX_free(ctx)


# --- asymmetric keys ------------------------------------------------------------------------

class PKey:
    """Owns an EVP_PKEY handle (ML-KEM, ML-DSA, X25519 or RSA) and frees it when collected."""

    def __init__(self, handle: int, algorithm: str):
        if not handle:
            raise _error(f"{algorithm} key")
        self._handle = c_void_p(handle)
        self.algorithm = algorithm

    @classmethod
    def generate(cls, algorithm: str, rsa_bits: int = 0) -> "PKey":
        ctx = _lib.EVP_PKEY_CTX_new_from_name(None, algorithm.encode(), None)
        if not ctx:
            raise _error(f"unknown algorithm {algorithm}")
        try:
            _check(_lib.EVP_PKEY_keygen_init(ctx), "EVP_PKEY_keygen_init")
            if rsa_bits:
                _check(_lib.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, rsa_bits), "set RSA bits")
            out = c_void_p()
            _check(_lib.EVP_PKEY_generate(ctx, byref(out)), f"{algorithm} keygen")
            return cls(out.value, algorithm)
        finally:
            _lib.EVP_PKEY_CTX_free(ctx)

    def _der(self, i2d) -> bytes:
        n = i2d(self._handle, None)
        if n <= 0:
            raise _error(f"{self.algorithm} DER encoding")
        buf = (c_ubyte * n)()
        p = ctypes.cast(buf, POINTER(c_ubyte))
        i2d(self._handle, byref(p))
        return bytes(buf)

    def private_der(self) -> bytes:
        return self._der(_lib.i2d_PrivateKey)

    def public_der(self) -> bytes:
        return self._der(_lib.i2d_PUBKEY)

    @classmethod
    def _from_der(cls, d2i, der: bytes, algorithm: str) -> "PKey":
        buf = (c_ubyte * len(der)).from_buffer_copy(der)
        p = ctypes.cast(buf, POINTER(c_ubyte))
        return cls(d2i(None, byref(p), len(der), None, None), algorithm)

    @classmethod
    def from_private_der(cls, der: bytes, algorithm: str) -> "PKey":
        return cls._from_der(_lib.d2i_AutoPrivateKey_ex, der, algorithm)

    @classmethod
    def from_public_der(cls, der: bytes, algorithm: str) -> "PKey":
        return cls._from_der(_lib.d2i_PUBKEY_ex, der, algorithm)

    def _ctx(self):
        ctx = _lib.EVP_PKEY_CTX_new_from_pkey(None, self._handle, None)
        if not ctx:
            raise _error("EVP_PKEY_CTX_new_from_pkey")
        return ctx

    def __del__(self):
        if getattr(self, "_handle", None):
            _lib.EVP_PKEY_free(self._handle)
            self._handle = None


# --- KEM: ML-KEM-768 and X25519 (DHKEM, RFC 9180) ---------------------------------------------

def _kem_op(algorithm: str):
    return b"DHKEM" if algorithm in ("X25519", "X448", "EC") else None


def kem_encapsulate(public: PKey) -> tuple[bytes, bytes]:
    """Returns (ciphertext, shared_secret) for the holder of the matching private key."""
    ctx = public._ctx()
    try:
        _check(_lib.EVP_PKEY_encapsulate_init(ctx, None), "EVP_PKEY_encapsulate_init")
        if op := _kem_op(public.algorithm):
            _check(_lib.EVP_PKEY_CTX_set_kem_op(ctx, op), "set KEM op")
        ct_len, ss_len = c_size_t(), c_size_t()
        _check(_lib.EVP_PKEY_encapsulate(ctx, None, byref(ct_len), None, byref(ss_len)), "KEM sizes")
        ct, ss = ctypes.create_string_buffer(ct_len.value), ctypes.create_string_buffer(ss_len.value)
        _check(_lib.EVP_PKEY_encapsulate(ctx, ct, byref(ct_len), ss, byref(ss_len)), "EVP_PKEY_encapsulate")
        return ct.raw[:ct_len.value], ss.raw[:ss_len.value]
    finally:
        _lib.EVP_PKEY_CTX_free(ctx)


def kem_decapsulate(private: PKey, ciphertext: bytes) -> bytes:
    ctx = private._ctx()
    try:
        _check(_lib.EVP_PKEY_decapsulate_init(ctx, None), "EVP_PKEY_decapsulate_init")
        if op := _kem_op(private.algorithm):
            _check(_lib.EVP_PKEY_CTX_set_kem_op(ctx, op), "set KEM op")
        ss_len = c_size_t()
        _check(_lib.EVP_PKEY_decapsulate(ctx, None, byref(ss_len), ciphertext, len(ciphertext)), "KEM size")
        ss = ctypes.create_string_buffer(ss_len.value)
        _check(_lib.EVP_PKEY_decapsulate(ctx, ss, byref(ss_len), ciphertext, len(ciphertext)), "EVP_PKEY_decapsulate")
        return ss.raw[:ss_len.value]
    finally:
        _lib.EVP_PKEY_CTX_free(ctx)


# --- ML-DSA signatures ------------------------------------------------------------------------

def sign(private: PKey, message: bytes) -> bytes:
    md = _lib.EVP_MD_CTX_new()
    try:
        _check(_lib.EVP_DigestSignInit_ex(md, None, None, None, None, private._handle, None), "EVP_DigestSignInit_ex")
        sig_len = c_size_t()
        _check(_lib.EVP_DigestSign(md, None, byref(sig_len), message, len(message)), "signature size")
        sig = ctypes.create_string_buffer(sig_len.value)
        _check(_lib.EVP_DigestSign(md, sig, byref(sig_len), message, len(message)), "EVP_DigestSign")
        return sig.raw[:sig_len.value]
    finally:
        _lib.EVP_MD_CTX_free(md)


def verify(public: PKey, message: bytes, signature: bytes) -> bool:
    md = _lib.EVP_MD_CTX_new()
    try:
        _check(_lib.EVP_DigestVerifyInit_ex(md, None, None, None, None, public._handle, None), "EVP_DigestVerifyInit_ex")
        ok = _lib.EVP_DigestVerify(md, signature, len(signature), message, len(message)) == 1
        while _lib.ERR_get_error():  # a failed verify leaves entries on the queue
            pass
        return ok
    finally:
        _lib.EVP_MD_CTX_free(md)


# --- RSA-OAEP (classical baseline for the quantum-vulnerable comparison only) -----------------

def rsa_oaep_encrypt(public: PKey, plaintext: bytes) -> bytes:
    ctx = public._ctx()
    try:
        _check(_lib.EVP_PKEY_encrypt_init(ctx), "EVP_PKEY_encrypt_init")
        _check(_lib.EVP_PKEY_CTX_set_rsa_padding(ctx, _RSA_PKCS1_OAEP_PADDING), "set OAEP")
        n = c_size_t()
        _check(_lib.EVP_PKEY_encrypt(ctx, None, byref(n), plaintext, len(plaintext)), "RSA size")
        out = ctypes.create_string_buffer(n.value)
        _check(_lib.EVP_PKEY_encrypt(ctx, out, byref(n), plaintext, len(plaintext)), "EVP_PKEY_encrypt")
        return out.raw[:n.value]
    finally:
        _lib.EVP_PKEY_CTX_free(ctx)


def rsa_oaep_decrypt(private: PKey, ciphertext: bytes) -> bytes:
    ctx = private._ctx()
    try:
        _check(_lib.EVP_PKEY_decrypt_init(ctx), "EVP_PKEY_decrypt_init")
        _check(_lib.EVP_PKEY_CTX_set_rsa_padding(ctx, _RSA_PKCS1_OAEP_PADDING), "set OAEP")
        n = c_size_t()
        _check(_lib.EVP_PKEY_decrypt(ctx, None, byref(n), ciphertext, len(ciphertext)), "RSA size")
        out = ctypes.create_string_buffer(n.value)
        if _lib.EVP_PKEY_decrypt(ctx, out, byref(n), ciphertext, len(ciphertext)) != 1:
            raise _error("RSA-OAEP decrypt", DecryptionError)
        return out.raw[:n.value]
    finally:
        _lib.EVP_PKEY_CTX_free(ctx)
