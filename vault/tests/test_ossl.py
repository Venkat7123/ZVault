import pytest

from zvault_vault.crypto import ossl


def test_openssl_is_3_5_or_newer():
    assert ossl.version().startswith("OpenSSL 3.")
    assert ossl._lib.OpenSSL_version_num() >= ossl.MIN_VERSION


def test_random_bytes_length_and_variety():
    assert len(ossl.random_bytes(32)) == 32
    assert ossl.random_bytes(32) != ossl.random_bytes(32)


def test_aes_gcm_round_trip_with_aad():
    key = ossl.random_bytes(32)
    blob = ossl.aes_gcm_encrypt(key, b"home loan application", aad=b"ctx")
    assert b"home loan" not in blob
    assert ossl.aes_gcm_decrypt(key, blob, aad=b"ctx") == b"home loan application"


def test_aes_gcm_empty_plaintext():
    key = ossl.random_bytes(32)
    assert ossl.aes_gcm_decrypt(key, ossl.aes_gcm_encrypt(key, b"")) == b""


@pytest.mark.parametrize("change", ["ciphertext", "tag", "aad", "key"])
def test_aes_gcm_rejects_any_change(change):
    key = ossl.random_bytes(32)
    blob = bytearray(ossl.aes_gcm_encrypt(key, b"secret data", aad=b"ctx"))
    aad = b"ctx"
    if change == "ciphertext":
        blob[ossl.GCM_NONCE_LEN] ^= 1
    elif change == "tag":
        blob[-1] ^= 1
    elif change == "aad":
        aad = b"other"
    else:
        key = ossl.random_bytes(32)
    with pytest.raises(ossl.DecryptionError):
        ossl.aes_gcm_decrypt(key, bytes(blob), aad=aad)


@pytest.mark.parametrize("algorithm", ["ML-KEM-768", "X25519"])
def test_kem_shared_secrets_match(algorithm):
    key = ossl.PKey.generate(algorithm)
    ct, ss = ossl.kem_encapsulate(key)
    assert len(ss) == 32
    assert ossl.kem_decapsulate(key, ct) == ss


def test_mlkem_768_sizes():
    key = ossl.PKey.generate("ML-KEM-768")
    ct, _ = ossl.kem_encapsulate(key)
    assert len(ct) == 1088  # FIPS 203 ML-KEM-768 ciphertext


@pytest.mark.parametrize("algorithm", ["ML-KEM-768", "ML-DSA-65", "X25519"])
def test_der_round_trip(algorithm):
    key = ossl.PKey.generate(algorithm)
    private = ossl.PKey.from_private_der(key.private_der(), algorithm)
    public = ossl.PKey.from_public_der(key.public_der(), algorithm)
    assert private.public_der() == key.public_der() == public.public_der()


def test_mldsa_sign_and_verify():
    key = ossl.PKey.generate("ML-DSA-65")
    public = ossl.PKey.from_public_der(key.public_der(), "ML-DSA-65")
    sig = ossl.sign(key, b"erasure certificate")
    assert len(sig) == 3309  # FIPS 204 ML-DSA-65 signature
    assert ossl.verify(public, b"erasure certificate", sig)


def test_mldsa_rejects_changed_message_signature_or_key():
    key = ossl.PKey.generate("ML-DSA-65")
    sig = ossl.sign(key, b"erasure certificate")
    assert not ossl.verify(key, b"erasure certificate!", sig)
    assert not ossl.verify(key, b"erasure certificate", sig[:-1] + bytes([sig[-1] ^ 1]))
    assert not ossl.verify(ossl.PKey.generate("ML-DSA-65"), b"erasure certificate", sig)


def test_rsa_oaep_round_trip():
    key = ossl.PKey.generate("RSA", rsa_bits=2048)
    ct = ossl.rsa_oaep_encrypt(key, b"k" * 32)
    assert ossl.rsa_oaep_decrypt(key, ct) == b"k" * 32
