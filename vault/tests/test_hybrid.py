import pytest

from zvault_vault.crypto import hybrid, ossl


@pytest.fixture(scope="module")
def root():
    return hybrid.HybridPrivateKey.generate()


def test_hybrid_encapsulation_round_trip(root):
    ct, secret = hybrid.encapsulate(root.public_key())
    assert len(secret) == 32
    assert hybrid.decapsulate(root, ct) == secret


def test_each_encapsulation_is_fresh(root):
    (ct1, s1), (ct2, s2) = hybrid.encapsulate(root.public_key()), hybrid.encapsulate(root.public_key())
    assert ct1 != ct2 and s1 != s2


def test_keys_survive_serialization(root):
    restored = hybrid.HybridPrivateKey.from_bytes(root.to_bytes())
    public = hybrid.HybridPublicKey.from_bytes(root.public_key().to_bytes())
    ct, secret = hybrid.encapsulate(public)
    assert hybrid.decapsulate(restored, ct) == secret


def test_wrap_and_unwrap(root):
    key = ossl.random_bytes(32)
    blob = hybrid.wrap_key(root.public_key(), key, b"kek|C-1|v1")
    assert key not in blob
    assert hybrid.unwrap_key(root, blob, b"kek|C-1|v1") == key


def test_wrapped_key_cannot_move_to_another_customer(root):
    blob = hybrid.wrap_key(root.public_key(), ossl.random_bytes(32), b"kek|C-1|v1")
    with pytest.raises(ossl.DecryptionError):
        hybrid.unwrap_key(root, blob, b"kek|C-2|v1")


def test_other_root_cannot_unwrap(root):
    blob = hybrid.wrap_key(root.public_key(), ossl.random_bytes(32), b"ctx")
    with pytest.raises(ossl.DecryptionError):
        hybrid.unwrap_key(hybrid.HybridPrivateKey.generate(), blob, b"ctx")


def test_tampered_or_truncated_blob_rejected(root):
    blob = bytearray(hybrid.wrap_key(root.public_key(), ossl.random_bytes(32), b"ctx"))
    blob[-1] ^= 1
    with pytest.raises(ossl.DecryptionError):
        hybrid.unwrap_key(root, bytes(blob), b"ctx")
    with pytest.raises(ossl.DecryptionError):
        hybrid.unwrap_key(root, bytes(blob[:40]), b"ctx")


def test_hkdf_lengths_and_domain_separation():
    assert len(hybrid.hkdf_sha384(b"ikm", b"a", 64)) == 64
    assert hybrid.hkdf_sha384(b"ikm", b"a") != hybrid.hkdf_sha384(b"ikm", b"b")
    assert hybrid.hkdf_sha384(b"ikm", b"a") == hybrid.hkdf_sha384(b"ikm", b"a")
