import pytest

from zvault_vault.crypto import ossl
from zvault_vault.keys import KeyDestroyedError, LeaseError, SoftHSM
from zvault_vault.store import EncryptedStore


@pytest.fixture
def env(tmp_path, clock):
    hsm = SoftHSM(tmp_path / "hsm", clock=clock)
    for c in ("C-1", "C-2"):
        hsm.create_customer_key(c)
    store = EncryptedStore(tmp_path / "data" / "copies.db", hsm)
    yield hsm, store
    store.close()
    hsm.close()


def test_put_and_get_text(env):
    hsm, store = env
    with hsm.lease("C-1", "dispute D-1") as lease:
        copy_id = store.put_text(lease, "chat", "I want to apply for a home loan.")
        assert store.get_text(lease, copy_id) == "I want to apply for a home loan."


def test_nothing_readable_on_disk(env, tmp_path):
    hsm, store = env
    with hsm.lease("C-1", "dispute D-1") as lease:
        copy_id = store.put_text(lease, "chat", "PAN ABCDE1234F salary 85000")
    sealed = store.sealed(copy_id)
    assert b"ABCDE1234F" not in sealed["ciphertext"]
    store.close()
    assert b"ABCDE1234F" not in (tmp_path / "data" / "copies.db").read_bytes()


def test_copies_are_registered(env):
    hsm, store = env
    with hsm.lease("C-1", "dispute D-1") as lease:
        ids = [store.put_text(lease, kind, "x") for kind in ("chat", "embedding", "memory")]
    records = store.registry.for_customer("C-1")
    assert [r.copy_id for r in records] == ids
    assert {r.location for r in records} == {"encrypted-store"}


def test_other_customers_lease_cannot_read(env):
    hsm, store = env
    with hsm.lease("C-1", "dispute D-1") as lease:
        copy_id = store.put_text(lease, "chat", "private")
    with hsm.lease("C-2", "dispute D-2") as other:
        with pytest.raises(LeaseError):
            store.get(other, copy_id)


def test_tampered_copy_rejected(env):
    hsm, store = env
    with hsm.lease("C-1", "dispute D-1") as lease:
        copy_id = store.put_text(lease, "chat", "private")
        store._db.execute(
            "UPDATE sealed_copies SET ciphertext = ? WHERE copy_id = ?",
            (store.sealed(copy_id)["ciphertext"][:-1] + b"\x00", copy_id),
        )
        with pytest.raises(ossl.DecryptionError):
            store.get(lease, copy_id)


def test_destroying_the_key_makes_every_copy_unreadable(env):
    hsm, store = env
    with hsm.lease("C-1", "dispute D-1") as lease:
        ids = [store.put_text(lease, "chat", f"message {i}") for i in range(5)]
    with hsm.lease("C-2", "dispute D-2") as lease:
        kept = store.put_text(lease, "chat", "another customer")

    hsm.schedule_destruction("C-1")
    hsm.destroy_due()

    with pytest.raises(KeyDestroyedError):
        hsm.lease("C-1", "dispute D-1")
    assert all(store.sealed(i)["ciphertext"] for i in ids)  # ciphertext still on disk, but no key exists
    with hsm.lease("C-2", "dispute D-2") as lease:
        assert store.get_text(lease, kept) == "another customer"
