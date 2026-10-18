import pytest

from zvault_vault.keys import (
    KeyDestroyedError,
    KeyNotActiveError,
    KeyServiceError,
    KeyState,
    LeaseError,
    LegalHoldError,
    SoftHSM,
)


@pytest.fixture
def hsm(tmp_path, clock):
    service = SoftHSM(tmp_path / "hsm", clock=clock)
    service.create_customer_key("C-1")
    yield service
    service.close()


def test_new_key_is_active_and_wrapped(hsm):
    info = hsm.info("C-1")
    assert info.state is KeyState.ACTIVE and info.version == 1
    assert len(hsm.wrapped_kek("C-1")) > 1088  # carries an ML-KEM-768 ciphertext


def test_duplicate_customer_rejected(hsm):
    with pytest.raises(KeyServiceError):
        hsm.create_customer_key("C-1")


def test_lease_needs_a_purpose(hsm):
    with pytest.raises(KeyServiceError):
        hsm.lease("C-1", purpose="  ")


def test_data_key_round_trip(hsm):
    with hsm.lease("C-1", "card dispute D-1") as lease:
        dek, wrapped = hsm.new_data_key(lease, b"copy-1")
        assert hsm.open_data_key(lease, wrapped, b"copy-1") == dek


def test_lease_expires(hsm, clock):
    lease = hsm.lease("C-1", "review", ttl=300)
    clock.advance(301)
    assert not lease.active
    with pytest.raises(LeaseError):
        hsm.new_data_key(lease, b"copy-1")


def test_revoked_lease_cannot_be_used(hsm):
    lease = hsm.lease("C-1", "review")
    lease.revoke()
    with pytest.raises(LeaseError):
        hsm.new_data_key(lease, b"copy-1")


def test_destroy_flow(hsm):
    lease = hsm.lease("C-1", "review")
    hsm.schedule_destruction("C-1")
    assert hsm.info("C-1").state is KeyState.PENDING_DESTRUCTION
    assert not lease.active  # pending destruction revokes open leases
    with pytest.raises(KeyNotActiveError):
        hsm.lease("C-1", "review")

    assert hsm.destroy_due() == ["C-1"]
    info = hsm.info("C-1")
    assert info.state is KeyState.DESTROYED and info.destroyed_at is not None
    assert hsm.wrapped_kek("C-1") is None
    with pytest.raises(KeyDestroyedError):
        hsm.lease("C-1", "review")


def test_pending_window_and_cancel(hsm, clock):
    hsm.schedule_destruction("C-1", delay_seconds=3600)
    assert hsm.destroy_due() == []
    hsm.cancel_destruction("C-1")
    assert hsm.info("C-1").state is KeyState.ACTIVE

    hsm.schedule_destruction("C-1", delay_seconds=3600)
    clock.advance(3601)
    assert hsm.destroy_due() == ["C-1"]


def test_legal_hold_blocks_destruction(hsm):
    hsm.set_legal_hold("C-1", True)
    with pytest.raises(LegalHoldError):
        hsm.schedule_destruction("C-1")


def test_hold_placed_during_pending_window_wins(hsm):
    hsm.schedule_destruction("C-1", delay_seconds=0)
    hsm.set_legal_hold("C-1", True)
    assert hsm.destroy_due() == []
    assert hsm.info("C-1").state is KeyState.PENDING_DESTRUCTION


def test_keys_persist_across_restart(tmp_path, clock):
    first = SoftHSM(tmp_path / "hsm", clock=clock)
    first.create_customer_key("C-9")
    with first.lease("C-9", "review") as lease:
        dek, wrapped = first.new_data_key(lease, b"copy")
    first.close()

    second = SoftHSM(tmp_path / "hsm", clock=clock)
    with second.lease("C-9", "review") as lease:
        assert second.open_data_key(lease, wrapped, b"copy") == dek
    second.close()


def test_destroyed_kek_is_gone_from_the_database_file(tmp_path, clock):
    hsm = SoftHSM(tmp_path / "hsm", clock=clock)
    hsm.create_customer_key("C-7")
    wrapped = hsm.wrapped_kek("C-7")
    hsm.schedule_destruction("C-7")
    hsm.destroy_due()
    hsm.close()
    assert wrapped[-64:] not in (tmp_path / "hsm" / "keys.db").read_bytes()
