import copy

import pytest

from zvault_vault.certs import CertificateSigner, verify_certificate
from zvault_vault.tlog import (
    TransparencyLog,
    inclusion_path,
    leaf_hash,
    merkle_root,
    verify_inclusion,
    verify_tree_head,
)


@pytest.fixture
def signer(tmp_path):
    return CertificateSigner(tmp_path / "enclave")


def test_certificate_signature_verifies(signer):
    cert = signer.sign({"type": "test", "customer_id": "C-1", "status": "erased"})
    assert cert["signature"]["algorithm"] == "ML-DSA-65"
    assert cert["enclave"]["attestation"].startswith("SIMULATED")
    assert verify_certificate(cert, signer.public_der)


def test_any_change_breaks_the_certificate(signer):
    cert = signer.sign({"type": "test", "copies": [{"result": "failed"}]})
    changed = copy.deepcopy(cert)
    changed["copies"][0]["result"] = "erased"
    assert not verify_certificate(changed, signer.public_der)


def test_other_key_cannot_vouch(signer, tmp_path):
    cert = signer.sign({"type": "test"})
    assert not verify_certificate(cert, CertificateSigner(tmp_path / "other").public_der)


def test_signer_key_persists(tmp_path):
    a, b = CertificateSigner(tmp_path / "e"), CertificateSigner(tmp_path / "e")
    assert a.public_der == b.public_der


@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 7, 8, 9, 13, 16, 17])
def test_every_inclusion_proof_verifies(size):
    entries = [f"entry {i}".encode() for i in range(size)]
    leaves = [leaf_hash(e) for e in entries]
    root = merkle_root(leaves)
    for i, e in enumerate(entries):
        assert verify_inclusion(e, i, size, inclusion_path(i, leaves), root)


def test_inclusion_rejects_wrong_entry_or_position():
    entries = [f"entry {i}".encode() for i in range(6)]
    leaves = [leaf_hash(e) for e in entries]
    root, path = merkle_root(leaves), inclusion_path(2, leaves)
    assert not verify_inclusion(b"forged", 2, 6, path, root)
    assert not verify_inclusion(entries[2], 3, 6, path, root)


def test_log_tree_head_and_proofs(tmp_path, signer):
    log = TransparencyLog(tmp_path / "log.db", signer)
    certs = [signer.sign({"type": "test", "n": i}) for i in range(5)]
    idx = [log.append(c) for c in certs]
    assert idx == list(range(5))
    head = log.tree_head()
    assert head.size == 5 and verify_tree_head(head, signer.public_der)
    assert verify_inclusion(log.entry(3), 3, head.size, log.inclusion_proof(3), head.root)
    log.close()
