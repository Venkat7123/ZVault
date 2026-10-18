import pytest

from zvault_vault.certs import verify_certificate
from zvault_vault.erasure import ErasureRefused
from zvault_vault.keys import KeyState
from zvault_vault.tlog import verify_inclusion, verify_tree_head


def _customer(env, i=0):
    return env["bank"].customers[i]


def test_forget_me_end_to_end(bank_env):
    env, c = bank_env, _customer(bank_env)
    out = env["engine"].erase(c.customer_id, identity_verified=True, identifiers=c.identifiers())
    cert = out["certificate"]

    assert env["hsm"].info(c.customer_id).state is KeyState.DESTROYED
    assert cert["status"] == "erased_with_exceptions"  # backups are reported as not verifiable
    store_copies = [x for x in cert["copies"] if x["location"] == "encrypted-store"]
    assert store_copies and all(x["result"] == "erased" for x in store_copies)
    assert len(store_copies) == len(env["store"].registry.for_customer(c.customer_id))

    inv = cert["recovery_test"]["inversion"]
    assert inv["before_erasure"]["mean_token_f1"] > 0.8
    assert inv["after_erasure"]["identifiers_recovered"] == []
    assert inv["after_erasure"]["mean_token_f1"] < inv["before_erasure"]["mean_token_f1"]
    assert inv["after_erasure"]["random_noise_baseline"]["trials"] == 100

    mem = cert["recovery_test"]["membership_inference"]
    assert mem["before_erasure"]["detected"] is True
    assert mem["after_erasure"]["detected"] is False
    assert cert["recovery_test"]["residue_scan"]["hits"] == []

    assert verify_certificate(cert, env["signer"].public_der)
    head = out["tree_head"]
    assert verify_tree_head(head, env["signer"].public_der)
    assert verify_inclusion(env["log"].entry(out["log_index"]), out["log_index"], head.size,
                            out["inclusion_proof"], head.root)


def test_membership_and_inversion_hold_in_a_larger_bank(big_bank_env):
    env = big_bank_env
    for c in env["bank"].customers[:3]:
        rt = env["engine"].erase(c.customer_id, True, c.identifiers())["certificate"]["recovery_test"]
        assert rt["membership_inference"]["before_erasure"]["detected"] is True
        assert rt["membership_inference"]["after_erasure"]["detected"] is False
        before, after = rt["inversion"]["before_erasure"], rt["inversion"]["after_erasure"]
        assert after["identifiers_recovered"] == []
        assert after["mean_token_f1"] < before["mean_token_f1"]


def test_other_customers_untouched(bank_env):
    env = bank_env
    env["engine"].erase(_customer(env).customer_id, True, _customer(env).identifiers())
    other = _customer(env, 1).customer_id
    assert env["hsm"].info(other).state is KeyState.ACTIVE
    with env["hsm"].lease(other, "check") as lease:
        rec = [r for r in env["store"].registry.for_customer(other) if r.kind == "chat"][0]
        assert env["store"].get_text(lease, rec.copy_id)


def test_unverified_identity_touches_nothing(bank_env):
    c = _customer(bank_env)
    with pytest.raises(ErasureRefused):
        bank_env["engine"].erase(c.customer_id, identity_verified=False, identifiers=c.identifiers())
    assert bank_env["hsm"].info(c.customer_id).state is KeyState.ACTIVE


def test_legal_hold_gives_a_signed_refusal(bank_env):
    env, c = bank_env, _customer(bank_env)
    env["hsm"].set_legal_hold(c.customer_id, True)
    cert = env["engine"].erase(c.customer_id, True, c.identifiers())["certificate"]
    assert cert["status"] == "refused_legal_hold"
    assert env["hsm"].info(c.customer_id).state is KeyState.ACTIVE
    assert verify_certificate(cert, env["signer"].public_der)


def test_external_copy_is_reported_not_verifiable(bank_env):
    env, c = bank_env, _customer(bank_env)
    env["store"].registry.record_external(c.customer_id, "chat", "external-ai-provider")
    cert = env["engine"].erase(c.customer_id, True, c.identifiers())["certificate"]
    ext = [x for x in cert["copies"] if x["location"] == "external-ai-provider"]
    assert ext and ext[0]["result"] == "not_verifiable"


def test_readable_leak_makes_the_certificate_fail(bank_env):
    env, c = bank_env, _customer(bank_env)
    (env["data"] / "debug.log").write_text(f"processing customer PAN {c.pan}\n")
    cert = env["engine"].erase(c.customer_id, True, c.identifiers())["certificate"]
    assert cert["status"] == "failed"
    assert any(x["kind"] == "residue" and x["result"] == "failed" for x in cert["copies"])
