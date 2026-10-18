import pytest

from zvault_vault.certs import verify_certificate
from zvault_vault.data import generate_bank
from zvault_vault.retention import DAY, RetentionModel, RetentionScheduler


@pytest.fixture(scope="module")
def model():
    bank = generate_bank(150, seed=11)
    train = [m for m in bank.messages if m.family == "train"]
    return RetentionModel().fit([m.text for m in train], [m.kind for m in train], [m.retention for m in train])


def test_generalises_to_unseen_phrasings(model):
    test = [m for m in generate_bank(150, seed=12).messages if m.family == "test"]
    preds = model.predict([m.text for m in test], [m.kind for m in test])
    accuracy = sum(p.retention_class == m.retention for p, m in zip(preds, test)) / len(test)
    assert accuracy > 0.75


def test_uncertain_predictions_keep_longer_and_ask_for_review(model):
    p = model.predict(["hello"], ["chat"])[0]
    assert p.needs_review or p.confidence >= 0.6


def test_explain_returns_words(model):
    words = model.explain("Please block my debit card, I lost it", "chat")
    assert words and all(isinstance(w, str) for w, _ in words)


def test_save_and_load(model, tmp_path):
    model.save(tmp_path / "m.pkl")
    again = RetentionModel.load(tmp_path / "m.pkl")
    assert again.predict(["What is my account balance?"], ["chat"])[0].retention_class == "short"


def test_scheduler_shreds_expired_copies_and_respects_legal_hold(bank_env, model, clock):
    env = bank_env
    sched = RetentionScheduler(env["store"], env["hsm"], model, env["signer"], env["log"], clock=clock)
    assigned = sched.assign()
    assert assigned and all(a["retention_until"] > 0 for a in assigned)

    held = env["bank"].customers[0].customer_id
    env["hsm"].set_legal_hold(held, True)
    clock.advance(400 * DAY)  # beyond every "short" (30 d) and "service" (1 y) copy
    report = sched.run()

    shredded = {s["copy_id"] for s in report["shredded"]}
    assert shredded and all(s["retention_class"] in ("short", "service") for s in report["shredded"])
    assert all(env["store"].is_shredded(c) for c in shredded)
    assert all(s["customer_id"] != held for s in report["shredded"])
    assert verify_certificate(report["record"], env["signer"].public_der)

    # long-lived copies survive
    survivors = [r for r in env["store"].registry.all() if r.retention_class == "contract"]
    assert all(not env["store"].is_shredded(r.copy_id) for r in survivors)
