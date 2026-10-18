from zvault_vault.data import RETENTION_DAYS, generate_bank


def test_generation_is_deterministic():
    a, b = generate_bank(10, seed=5), generate_bank(10, seed=5)
    assert [m.text for m in a.messages] == [m.text for m in b.messages]


def test_every_retention_class_and_both_families_appear():
    bank = generate_bank(60)
    assert {m.retention for m in bank.messages} == set(RETENTION_DAYS)
    assert {m.family for m in bank.messages} == {"train", "test"}
    assert {m.kind for m in bank.messages} == {"chat", "agent-memory", "transaction"}


def test_identifiers_are_unique_per_customer():
    bank = generate_bank(60)
    accounts = [c.account_no for c in bank.customers]
    assert len(set(accounts)) == len(accounts)
    assert all(len(c.pan) == 10 for c in bank.customers)
