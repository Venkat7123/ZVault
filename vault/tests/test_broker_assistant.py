import pytest

from zvault_vault.assistant import AnalystAssistant
from zvault_vault.broker import AccessDenied


@pytest.fixture
def broker(bank_env):
    b = bank_env["broker"]
    b.register_analyst("A-1", "Analyst One", mfa_verified=True)
    b.register_analyst("A-2", "Analyst Two", mfa_verified=False)
    b.open_case("D-1", "card dispute", ["CUST-0001", "CUST-0002"])
    return b


def test_allowed_request_returns_lease(broker):
    with broker.request("A-1", "D-1", "CUST-0001") as lease:
        assert lease.active and "card dispute" in lease.purpose


@pytest.mark.parametrize("analyst, case, customer, reason", [
    ("A-9", "D-1", "CUST-0001", "unknown analyst"),
    ("A-2", "D-1", "CUST-0001", "MFA"),
    ("A-1", "D-404", "CUST-0001", "no open case"),
    ("A-1", "D-1", "CUST-0005", "not part of this case"),
])
def test_refusals(broker, analyst, case, customer, reason):
    with pytest.raises(AccessDenied, match=reason):
        broker.request(analyst, case, customer)


def test_closed_case_refused(broker):
    broker.close_case("D-1")
    with pytest.raises(AccessDenied, match="no open case"):
        broker.request("A-1", "D-1", "CUST-0001")


def test_every_decision_is_logged_for_the_customer(broker):
    broker.request("A-1", "D-1", "CUST-0001").revoke()
    with pytest.raises(AccessDenied):
        broker.request("A-2", "D-1", "CUST-0001")
    log = broker.access_log("CUST-0001")
    assert [d.allowed for d in log] == [True, False]


def test_assistant_answers_and_blocks_erased_customer(bank_env, broker):
    assistant = AnalystAssistant(broker, bank_env["store"], bank_env["embedder"])
    first = assistant.ask("A-1", "D-1", "unauthorised payment dispute")
    assert first.sources and not first.blocked

    bank_env["hsm"].schedule_destruction("CUST-0002")
    bank_env["hsm"].destroy_due()
    second = assistant.ask("A-1", "D-1", "unauthorised payment dispute")
    assert {c for _, c, _, _ in second.sources} <= {"CUST-0001"}
    assert second.blocked and second.blocked[0][0] == "CUST-0002"
    assert "destroyed" in second.blocked[0][1]
