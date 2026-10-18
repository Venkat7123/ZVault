import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class FakeClock:
    def __init__(self, start: float = 1_000_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def bank_env(tmp_path, clock):
    yield from _bank_env(tmp_path, clock, 12)


@pytest.fixture
def big_bank_env(tmp_path, clock):
    yield from _bank_env(tmp_path, clock, 60)


def _bank_env(tmp_path, clock, n_customers):
    """A bank of n customers ingested, plus broker, signer, log and erasure engine."""
    from zvault_vault.attacks import CandidateInverter
    from zvault_vault.broker import AccessBroker
    from zvault_vault.certs import CertificateSigner
    from zvault_vault.data import generate_bank
    from zvault_vault.embeddings import HashingEmbedder
    from zvault_vault.erasure import ErasureEngine
    from zvault_vault.ingest import ingest_bank
    from zvault_vault.keys import SoftHSM
    from zvault_vault.store import EncryptedStore
    from zvault_vault.tlog import TransparencyLog

    data = tmp_path / "data"
    bank = generate_bank(n_customers, seed=3)
    embedder = HashingEmbedder()
    hsm = SoftHSM(data / "hsm", clock=clock)
    store = EncryptedStore(data / "copies.db", hsm)
    ingest_bank(bank, hsm, store, embedder, now=clock())
    signer = CertificateSigner(tmp_path / "enclave")
    log = TransparencyLog(data / "tlog.db", signer)
    outsiders = generate_bank(20, seed=99, prefix="AUX")
    inverter = CandidateInverter(embedder, [m.text for m in outsiders.messages])
    probes = [m.text for m in generate_bank(40, seed=123, prefix="NON").messages]
    engine = ErasureEngine(hsm, store, signer, log, embedder, inverter, [data], probes, clock=clock)
    broker = AccessBroker(hsm, data / "broker.db", clock=clock)
    env = dict(bank=bank, embedder=embedder, hsm=hsm, store=store, signer=signer, log=log,
               engine=engine, broker=broker, data=data)
    yield env
    broker.close()
    log.close()
    store.close()
    hsm.close()
