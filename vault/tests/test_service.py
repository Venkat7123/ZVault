"""The vault service: store, list, forget, remove one copy, legal hold, tokens (Phase C)."""
import json
import sys
import threading
import urllib.error
import urllib.request
from http.server import HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import service  # noqa: E402
from service import NotFound, Refused, Vault, VaultError  # noqa: E402

FIELDS = {"applicant_reference": "Customer 1002", "loan_amount": "Rs 25 lakh",
          "purpose": "Home loan - purchase of a flat", "tenure": "20 years", "monthly_income": "Rs 1.2 lakh"}
GW, AU = "g" * 40, "a" * 40


@pytest.fixture
def vault(tmp_path):
    v = Vault(tmp_path / "data", tmp_path / "no-models")
    yield v
    v.store.close()


def all_bytes(folder: Path) -> bytes:
    return b"".join(p.read_bytes() for p in folder.rglob("*") if p.is_file())


def test_store_encrypts_under_pseudonymous_customer(vault, tmp_path):
    out = vault.store_copy("1002", FIELDS, "doc sha256=abcd", "CLERK1")
    assert out["copy_id"].startswith("agent-memory-")
    # no model loaded -> keep for the longest period and ask a person
    assert out["retention_class"] == "contract" and out["needs_review"] is True
    disk = all_bytes(tmp_path / "data")
    assert b"Customer 1002" not in disk and b"25 lakh" not in disk and b"1002" not in disk
    listing = vault.list_copies("1002")
    assert listing["key_state"] == "ACTIVE" and [c["status"] for c in listing["copies"]] == ["encrypted"]


def test_forget_produces_verified_certificate_and_blocks_new_copies(vault):
    vault.store_copy("1002", FIELDS, "doc", "CLERK1")
    vault.store_copy("1003", {"applicant_reference": "Customer 1003", "loan_amount": "Rs 8 lakh",
                              "purpose": "Car loan", "tenure": "5 years", "monthly_income": "Rs 0.6 lakh"}, "doc", "CLERK1")
    out = vault.forget("1002", "MANAGER1", identity_verified=True)
    assert out["status"] in ("erased", "erased_with_exceptions")
    assert out["proofs"]["signature_valid"] and out["proofs"]["in_transparency_log"]
    s = out["summary"]
    assert s["copies_erased"] >= 2 and s["copies_failed"] == 0 and s["identifiers_recovered"] == []
    assert s["key_state"] == "DESTROYED" and s["residue_leaks"] == 0
    assert vault.list_copies("1002")["copies"][0]["status"] == "erased"
    assert vault.list_copies("1003")["copies"][0]["status"] == "encrypted"    # others untouched
    with pytest.raises(Refused):
        vault.store_copy("1002", FIELDS, "doc", "CLERK1")
    with pytest.raises(Refused):
        vault.forget("1002", "MANAGER1", identity_verified=True)


def test_forget_needs_identity_and_existing_copies(vault):
    with pytest.raises(NotFound):
        vault.forget("1001", "MANAGER1", identity_verified=True)
    vault.store_copy("1001", FIELDS, "doc", "CLERK1")
    with pytest.raises(VaultError):
        vault.forget("1001", "MANAGER1", identity_verified=False)


def test_remove_one_poisoned_copy(vault):
    bad = vault.store_copy("1002", FIELDS, "doc 1", "CLERK1")["copy_id"]
    good = vault.store_copy("1002", FIELDS, "doc 2", "CLERK1")["copy_id"]
    out = vault.remove_copy("1002", bad, "poisoned", "MANAGER1")
    assert out["status"] == "removed" and all(c["result"] == "unreadable" for c in out["copies"])
    assert out["proofs"]["signature_valid"] and out["proofs"]["in_transparency_log"]
    status = {c["copy_id"]: c["status"] for c in vault.list_copies("1002")["copies"]}
    assert status == {bad: "removed", good: "encrypted"}
    with pytest.raises(Refused):
        vault.remove_copy("1002", bad, "poisoned", "MANAGER1")
    with pytest.raises(NotFound):                       # a copy of ANOTHER customer
        vault.remove_copy("1003", good, "poisoned", "MANAGER1")
    with pytest.raises(VaultError):
        vault.remove_copy("1002", good, "because I say so", "MANAGER1")


def test_legal_hold_blocks_forget_and_removal(vault):
    cid = vault.store_copy("1002", FIELDS, "doc", "CLERK1")["copy_id"]
    assert vault.legal_hold("1002", True, "AUDITOR1")["legal_hold"] is True
    out = vault.forget("1002", "MANAGER1", identity_verified=True)
    assert out["status"] == "refused_legal_hold" and out["proofs"]["signature_valid"]
    with pytest.raises(Refused):
        vault.remove_copy("1002", cid, "poisoned", "MANAGER1")
    vault.legal_hold("1002", False, "AUDITOR1")
    assert vault.forget("1002", "MANAGER1", identity_verified=True)["status"].startswith("erased")


def test_bad_customer_numbers_rejected(vault):
    for bad in ("12", "abcd", "1002; drop", ""):
        with pytest.raises(VaultError):
            vault.pseudonym(bad)


# ---------------------------------------------------------------- HTTP layer
@pytest.fixture
def http(tmp_path):
    ready, holder = threading.Event(), {}

    def serve():
        v = Vault(tmp_path / "http-data", tmp_path / "no-models")
        holder["server"] = HTTPServer(("127.0.0.1", 0), service.make_handler(v, GW, AU))
        ready.set()
        holder["server"].serve_forever()

    threading.Thread(target=serve, daemon=True).start()
    ready.wait(60)
    server = holder["server"]
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def call(method, path, body=None, token=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                                     method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    yield call
    server.shutdown()


def test_http_tokens_and_roles(http):
    body = {"customer": "1002", "fields": FIELDS, "source": "doc", "requested_by": "CLERK1"}
    assert http("POST", "/v1/copies", body)[0] == 401
    assert http("POST", "/v1/copies", body, token="x" * 40)[0] == 401
    assert http("POST", "/v1/copies", body, token=AU)[0] == 403          # auditor token cannot store
    status, out = http("POST", "/v1/copies", body, token=GW)
    assert status == 200 and "text" not in out
    assert http("POST", "/v1/customers/1002/hold", {"on": True, "requested_by": "AUDITOR1"}, token=GW)[0] == 403
    assert http("POST", "/v1/customers/1002/hold", {"on": True, "requested_by": "AUDITOR1"}, token=AU)[0] == 200
    status, out = http("POST", "/v1/customers/1002/forget", {"requested_by": "MANAGER1", "identity_verified": True},
                       token=GW)
    assert status == 200 and out["status"] == "refused_legal_hold"
    assert http("GET", "/v1/customers/1002/copies", token=GW)[1]["legal_hold"] is True
    assert http("GET", "/v1/public")[1]["signature_algorithm"] == "ML-DSA-65"
    assert http("GET", "/nope")[0] == 404
    assert http("POST", "/v1/copies", {**body, "requested_by": "<script>"}, token=GW)[0] == 400
