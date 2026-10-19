"""
test_privacy.py - Phase C end to end: the REAL vault service (OpenSSL 3.5) + the real gateway code,
with Db2 and Granite replaced by stand-ins.

  * a clean loan document is saved to the vault, only for a customer Db2 lets the clerk see
  * managers (only) can view what is held, forget a customer, remove one poisoned copy
  * legal hold (auditor token only) blocks erasure; the gateway never has that token

Needs fastapi, httpx, pyjwt, pypdf, python-multipart, numpy, scikit-learn and OpenSSL 3.5
(set ZVAULT_LIBCRYPTO if the system OpenSSL is older). Run from the project folder:
    python tests/test_privacy.py
"""
import json
import os
import sys
import tempfile
import threading
import types
import urllib.request
from http.server import HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests"), str(ROOT / "vault")]
GW_TOKEN, AUD_TOKEN = "g" * 40, "a" * 40
os.environ.update(JWT_SECRET="x" * 40, DEMO_PASSWORD="demo", VAULT_TOKEN=GW_TOKEN)
sys.modules.setdefault("ibm_db", types.ModuleType("ibm_db"))

# ---- the real vault service on a free local port (built inside its own thread: SQLite) ----
import service  # noqa: E402

ready, holder = threading.Event(), {}


def serve():
    vault = service.Vault(Path(tempfile.mkdtemp()) / "data", ROOT / "vault" / "no-models")
    holder["server"] = HTTPServer(("127.0.0.1", 0), service.make_handler(vault, GW_TOKEN, AUD_TOKEN))
    ready.set()
    holder["server"].serve_forever()


threading.Thread(target=serve, daemon=True).start()
ready.wait(60)
VAULT = f"http://127.0.0.1:{holder['server'].server_address[1]}"
os.environ["VAULT_URL"] = VAULT

from fastapi.testclient import TestClient  # noqa: E402

import make_demo_pdfs as demo  # noqa: E402
from botsbank import db, llm, main, vault_client  # noqa: E402

vault_client.VAULT_URL = VAULT
failures = []


def check(name, ok, detail=""):
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail)
    if not ok:
        failures.append(name)


# ---- stand-ins: Db2 row rules (own branch only) and Granite ----
VISIBLE = {"CLERK1": {"1001", "1002", "1003"}, "MANAGER1": {"1001", "1002", "1003"}, "CLERK2": {"2001", "2002"}}
logs = []
db.write_log = lambda *a, **k: logs.append(a)


def run_as(user, sql, params=()):
    cust = str(params[0]) if params else ""
    return [{"CUST_ID": int(cust), "BRANCH_ID": "CHN01"}] if cust in VISIBLE.get(user, set()) else []


db.run_as = run_as
llm.doc_injection_check = lambda text: True


def fake_fields(text):
    ref = "Customer 2001" if "Customer 2001" in text else "Customer 1003" if "Customer 1003" in text else "Customer 1002"
    return {"applicant_reference": ref, "loan_amount": "Rs 25 lakh", "purpose": "Home loan - purchase of a flat",
            "tenure": "20 years", "monthly_income": "Rs 1.2 lakh"}


llm.extract_fields = fake_fields
client = TestClient(main.app)


def token(user):
    return {"Authorization": "Bearer " + client.post("/login", json={"user_id": user, "password": "demo"}).json()["token"]}


def pdf_for(cust: str) -> bytes:
    return demo.DOCS["1_clean.pdf"].replace(b"Customer 1002", f"Customer {cust}".encode())


def upload(user, data):
    return client.post("/documents/scan", files={"file": ("loan.pdf", data, "application/pdf")}, headers=token(user))


CLERK, MANAGER, CLERK2 = "CLERK1", "MANAGER1", "CLERK2"

# ---- 1. save after a clean scan ----
r = upload(CLERK, pdf_for("1002")).json()
st = r.get("stored", {})
check("clean doc saved to the vault", r["verdict"] == "CLEAN" and st.get("saved") is True
      and st.get("customer") == "1002" and st.get("copy_id", "").startswith("agent-memory-"), st)
check("saved under a quantum-safe customer key", "ML-KEM-768" in st.get("key", ""), st)
check("store logged ALLOW", logs[-1][1:3] == ("vault_store", "ALLOW") and "customer 1002" in logs[-1][4], logs[-1])
first_copy = st.get("copy_id")
upload(CLERK, pdf_for("1003"))
main._hits.clear()

r = upload(CLERK, pdf_for("2001")).json()["stored"]
check("other-branch customer NOT saved (Db2 decides)", r["saved"] is False and "allowed to see" in r["reason"], r)
check("refusal logged BLOCK", logs[-1][1:3] == ("vault_store", "BLOCK"), logs[-1])

quarantined = upload(CLERK, demo.DOCS["2_white_text.pdf"]).json()
check("quarantined doc is never saved", "stored" not in quarantined, quarantined.get("stored"))

# ---- 2. managers only ----
check("clerk cannot use privacy actions", client.get("/privacy/customers/1002", headers=token(CLERK)).status_code == 403)
check("a clerk of another branch cannot either",
      client.get("/privacy/customers/2001", headers=token(CLERK2)).status_code == 403)
check("manager cannot see a customer outside his branch",
      client.get("/privacy/customers/2001", headers=token(MANAGER)).status_code == 404)
view = client.get("/privacy/customers/1002", headers=token(MANAGER)).json()
check("manager sees metadata only, no content", view["key_state"] == "ACTIVE" and len(view["copies"]) == 1
      and set(view["copies"][0]) == {"copy_id", "kind", "created_at", "retention_class", "retention_until", "status"},
      view)

# ---- 3. remove one poisoned copy ----
c1003 = client.get("/privacy/customers/1003", headers=token(MANAGER)).json()["copies"][0]["copy_id"]
r = client.post(f"/privacy/customers/1003/copies/{c1003}/remove", json={"reason": "poisoned"}, headers=token(MANAGER))
check("poisoned copy removed with signed record", r.status_code == 200 and r.json()["status"] == "removed"
      and r.json()["proofs"]["signature_valid"] and r.json()["proofs"]["in_transparency_log"], r.text[:300])
r = client.post(f"/privacy/customers/1002/copies/{c1003}/remove", json={"reason": "poisoned"}, headers=token(MANAGER))
check("cannot remove another customer's copy", r.status_code == 404, r.status_code)
r = client.post(f"/privacy/customers/1003/copies/{c1003}/remove", json={"reason": "because"}, headers=token(MANAGER))
check("removal reason must be from the list", r.status_code == 422, r.status_code)

# ---- 4. forget ----
r = client.post("/privacy/customers/1002/forget", json={"identity_verified": True, "confirm": "FORGET 1001"},
                headers=token(MANAGER))
check("wrong confirmation refused", r.status_code == 400)
r = client.post("/privacy/customers/1002/forget", json={"identity_verified": False, "confirm": "FORGET 1002"},
                headers=token(MANAGER))
check("identity check required", r.status_code == 400)
r = client.post("/privacy/customers/1002/forget", json={"identity_verified": True, "confirm": "FORGET 1002"},
                headers=token(MANAGER))
out = r.json()
check("forget -> signed erasure certificate", r.status_code == 200 and out["status"].startswith("erased")
      and out["proofs"]["signature_valid"] and out["proofs"]["in_transparency_log"]
      and out["summary"]["copies_failed"] == 0 and out["summary"]["identifiers_recovered"] == [], r.text[:400])
check("forget logged ALLOW for the alert engine", logs[-1][1:3] == ("vault_forget", "ALLOW"), logs[-1])
view = client.get("/privacy/customers/1002", headers=token(MANAGER)).json()
check("after forget: key destroyed, copy erased", view["key_state"] == "DESTROYED"
      and view["copies"][0]["status"] == "erased", view)
r = upload(CLERK, pdf_for("1002")).json()["stored"]
check("erased customer: new copies refused", r["saved"] is False and "erased" in r["reason"], r)
r = client.post("/privacy/customers/1002/forget", json={"identity_verified": True, "confirm": "FORGET 1002"},
                headers=token(MANAGER))
check("second forget -> 409", r.status_code == 409, r.status_code)

# ---- 5. legal hold: only the auditor's token, never the gateway's ----
req = urllib.request.Request(VAULT + "/v1/customers/1001/hold", method="POST",
                             data=json.dumps({"on": True, "requested_by": "AUDITOR1"}).encode(),
                             headers={"Content-Type": "application/json", "Authorization": f"Bearer {AUD_TOKEN}"})
with urllib.request.urlopen(req) as resp:
    check("auditor sets legal hold", json.load(resp)["legal_hold"] is True)
upload(CLERK, pdf_for("1001"))
r = client.post("/privacy/customers/1001/forget", json={"identity_verified": True, "confirm": "FORGET 1001"},
                headers=token(MANAGER))
check("legal hold -> erasure refused, signed", r.status_code == 200 and r.json()["status"] == "refused_legal_hold"
      and r.json()["proofs"]["signature_valid"], r.text[:300])
check("refusal logged BLOCK", logs[-1][1:3] == ("vault_forget", "BLOCK"), logs[-1])
try:
    vault_client._call("POST", "/v1/customers/1001/hold", {"on": False, "requested_by": "MANAGER1"})
    check("gateway token cannot lift a legal hold", False, "accepted")
except vault_client.VaultUnavailable:
    check("gateway token cannot lift a legal hold", True)

# ---- 6. vault down: the scan still works, nothing is saved ----
vault_client.VAULT_URL = "http://127.0.0.1:9"
main._hits.clear()                      # the per-minute upload limit, not under test here
r = upload(CLERK, pdf_for("1003")).json()
check("vault down -> scan still CLEAN, not saved", r["verdict"] == "CLEAN" and r["stored"]["saved"] is False, r["stored"])

print(f"\n{'ALL PASSED' if not failures else str(len(failures)) + ' FAILED'}")
sys.exit(1 if failures else 0)
