"""
run_demo.py - the ZVault vault demo as a plain script (no Jupyter needed), e.g. on LinuxONE:

    python3 run_demo.py

Uses models/qshelf.pkl if it exists AND matches models/qshelf.pkl.sha256 (train it first with
train_qshelf.py on the same machine); otherwise it trains a demo model in memory and says so.
Writes demo data (including demo key stores) to demo_data/, which is never committed.
"""
import hashlib
import os
import sys
from pathlib import Path

os.chdir(Path(__file__).resolve().parent)


def display(obj):
    print(obj.to_string() if hasattr(obj, "to_string") else obj)


def section(title):
    print("\n" + "=" * 78 + "\n" + title + "\n" + "=" * 78)


section('2. Setup')

import sys, time, shutil, platform, copy
from pathlib import Path
PROJECT = Path.cwd()  # run this notebook from the vault/ folder
sys.path.insert(0, str(PROJECT))

import numpy as np, pandas as pd
from zvault_vault.crypto import ossl, hybrid
from zvault_vault.data import generate_bank, RETENTION_DAYS
from zvault_vault.embeddings import default_embedder
from zvault_vault.keys import SoftHSM, KeyState, KeyDestroyedError, KeyNotActiveError, LegalHoldError
from zvault_vault.store import EncryptedStore
from zvault_vault.ingest import ingest_bank
from zvault_vault.broker import AccessBroker, AccessDenied
from zvault_vault.assistant import AnalystAssistant
from zvault_vault.certs import CertificateSigner, verify_certificate
from zvault_vault.tlog import TransparencyLog, verify_inclusion, verify_tree_head
from zvault_vault.attacks import CandidateInverter, Vec2TextInverter, auc, membership_scores, inversion_result, specific_texts
from zvault_vault.erasure import ErasureEngine
from zvault_vault.retention import RetentionModel, RetentionScheduler, DAY

USE_GTR = os.getenv("USE_GTR", "0") == "1"   # gtr-t5-base needs sentence-transformers
TRY_VEC2TEXT = False

cpacf = "msa" in Path("/proc/cpuinfo").read_text() if Path("/proc/cpuinfo").exists() else False
print("Machine     :", platform.machine())
print("OpenSSL     :", ossl.version())
print("CPACF (AES) :", "present" if cpacf else "not detected (not an IBM Z CPU)")
embedder = default_embedder(prefer_gtr=USE_GTR)
print("Embedder    :", embedder.name)

section('3. Quantum-safe keys')

print("\n--- " + '1. Quantum-vulnerable vs quantum-safe key wrapping')

customer_key = ossl.random_bytes(32)
context = b"kek|CUST-0001|v1"

rsa = ossl.PKey.generate("RSA", rsa_bits=2048)
rsa_blob = ossl.rsa_oaep_encrypt(rsa, customer_key)

root = hybrid.HybridPrivateKey.generate()
pq_blob = hybrid.wrap_key(root.public_key(), customer_key, context)

assert ossl.rsa_oaep_decrypt(rsa, rsa_blob) == customer_key
assert hybrid.unwrap_key(root, pq_blob, context) == customer_key

print(f"{'Wrapping':<34}{'Size':>8}   Recorded today, readable by a future quantum computer?")
print(f"{'RSA-2048 OAEP':<34}{len(rsa_blob):>6} B   YES  (Shor's algorithm breaks RSA)")
print(f"{'Hybrid X25519 + ML-KEM-768':<34}{len(pq_blob):>6} B   NO   (needs ML-KEM-768 broken too)")

print("\n--- " + '2. Customer keys and encrypted AI copies')

DEMO = PROJECT / "demo_data" / "nb01"
shutil.rmtree(DEMO, ignore_errors=True)

hsm = SoftHSM(DEMO / "hsm")
store = EncryptedStore(DEMO / "copies.db", hsm)
print("Key backend:", hsm.backend_label)

for customer in ("CUST-0001", "CUST-0002"):
    hsm.create_customer_key(customer)

with hsm.lease("CUST-0001", purpose="card dispute D-4471") as lease:
    copies_1 = [
        store.put_text(lease, "chat", "I want to apply for a home loan of 50 lakh."),
        store.put_text(lease, "embedding", "[768-dim vector of the home loan chat]"),
        store.put_text(lease, "agent-memory", "Customer disputes card transaction of Rs 18,400 on 12 Oct."),
    ]
    print("CUST-0001 reads back:", store.get_text(lease, copies_1[0]))

with hsm.lease("CUST-0002", purpose="card dispute D-4502") as lease:
    copy_2 = store.put_text(lease, "chat", "Please block my debit card.")

for r in store.registry.for_customer("CUST-0001"):
    print(f"  registered {r.copy_id:<26} kind={r.kind:<13} location={r.location}")

sealed = store.sealed(copies_1[0])
print("What someone who copies the disk gets:")
print("  ciphertext :", sealed["ciphertext"][:32].hex(), "...")
print("  wrapped key:", sealed["wrapped_dek"][:32].hex(), "...")
print("  plaintext visible on disk?", b"home loan" in (DEMO / "copies.db").read_bytes())

print("\n--- " + "3. Forget: destroy one customer's key")

print("Before:", hsm.info("CUST-0001").state.value)
hsm.schedule_destruction("CUST-0001", delay_seconds=0)
print("Pending:", hsm.info("CUST-0001").state.value)
print("Destroyed now:", hsm.destroy_due())
print("After:", hsm.info("CUST-0001").state.value, "| wrapped key still stored:", hsm.wrapped_kek("CUST-0001") is not None)

try:
    hsm.lease("CUST-0001", purpose="card dispute D-4471")
except KeyDestroyedError as e:
    print("Reading CUST-0001's copies ->", type(e).__name__, ":", e)

print("Ciphertext of CUST-0001 still on disk:", all(store.sealed(c)["ciphertext"] for c in copies_1), "(but no key exists to open it)")

with hsm.lease("CUST-0002", purpose="card dispute D-4502") as lease:
    print("CUST-0002 unaffected:", store.get_text(lease, copy_2))

print("\n--- " + '4. Legal hold wins')

hsm.set_legal_hold("CUST-0002", True)
try:
    hsm.schedule_destruction("CUST-0002")
except LegalHoldError as e:
    print("Erasure request ->", type(e).__name__, ":", e)
print("CUST-0002 state:", hsm.info("CUST-0002").state.value)

print("\n--- " + '5. Speed on this machine')

def bench(fn, seconds=1.0):
    n, start = 0, time.perf_counter()
    while time.perf_counter() - start < seconds:
        fn(); n += 1
    return n / (time.perf_counter() - start)

key, mb = ossl.random_bytes(32), ossl.random_bytes(1 << 20)
blob = ossl.aes_gcm_encrypt(key, mb)
mlkem, mldsa = ossl.PKey.generate("ML-KEM-768"), ossl.PKey.generate("ML-DSA-65")
ct, _ = ossl.kem_encapsulate(mlkem)
sig = ossl.sign(mldsa, b"certificate")
pub = root.public_key()
wrapped = hybrid.wrap_key(pub, key, b"ctx")

results = [
    ("AES-256-GCM encrypt 1 MiB", bench(lambda: ossl.aes_gcm_encrypt(key, mb)), "MiB/s"),
    ("AES-256-GCM decrypt 1 MiB", bench(lambda: ossl.aes_gcm_decrypt(key, blob)), "MiB/s"),
    ("ML-KEM-768 encapsulate", bench(lambda: ossl.kem_encapsulate(mlkem)), "ops/s"),
    ("ML-KEM-768 decapsulate", bench(lambda: ossl.kem_decapsulate(mlkem, ct)), "ops/s"),
    ("Hybrid wrap customer key", bench(lambda: hybrid.wrap_key(pub, key, b"ctx")), "ops/s"),
    ("Hybrid unwrap customer key", bench(lambda: hybrid.unwrap_key(root, wrapped, b"ctx")), "ops/s"),
    ("ML-DSA-65 sign", bench(lambda: ossl.sign(mldsa, b"certificate")), "ops/s"),
    ("ML-DSA-65 verify", bench(lambda: ossl.verify(mldsa, b"certificate", sig)), "ops/s"),
    ("RSA-2048 OAEP decrypt (classical)", bench(lambda: ossl.rsa_oaep_decrypt(rsa, rsa_blob)), "ops/s"),
]
print(f"{'Operation':<36}{'Rate':>12}")
for name, rate, unit in results:
    print(f"{name:<36}{rate:>10,.0f} {unit}")

store.close(); hsm.close()

section('4. Synthetic bank data → encrypted AI copies')

DEMO = PROJECT / "demo_data" / "main"
shutil.rmtree(DEMO, ignore_errors=True)
bank = generate_bank(60, seed=7)
df = pd.DataFrame([m.__dict__ for m in bank.messages])
print(len(bank.customers), "customers,", len(df), "messages")
display(df.groupby(["kind", "retention"]).size().unstack(fill_value=0))
display(df.sample(6, random_state=1)[["customer_id", "kind", "retention", "text"]])

NOW = time.time()
hsm = SoftHSM(DEMO / "hsm")
store = EncryptedStore(DEMO / "copies.db", hsm)
t0 = time.perf_counter()
ingest_bank(bank, hsm, store, embedder, now=NOW, verbose=True)
print(f"Stored {len(store.registry.all())} encrypted AI copies (text + embedding) in {time.perf_counter() - t0:.1f} s")
disk = (DEMO / "copies.db").read_bytes()
print("Any customer name or PAN readable on disk?", any(c.name.encode() in disk or c.pan.encode() in disk for c in bank.customers))

section('5. Forget on request')

outsiders = generate_bank(80, seed=99, prefix="AUX")
inverter = CandidateInverter(embedder, [m.text for m in outsiders.messages])
if TRY_VEC2TEXT:
    try:
        inverter = Vec2TextInverter()
    except Exception as e:
        print("vec2text unavailable:", type(e).__name__, "- using dictionary inversion")
print("Inversion attack:", inverter.name)

target = bank.customers[0]
msgs = bank.for_customer(target.customer_id)
plain_vectors = embedder.encode([m.text for m in msgs])   # conventional pipeline: stored in plaintext
soft_deleted = True                                        # "deleted" = a flag; vectors stay on disk
leak = inversion_result(inverter, plain_vectors, [m.text for m in msgs], target.identifiers())
print(f"Conventional pipeline after 'delete': attacker recovers text with token F1 = {leak['mean_token_f1']}")
for m, g in list(zip(msgs, inverter.invert(plain_vectors)))[:3]:
    print("  original :", m.text)
    print("  recovered:", g)

print("\n--- " + '5.2 The analyst assistant, through the broker')

broker = AccessBroker(hsm, DEMO / "broker.db")
broker.register_analyst("A-2291", "Fraud analyst", mfa_verified=True)
case = [bank.customers[0].customer_id, bank.customers[1].customer_id]
broker.open_case("D-4471", "card dispute", case)
assistant = AnalystAssistant(broker, store, embedder)

def show(ans):
    print("Q:", ans.question)
    for score, cust, kind, text in ans.sources:
        print(f"  {score:.2f}  {cust}  [{kind}]  {text}")
    for cust, why in ans.blocked:
        print(f"  BLOCKED {cust}: {why}")

show(assistant.ask("A-2291", "D-4471", "customer disputes a payment they did not make"))
try:
    broker.request("A-2291", "D-4471", bank.customers[5].customer_id)
except AccessDenied as e:
    print("Customer outside the case ->", e)

print("\n--- " + '5.3 The customer taps **Forget me**')

signer = CertificateSigner(DEMO / "enclave")
log = TransparencyLog(DEMO / "tlog.db", signer)
probes = [m.text for m in generate_bank(40, seed=123, prefix="NON").messages]  # people who were never customers
engine = ErasureEngine(hsm, store, signer, log, embedder, inverter, [DEMO], probes)

t0 = time.perf_counter()
out = engine.erase(target.customer_id, identity_verified=True, identifiers=target.identifiers())
cert = out["certificate"]
rt = cert["recovery_test"]
print(f"Erasure {cert['request_id']} for {cert['customer_id']}: {cert['status'].upper()}  ({time.perf_counter() - t0:.1f} s)")
print("Key:", cert["key"]["state"], "|", cert["key"]["backend"])
print(pd.Series([c["result"] for c in cert["copies"]]).value_counts().to_string())
inv, mem = rt["inversion"], rt["membership_inference"]
print(pd.DataFrame({
    "before erasure": [inv["before_erasure"]["mean_token_f1"], "-",
                       mem["before_erasure"]["share_flagged"], mem["before_erasure"]["detected"]],
    "after erasure":  [inv["after_erasure"]["mean_token_f1"],
                       "{mean_token_f1} (95% up to {p95_token_f1})".format(**inv["after_erasure"]["random_noise_baseline"]),
                       mem["after_erasure"]["share_flagged"], mem["after_erasure"]["detected"]],
}, index=["inversion: token F1", "same attack on random noise", "membership: share of messages flagged",
          "membership: customer detected"]).to_string())
print("Identifiers recovered after erasure:", inv["after_erasure"]["identifiers_recovered"] or "none")
print("Residue scan:", rt["residue_scan"]["files_scanned"], "files,", len(rt["residue_scan"]["hits"]), "readable leaks")
print("Not verifiable:", [c["location"] for c in cert["copies"] if c["result"] == "not_verifiable"])

print("\n--- " + '5.4 The analyst asks again')

show(assistant.ask("A-2291", "D-4471", "customer disputes a payment they did not make"))

print("\n--- " + '5.5 Anyone can verify the certificate, without trusting the bank')

head = out["tree_head"]
print("Certificate signature (ML-DSA-65) valid:", verify_certificate(cert, signer.public_der))
print("Signed tree head valid               :", verify_tree_head(head, signer.public_der))
print("Certificate is in the public log     :", verify_inclusion(log.entry(out["log_index"]), out["log_index"], head.size, out["inclusion_proof"], head.root))
forged = copy.deepcopy(cert); forged["status"] = "erased"; forged["copies"] = forged["copies"][:1]
print("Edited certificate still valid?      :", verify_certificate(forged, signer.public_der))
print("Enclave measurement:", cert["enclave"]["measurement_sha3_256"][:24], "...", "|", cert["enclave"]["attestation"])

print("\n--- " + '5.6 Membership inference over a batch of erased customers')

batch = bank.customers[10:15]
members = specific_texts([m.text for c in batch for m in bank.for_customer(c.customer_id)])
non_members = specific_texts(probes)
index = engine.readable_index()
before = auc(membership_scores(embedder, index, members), membership_scores(embedder, index, non_members))
for c in batch:
    engine.erase(c.customer_id, True, c.identifiers())
index = engine.readable_index()
after = auc(membership_scores(embedder, index, members), membership_scores(embedder, index, non_members))
print(f"Membership-inference AUC  before erasure: {before:.2f}   after erasure: {after:.2f}")

print("\n--- " + '5.7 Legal hold: erasure refused, and the customer is told why')

held = bank.customers[2]
hsm.set_legal_hold(held.customer_id, True)
refusal = engine.erase(held.customer_id, True, held.identifiers())["certificate"]
print(refusal["status"], "-", refusal["reason"])
print("Signed:", verify_certificate(refusal, signer.public_der), "| key state:", hsm.info(held.customer_id).state.value)

section('6. Forget on schedule (QShelf)')

from sklearn.metrics import classification_report
train = [m for m in generate_bank(300, seed=11).messages if m.family == "train"]
test = [m for m in generate_bank(300, seed=12).messages if m.family == "test"]
MODEL_FILE = PROJECT / "models" / "qshelf.pkl"
SUM_FILE = PROJECT / "models" / "qshelf.pkl.sha256"
import json, sklearn
INFO_FILE = PROJECT / "models" / "qshelf.json"
trained_with = json.loads(INFO_FILE.read_text())["versions"]["scikit_learn"] if INFO_FILE.exists() else None
if trained_with and trained_with != sklearn.__version__:
    print(f"models/qshelf.pkl was trained with scikit-learn {trained_with}, this machine has "
          f"{sklearn.__version__}: not loading it. Run train_qshelf.py here first.")
if trained_with == sklearn.__version__ and MODEL_FILE.exists() and SUM_FILE.exists() and \
        hashlib.sha256(MODEL_FILE.read_bytes()).hexdigest() == SUM_FILE.read_text().split()[0]:
    model = RetentionModel.load(MODEL_FILE)
    print(f"Using the trained model models/qshelf.pkl (fingerprint checked); testing on {len(test)} unseen phrasings")
else:
    t0 = time.perf_counter()
    model = RetentionModel().fit([m.text for m in train], [m.kind for m in train], [m.retention for m in train])
    print(f"No verified models/qshelf.pkl: trained a demo model on {len(train)} copies in "
          f"{time.perf_counter() - t0:.1f} s; testing on {len(test)} unseen phrasings")
preds = model.predict([m.text for m in test], [m.kind for m in test])
y, p = [m.retention for m in test], [x.retention_class for x in preds]
print(classification_report(y, p, digits=3))
display(pd.crosstab(pd.Series(y, name="true"), pd.Series(p, name="predicted")))
print("Flagged for human review (low confidence, longer class kept):", sum(x.needs_review for x in preds))
too_early = sum(RETENTION_DAYS[q] < RETENTION_DAYS[t] for q, t in zip(p, y))
print("Copies that would be deleted earlier than required:", too_early, "of", len(y))

for text, kind in [("Please block my debit card, I lost it", "chat"),
                   ("I would like to borrow 40 lakh to buy a flat, tenure 20 years.", "chat"),
                   ("mera balance kitna hai?", "chat")]:
    pr = model.predict([text], [kind])[0]
    words = ", ".join(w for w, _ in model.explain(text, kind, top=4))
    print(f"{pr.retention_class:<10} {pr.days:>5} days  conf {pr.confidence:.2f}  because: {words:<45} | {text}")

print("\n--- " + '6.1 The scheduler on the live store, with simulated time')

clock = {"now": NOW}
scheduler = RetentionScheduler(store, hsm, model, signer, log, clock=lambda: clock["now"])
assigned = scheduler.assign()
print("Retention assigned to", len(assigned), "text copies (their embeddings get the same expiry)")
display(pd.Series([a["retention_class"] for a in assigned]).value_counts())

for days in (45, 400, 2000):
    clock["now"] = NOW + days * DAY
    rep = scheduler.run()
    by_class = pd.Series([s["retention_class"] for s in rep["shredded"]]).value_counts().to_dict()
    print(f"+{days:>4} days: shredded {len(rep['shredded']):>3} copies {by_class}  | kept for legal hold: {len(rep['kept_for_legal_hold'])}")
    if "record" in rep:
        assert verify_certificate(rep["record"], signer.public_der)

clock["now"] = NOW
broker.open_case("D-5001", "account review", [bank.customers[3].customer_id])
show(assistant.ask("A-2291", "D-5001", "what did the customer ask about"))
print("(expired copies are shredded and no longer appear)")

section('7. Summary')

head = log.tree_head()
ok = all(verify_inclusion(log.entry(i), i, head.size, log.inclusion_proof(i), head.root) for i in range(head.size))
print(f"Transparency log: {head.size} signed records | tree head valid: {verify_tree_head(head, signer.public_der)} | every inclusion proof valid: {ok}")
print()
print(pd.DataFrame([
    ["AES-256-GCM on CPACF", "real" if cpacf else "real (x86 here)", "OpenSSL 3.5 system library"],
    ["ML-KEM-768 + X25519 hybrid key wrapping", "real", "OpenSSL 3.5"],
    ["ML-DSA-65 certificates and log", "real", "OpenSSL 3.5"],
    ["Crypto Express HSM", "simulated", hsm.backend_label],
    ["IBM Secure Execution attestation", "simulated", "measurement computed in software"],
    ["Embedding model", "real" if "gtr" in embedder.name else "fallback", embedder.name],
    ["Inversion attack", "real", inverter.name],
], columns=["Part", "Status", "Detail"]).to_string(index=False))
store.close(); hsm.close(); broker.close(); log.close()
