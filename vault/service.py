"""
service.py - the ZVault vault as a small local-only service.

The AI gateway sends it AI copies (today: verified loan-document summaries) to keep
encrypted under each customer's own quantum-safe key, and asks it to forget a customer or
remove one poisoned copy. The gateway can STORE, but it can never READ a copy back and never
holds a key. The vault has no Db2 access and no network access beyond 127.0.0.1.

    python3 service.py            # serves on 127.0.0.1:8090 (VAULT_BIND, VAULT_PORT)

Environment:
    VAULT_GATEWAY_TOKEN   32+ chars: store, list, forget, remove        (the gateway has this)
    VAULT_AUDITOR_TOKEN   32+ chars: legal hold                         (only the auditor has this)
    VAULT_DATA            key store, encrypted copies, signer, transparency log (default /data)
    VAULT_MODELS          retention model folder (default ./models)

Customer numbers never appear in the vault's files: each one is turned into a pseudonym with
a secret key (HMAC-SHA256), so the vault's database alone does not say whose copies it holds.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from zvault_vault.attacks import CandidateInverter
from zvault_vault.certs import CertificateSigner, verify_certificate
from zvault_vault.crypto import ossl
from zvault_vault.data import generate_bank
from zvault_vault.embeddings import HashingEmbedder
from zvault_vault.erasure import ErasureEngine, ErasureRefused
from zvault_vault.keys import KeyDestroyedError, KeyServiceError, KeyState, SoftHSM
from zvault_vault.retention import RetentionModel, RetentionScheduler
from zvault_vault.store import CopyShreddedError, EncryptedStore
from zvault_vault.tlog import TransparencyLog, verify_inclusion, verify_tree_head

DAY = 86400
MAX_BODY = 64 * 1024
MAX_TEXT = 2000
COPY_KIND = "agent-memory"          # an AI-derived note about the customer
REMOVAL_REASONS = {"poisoned", "wrong_customer", "duplicate"}
CUSTOMER = re.compile(r"^\d{4}$")
COPY_ID = re.compile(r"^[a-z-]{1,20}-[0-9a-f]{12}$")
KEY_DESCRIPTION = "customer key (AES-256) wrapped by hybrid ML-KEM-768 + X25519 root key"


class VaultError(Exception):
    status = 400


class NotFound(VaultError):
    status = 404


class Refused(VaultError):
    status = 409


def _summary_corpus(first: int, count: int, seed: int) -> list[str]:
    """Plausible loan summaries of people who are NOT our customers (numbers outside the bank's
    range), all synthetic. Used as the attacker's dictionary for the inversion test and as the
    non-member reference for the membership test, so both are calibrated on look-alike text."""
    import random

    rng = random.Random(seed)
    purposes = ["Home loan - purchase of a flat", "Car loan", "Personal loan", "Education loan",
                "Home loan - construction", "Business loan"]
    return [summary_text({
        "applicant_reference": f"Customer {n}", "loan_amount": f"Rs {rng.choice([5, 8, 12, 18, 25, 40, 60])} lakh",
        "purpose": rng.choice(purposes), "tenure": f"{rng.choice([3, 5, 7, 10, 15, 20, 25])} years",
        "monthly_income": f"Rs {rng.choice([0.4, 0.6, 0.8, 1.2, 1.5, 2.5])} lakh"})
        for n in range(first, first + count)]


def summary_text(fields: dict) -> str:
    labels = [("applicant_reference", "Applicant reference"), ("loan_amount", "Loan amount"),
              ("purpose", "Purpose"), ("tenure", "Tenure"), ("monthly_income", "Monthly income stated")]
    parts = [f"{label}: {fields[name]}" for name, label in labels if fields.get(name)]
    return "Loan document summary. " + ". ".join(parts) + "."


def load_model(folder: Path):
    """The retention model, only if its fingerprint matches AND it was trained with this scikit-learn."""
    import sklearn

    pkl, digest, info = folder / "qshelf.pkl", folder / "qshelf.pkl.sha256", folder / "qshelf.json"
    if not (pkl.exists() and digest.exists() and info.exists()):
        return None, "no model (run train_qshelf.py)"
    meta = json.loads(info.read_text())
    if meta.get("versions", {}).get("scikit_learn") != sklearn.__version__:
        return None, f"model trained with scikit-learn {meta['versions'].get('scikit_learn')}, not {sklearn.__version__}"
    if hashlib.sha256(pkl.read_bytes()).hexdigest() != digest.read_text().split()[0]:
        return None, "model fingerprint mismatch: not loaded"
    return RetentionModel.load(pkl), f"{RetentionModel.version} sha256 {meta['sha256'][:16]}"


class SummaryErasureEngine(ErasureEngine):
    """Membership test calibrated for templated AI summaries.

    Loan summaries share one template, so a customer's summary looks like other customers'
    summaries that legitimately stay in the index. The fair question is: does the index still
    favour THIS customer over a look-alike stranger? So the non-member reference is the
    customer's own texts with the customer number swapped for numbers the bank never issued.
    Before erasure the customer's own vectors are present (detected); after erasure the
    customer scores like a stranger (not detected)."""

    def _membership(self, texts):
        import random

        import numpy as np

        from zvault_vault import attacks

        rng = random.Random(len(texts))
        index = self.readable_index()
        member = attacks.membership_scores(self.embedder, index, list(texts))
        lookalikes = [re.sub(r"Customer \d{4}", f"Customer {rng.randint(9000, 9999)}", t)
                      for t in texts for _ in range(1000)]
        reference = attacks.membership_scores(self.embedder, index, lookalikes)
        # Stricter than a 95% cut-off: the customer must beat EVERY look-alike stranger.
        threshold = float(np.max(reference)) if len(reference) else 1.0
        flagged = float((member > threshold + 1e-6).mean()) if len(member) else 0.0
        return {"messages_probed": int(len(member)), "share_flagged": round(flagged, 3),
                "threshold_best_lookalike": round(threshold, 3), "lookalikes_per_message": 1000,
                "detected": flagged > 0.5}


class Vault:
    def __init__(self, data_dir, model_dir, clock=time.time):
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        self._clock = clock
        self.hsm = SoftHSM(self.dir / "hsm", clock=clock)
        self.store = EncryptedStore(self.dir / "copies.db", self.hsm)
        self.signer = CertificateSigner(self.dir / "signer")
        self.log = TransparencyLog(self.dir / "tlog.db", self.signer)
        self.embedder = HashingEmbedder()
        corpus = [m.text for m in generate_bank(80, seed=99, prefix="AUX").messages] + _summary_corpus(5000, 300, 1)
        probes = [m.text for m in generate_bank(40, seed=123, prefix="NON").messages] + _summary_corpus(6000, 120, 2)
        self.engine = SummaryErasureEngine(self.hsm, self.store, self.signer, self.log, self.embedder,
                                    CandidateInverter(self.embedder, corpus), [self.dir], probes, clock=clock)
        self.model, self.model_info = load_model(Path(model_dir))
        self._pepper = self._load_pepper()

    # ---- helpers ----------------------------------------------------------------------------
    def _load_pepper(self) -> bytes:
        path = self.dir / "pseudonym.key"
        if not path.exists():
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(secrets.token_bytes(32))
        return path.read_bytes()

    def pseudonym(self, number: str) -> str:
        if not CUSTOMER.match(str(number)):
            raise VaultError("customer must be a 4-digit number")
        return "C-" + hmac.new(self._pepper, str(number).encode(), hashlib.sha256).hexdigest()[:16]

    def _key_state(self, cid: str):
        try:
            return self.hsm.info(cid)
        except KeyServiceError:
            return None

    def _proofs(self, out: dict) -> dict:
        cert, head = out["certificate"], out["tree_head"]
        return {
            "signature_valid": verify_certificate(cert, self.signer.public_der),
            "tree_head_valid": verify_tree_head(head, self.signer.public_der),
            "in_transparency_log": verify_inclusion(self.log.entry(out["log_index"]), out["log_index"], head.size,
                                                    out["inclusion_proof"], head.root),
            "log_index": out["log_index"], "log_size": head.size, "log_root": head.root.hex(),
            "signature_algorithm": cert["signature"]["algorithm"], "signer_key_id": cert["signature"]["key_id"],
        }

    def _publish(self, record: dict) -> dict:
        signed = self.signer.sign(record)
        index = self.log.append(signed)
        out = {"certificate": signed, "log_index": index, "tree_head": self.log.tree_head(),
               "inclusion_proof": self.log.inclusion_proof(index)}
        return {"certificate": signed, "proofs": self._proofs(out)}

    # ---- operations -------------------------------------------------------------------------
    def store_copy(self, number: str, fields: dict, source: str, requested_by: str) -> dict:
        cid = self.pseudonym(number)
        text = summary_text({k: str(v)[:80] for k, v in (fields or {}).items() if v})
        if len(text) > MAX_TEXT:
            raise VaultError("summary too long")
        info = self._key_state(cid)
        if info is None:
            self.hsm.create_customer_key(cid)
        elif info.state is KeyState.DESTROYED:
            raise Refused("this customer's AI data was erased; new copies are not accepted")
        elif info.state is not KeyState.ACTIVE:
            raise Refused(f"customer key is {info.state.value}")
        now = self._clock()
        with self.hsm.lease(cid, purpose=f"store AI copy ({source[:40]}) for {requested_by}") as lease:
            copy_id = self.store.put_text(lease, COPY_KIND, text, created_at=now)
            self.store.put_vector(lease, self.embedder.encode([text])[0], source_copy_id=copy_id, created_at=now)
        if self.model is not None:
            p = self.model.predict([text], [COPY_KIND])[0]
            cls, days, review = str(p.retention_class), int(p.days), bool(p.needs_review)
        else:   # no trusted model: keep for the longest period and ask a person
            cls, days, review = "contract", 20 * 365, True
        until = now + days * DAY
        self.store.registry.set_retention(copy_id, cls, until)
        if emb := self.store.registry.embedding_of(copy_id):
            self.store.registry.set_retention(emb.copy_id, cls, until)
        return {"copy_id": copy_id, "retention_class": cls, "retention_days": days, "needs_review": review,
                "retention_until": until, "encryption": "AES-256-GCM (CPACF on IBM Z)", "key": KEY_DESCRIPTION}

    def list_copies(self, number: str) -> dict:
        cid = self.pseudonym(number)
        info = self._key_state(cid)
        copies = []
        for r in self.store.registry.for_customer(cid):
            if r.kind == "embedding":
                continue
            status = ("erased" if info and info.state is KeyState.DESTROYED
                      else "removed" if self.store.is_shredded(r.copy_id) else "encrypted")
            copies.append({"copy_id": r.copy_id, "kind": "AI summary (loan document)" if r.kind == COPY_KIND
                           else r.kind, "created_at": r.created_at, "retention_class": r.retention_class,
                           "retention_until": r.retention_until, "status": status})
        return {"customer": number, "key_state": info.state.value if info else "NONE",
                "legal_hold": bool(info and info.legal_hold), "copies": copies, "key": KEY_DESCRIPTION}

    def forget(self, number: str, requested_by: str, identity_verified: bool) -> dict:
        cid = self.pseudonym(number)
        info = self._key_state(cid)
        if info is None:
            raise NotFound("ZVault holds no AI copies for this customer")
        if info.state is KeyState.DESTROYED:
            raise Refused("this customer was already erased")
        try:
            out = self.engine.erase(cid, identity_verified, identifiers=[f"Customer {number}"])
        except ErasureRefused as exc:
            raise VaultError(str(exc)) from None
        cert = out["certificate"]
        result = {"request_id": cert["request_id"], "status": cert["status"], "requested_by": requested_by,
                  "reason": cert.get("reason"), "certificate": cert, "proofs": self._proofs(out)}
        if cert["status"] != "refused_legal_hold":
            rt = cert["recovery_test"]
            result["summary"] = {
                "copies_erased": sum(c["result"] == "erased" for c in cert["copies"]),
                "copies_failed": sum(c["result"] == "failed" for c in cert["copies"]),
                "not_verifiable": [c["location"] for c in cert["copies"] if c["result"] == "not_verifiable"],
                "key_state": cert["key"]["state"],
                "inversion_f1_before": rt["inversion"]["before_erasure"]["mean_token_f1"],
                "inversion_f1_after": rt["inversion"]["after_erasure"]["mean_token_f1"],
                "noise_baseline_f1": rt["inversion"]["after_erasure"]["random_noise_baseline"]["mean_token_f1"],
                "identifiers_recovered": rt["inversion"]["after_erasure"]["identifiers_recovered"],
                "customer_detected_before": rt["membership_inference"]["before_erasure"]["detected"],
                "customer_detected_after": rt["membership_inference"]["after_erasure"]["detected"],
                "residue_files_scanned": rt["residue_scan"]["files_scanned"],
                "residue_leaks": len(rt["residue_scan"]["hits"]),
            }
        return result

    def remove_copy(self, number: str, copy_id: str, reason: str, requested_by: str) -> dict:
        """Remove ONE copy (e.g. a poisoned AI note) and publish a signed removal record."""
        cid = self.pseudonym(number)
        if reason not in REMOVAL_REASONS:
            raise VaultError(f"reason must be one of {sorted(REMOVAL_REASONS)}")
        if not COPY_ID.match(copy_id or ""):
            raise VaultError("bad copy id")
        try:
            rec = self.store.registry.get(copy_id)
        except KeyError:
            raise NotFound("no such copy for this customer") from None
        if rec.customer_id != cid or rec.kind == "embedding":
            raise NotFound("no such copy for this customer")
        info = self._key_state(cid)
        if info and info.legal_hold:
            raise Refused("this customer is under legal hold; copies cannot be removed")
        if self.store.is_shredded(copy_id) or (info and info.state is KeyState.DESTROYED):
            raise Refused("this copy is already unreadable")
        removed = [copy_id]
        self.store.shred(copy_id)
        if emb := self.store.registry.embedding_of(copy_id):
            self.store.shred(emb.copy_id)
            removed.append(emb.copy_id)
        checks = []
        for c in removed:                     # recovery test: try to read what was removed
            try:
                with self.hsm.lease(cid, purpose=f"removal check {copy_id}") as lease:
                    self.store.get(lease, c)
                checks.append({"copy_id": c, "result": "failed", "evidence": "copy could still be decrypted"})
            except (CopyShreddedError, KeyDestroyedError):
                checks.append({"copy_id": c, "result": "unreadable", "evidence": "data key destroyed; decrypt refused"})
        out = self._publish({
            "type": "zvault.copy-removal/v1", "request_id": f"RM-{secrets.token_hex(5).upper()}",
            "customer_id": cid, "reason": reason, "requested_by": requested_by, "removed_at": self._clock(),
            "copies": checks, "other_copies_of_customer": "untouched",
            "status": "removed" if all(c["result"] == "unreadable" for c in checks) else "failed"})
        return {"request_id": out["certificate"]["request_id"], "status": out["certificate"]["status"],
                "copies": checks, "certificate": out["certificate"], "proofs": out["proofs"]}

    def legal_hold(self, number: str, on: bool, requested_by: str) -> dict:
        cid = self.pseudonym(number)
        if self._key_state(cid) is None:
            self.hsm.create_customer_key(cid)     # so the hold also covers copies stored later
        info = self.hsm.set_legal_hold(cid, bool(on))
        out = self._publish({"type": "zvault.legal-hold/v1", "request_id": f"LH-{secrets.token_hex(5).upper()}",
                             "customer_id": cid, "legal_hold": info.legal_hold, "requested_by": requested_by,
                             "at": self._clock()})
        return {"customer": number, "legal_hold": info.legal_hold, "proofs": out["proofs"]}

    def retention_run(self) -> dict:
        if self.model is None:
            return {"skipped": True, "reason": self.model_info}
        report = RetentionScheduler(self.store, self.hsm, self.model, self.signer, self.log,
                                    clock=self._clock).run()
        return {"shredded": len(report["shredded"]), "kept_for_legal_hold": len(report["kept_for_legal_hold"]),
                "log_index": report.get("log_index")}

    def public_info(self) -> dict:
        head = self.log.tree_head()
        return {"signature_algorithm": "ML-DSA-65", "signer_key_id": self.signer.key_id,
                "public_key_der_b64": base64.b64encode(self.signer.public_der).decode(),
                "log_size": head.size, "log_root": head.root.hex(),
                "tree_head_signature_b64": base64.b64encode(head.signature).decode()}


# ---------------------------------------------------------------- HTTP
def _json_default(o):
    if isinstance(o, (bytes, bytearray)):
        return o.hex()
    if hasattr(o, "to_dict"):
        return o.to_dict()
    return str(o)


def make_handler(vault: Vault, gateway_token: str, auditor_token: str):
    routes = [
        ("POST", re.compile(r"^/v1/copies$"), "gateway", "store"),
        ("GET", re.compile(r"^/v1/customers/(\d{4})/copies$"), "gateway", "list"),
        ("POST", re.compile(r"^/v1/customers/(\d{4})/forget$"), "gateway", "forget"),
        ("POST", re.compile(r"^/v1/customers/(\d{4})/copies/([a-z0-9-]{1,40})/remove$"), "gateway", "remove"),
        ("POST", re.compile(r"^/v1/customers/(\d{4})/hold$"), "auditor", "hold"),
        ("GET", re.compile(r"^/v1/public$"), None, "public"),
        ("GET", re.compile(r"^/health$"), None, "health"),
    ]

    class Handler(BaseHTTPRequestHandler):
        server_version = "zvault-vault"
        sys_version = ""

        def log_message(self, fmt, *args):   # method, path and status only; never bodies
            sys.stderr.write(f"{self.command} {self.path.split('?')[0]} -> {args[1] if len(args) > 1 else ''}\n")

        def _send(self, status: int, body: dict):
            data = json.dumps(body, default=_json_default).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _role(self):
            auth = self.headers.get("Authorization", "")
            token = auth[7:] if auth.startswith("Bearer ") else ""
            if token and hmac.compare_digest(token, gateway_token):
                return "gateway"
            if token and hmac.compare_digest(token, auditor_token):
                return "auditor"
            return None

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                raise VaultError("request too large")
            data = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(data, dict):
                raise VaultError("JSON object expected")
            return data

        def _dispatch(self, method: str):
            path = self.path.split("?")[0]
            for m, pattern, need, name in routes:
                match = pattern.match(path)
                if m != method or not match:
                    continue
                if need:
                    role = self._role()
                    if role is None:
                        return self._send(401, {"detail": "missing or wrong token"})
                    if role != need:
                        return self._send(403, {"detail": f"needs the {need} token"})
                try:
                    return self._send(200, self._run(name, match.groups()))
                except VaultError as exc:
                    return self._send(exc.status, {"detail": str(exc)})
                except (ValueError, json.JSONDecodeError):
                    return self._send(400, {"detail": "bad request"})
                except Exception as exc:  # noqa: BLE001 - never leak internals
                    sys.stderr.write(f"ERROR {name}: {type(exc).__name__}\n")
                    return self._send(500, {"detail": "vault error"})
            return self._send(404, {"detail": "not found"})

        def _run(self, name, groups):
            body = self._body() if self.command == "POST" else {}
            by = str(body.get("requested_by", ""))[:30]
            if name in ("store", "forget", "remove", "hold") and not re.match(r"^[A-Z0-9_]{1,30}$", by):
                raise VaultError("requested_by must be an employee id")
            if name == "store":
                return vault.store_copy(str(body.get("customer", "")), body.get("fields") or {},
                                        str(body.get("source", ""))[:80], by)
            if name == "list":
                return vault.list_copies(groups[0])
            if name == "forget":
                return vault.forget(groups[0], by, body.get("identity_verified") is True)
            if name == "remove":
                return vault.remove_copy(groups[0], groups[1], str(body.get("reason", "")), by)
            if name == "hold":
                return vault.legal_hold(groups[0], body.get("on") is True, by)
            if name == "public":
                return vault.public_info()
            return {"status": "ok", "openssl": ossl.version(), "model": vault.model_info,
                    "key_backend": vault.hsm.backend_label}

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

    return Handler


def tokens() -> tuple[str, str]:
    gw, au = os.environ.get("VAULT_GATEWAY_TOKEN", ""), os.environ.get("VAULT_AUDITOR_TOKEN", "")
    if len(gw) < 32 or len(au) < 32 or gw == au:
        sys.exit("VAULT_GATEWAY_TOKEN and VAULT_AUDITOR_TOKEN must be set, 32+ characters, and different")
    return gw, au


def main():
    gw, au = tokens()
    here = Path(__file__).resolve().parent
    vault = Vault(os.getenv("VAULT_DATA", "/data"), os.getenv("VAULT_MODELS", str(here / "models")))
    bind, port = os.getenv("VAULT_BIND", "127.0.0.1"), int(os.getenv("VAULT_PORT", "8090"))
    print(f"ZVault vault on {bind}:{port} | {ossl.version()} | model: {vault.model_info}", flush=True)
    HTTPServer((bind, port), make_handler(vault, gw, au)).serve_forever()


if __name__ == "__main__":
    main()
