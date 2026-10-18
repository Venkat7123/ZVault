"""Feature 1: forget on request.

    confirm identity ─► legal-hold check ─► baseline attack (inside the enclave)
      ─► customer key ACTIVE → PENDING_DESTRUCTION → DESTROYED
      ─► recovery test on what is left ─► honest certificate ─► ML-DSA sign ─► transparency log

The baseline runs the same attacks while the data is still readable, so the
certificate shows the attacks work on this data and then fail after erasure.
"""

import secrets
import time
from pathlib import Path
from typing import Callable

import numpy as np

from . import attacks
from .certs import CERT_TYPE, CertificateSigner
from .embeddings import CachedEmbedder, from_bytes
from .keys import KeyDestroyedError, KeyServiceError, KeyState, SoftHSM
from .store import LOCATION, EncryptedStore
from .tlog import TransparencyLog

TEXT_KINDS = ("chat", "agent-memory", "transaction")
BACKUP_NOTE = ("No backups are configured in this demo. In production, key-store backups are encrypted under "
               "per-epoch backup keys that are destroyed when backup retention ends, so a destroyed customer key "
               "becomes unreadable in backups at the end of that window.")


class ErasureRefused(Exception):
    pass


class ErasureEngine:
    def __init__(self, keys: SoftHSM, store: EncryptedStore, signer: CertificateSigner, log: TransparencyLog,
                 embedder, inverter, data_paths: list, probe_texts: list[str],
                 clock: Callable[[], float] = time.time):
        self.keys, self.store, self.signer, self.log = keys, store, signer, log
        self.embedder, self.inverter = CachedEmbedder(embedder), inverter
        self.data_paths = [Path(p) for p in data_paths]
        self.probe_texts = probe_texts  # messages of people who were never customers (membership baseline)
        self._clock = clock

    # --- helpers --------------------------------------------------------------------------

    def readable_index(self) -> np.ndarray:
        """Every vector the live assistant could still retrieve (customers with an active key)."""
        vectors = []
        for customer_id in self.keys.customers():
            if self.keys.info(customer_id).state is not KeyState.ACTIVE:
                continue
            with self.keys.lease(customer_id, purpose="recovery test: attacker's view of the live index") as lease:
                for r in self.store.registry.for_customer(customer_id):
                    if r.kind == "embedding" and not self.store.is_shredded(r.copy_id):
                        vectors.append(self.store.get_vector(lease, r.copy_id))
        return np.array(vectors) if vectors else np.zeros((0, self.embedder.dim))

    def _membership(self, texts: list[str]) -> dict:
        """Can an attacker tell this customer's specific messages are still in the live index?

        Only messages with a person-specific number (amount, account) are probed: generic
        ones like "Show my balance please." are shared by many people and say nothing
        about one customer. The threshold is set so 5% of non-members would be flagged;
        the customer counts as detected when most of their messages exceed it.
        """
        index = self.readable_index()
        member = attacks.membership_scores(self.embedder, index, attacks.specific_texts(texts))
        reference = attacks.membership_scores(self.embedder, index, attacks.specific_texts(self.probe_texts))
        threshold = float(np.quantile(reference, 0.95)) if len(reference) else 1.0
        flagged = float((member > threshold).mean()) if len(member) else 0.0
        return {
            "messages_probed": int(len(member)),
            "share_flagged": round(flagged, 3),
            "threshold_95pct_non_members": round(threshold, 3),
            "detected": flagged > 0.5,
        }

    # --- the flow ---------------------------------------------------------------------------

    def erase(self, customer_id: str, identity_verified: bool, identifiers: list[str]) -> dict:
        request_id = f"ER-{secrets.token_hex(5).upper()}"
        requested_at = self._clock()
        if not identity_verified:
            raise ErasureRefused("identity not confirmed; no key was touched")

        info = self.keys.info(customer_id)
        records = self.store.registry.for_customer(customer_id)
        base = {
            "type": CERT_TYPE, "request_id": request_id, "customer_id": customer_id,
            "requested_at": requested_at,
            "identity_check": {"method": "IBM Verify MFA + liveness partner (stubbed in demo)", "passed": True},
            "legal_hold_check": {"on_hold": info.legal_hold},
        }
        if info.legal_hold:
            refusal = self.signer.sign({**base, "status": "refused_legal_hold",
                                        "reason": "An open investigation requires these records to be kept (PMLA). "
                                                  "Erasure will be possible when the hold is lifted."})
            return self._publish(refusal)

        # 1. Baseline inside the enclave, while the copies are still readable.
        texts, vectors = {}, {}
        with self.keys.lease(customer_id, purpose=f"erasure baseline {request_id}") as lease:
            for r in records:
                if r.location != LOCATION or self.store.is_shredded(r.copy_id):
                    continue
                if r.kind in TEXT_KINDS:
                    texts[r.copy_id] = self.store.get_text(lease, r.copy_id)
                elif r.kind == "embedding":
                    vectors[r.copy_id] = self.store.get_vector(lease, r.copy_id)
        sources = {r.copy_id: r.source_copy_id for r in records}
        pair_ids = [c for c in vectors if sources.get(c) in texts]
        truths = [texts[sources[c]] for c in pair_ids]
        before_inversion = attacks.inversion_result(
            self.inverter, np.array([vectors[c] for c in pair_ids]), truths, identifiers)
        before_membership = self._membership(list(texts.values()))

        # 2. Destroy the customer's key.
        self.keys.schedule_destruction(customer_id, delay_seconds=0)
        self.keys.destroy_due()
        key_info = self.keys.info(customer_id)

        # 3. Recovery test on what is left.
        copies = []
        for r in records:
            if r.location != LOCATION:
                copies.append({"copy_id": r.copy_id, "kind": r.kind, "location": r.location,
                               "result": "not_verifiable",
                               "evidence": "copy left ZVault's control; it cannot be checked or erased from here"})
                continue
            try:
                with self.keys.lease(customer_id, purpose=f"recovery test {request_id}") as lease:
                    self.store.get(lease, r.copy_id)
                result, evidence = "failed", "copy could still be decrypted"
            except KeyDestroyedError:
                result, evidence = "erased", "customer key destroyed; decrypt attempt refused"
            except KeyServiceError as e:
                result, evidence = "failed", f"unexpected key state: {e}"
            copies.append({"copy_id": r.copy_id, "kind": r.kind, "location": r.location,
                           "result": result, "evidence": evidence})

        # The attacker copies the disk and reads each stored embedding as if it were a vector.
        sealed = [self.store.sealed(c)["ciphertext"] for c in pair_ids]
        stolen = np.array([np.resize(from_bytes(s), self.embedder.dim) for s in sealed])
        after_inversion = attacks.inversion_result(self.inverter, stolen, truths, identifiers)
        after_inversion["random_noise_baseline"] = attacks.noise_baseline(
            self.inverter, len(sealed), len(sealed[0]) if sealed else 0, self.embedder.dim, truths)
        after_membership = self._membership(list(texts.values()))
        residue = attacks.residue_scan(self.data_paths, identifiers + [t for t in texts.values() if len(t) >= 40])
        texts.clear()
        vectors.clear()

        for hit in residue["hits"]:
            copies.append({"copy_id": None, "kind": "residue", "location": hit["file"], "result": "failed",
                           "evidence": "customer data found in readable form"})
        copies.append({"copy_id": None, "kind": "backups", "location": "backups", "result": "not_verifiable",
                       "evidence": BACKUP_NOTE})

        # Pass/fail rests on what an attacker could actually learn: any identifier. The token
        # F1 is reported next to the random-noise baseline for context, not used as a cut-off,
        # because an attack on ciphertext is itself a random draw.
        inversion_ok = not after_inversion["identifiers_recovered"]
        if any(c["result"] == "failed" for c in copies) or not inversion_ok or after_membership["detected"]:
            status = "failed"
        elif any(c["result"] == "not_verifiable" for c in copies):
            status = "erased_with_exceptions"
        else:
            status = "erased"

        certificate = self.signer.sign({
            **base,
            "status": status,
            "completed_at": self._clock(),
            "key": {"backend": self.keys.backend_label, "state": key_info.state.value,
                    "destroyed_at": key_info.destroyed_at},
            "copies": copies,
            "recovery_test": {
                "inversion": {"before_erasure": before_inversion, "after_erasure": after_inversion,
                              "pass_rule": "no identifier recovered after erasure; token F1 is compared with the "
                                           "same attack on random noise"},
                "membership_inference": {"before_erasure": before_membership, "after_erasure": after_membership},
                "residue_scan": residue,
            },
        })
        return self._publish(certificate)

    def _publish(self, certificate: dict) -> dict:
        index = self.log.append(certificate)
        head = self.log.tree_head()
        return {"certificate": certificate, "log_index": index, "tree_head": head,
                "inclusion_proof": self.log.inclusion_proof(index)}
