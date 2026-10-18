"""Feature 2: forget on schedule (QShelf).

A model reads each AI copy and predicts how long it must be kept:

    short 30 days · service 1 year · regulatory 5 years · contract 20 years

When that time passes, the scheduler shreds the copy (and its embedding), unless the
customer is under legal hold. Uncertain predictions are never shortened: the longer of
the two most likely classes is used and the copy is flagged for human review, because
deleting too early can break record-keeping law while keeping too long breaks DPDP.

Prior art: Wells Fargo patent US 11,240,014 B1 assigns a per-data "security shelf-life"
from regulatory retention tables. Here the retention is predicted from the content of
AI-derived copies (chats, agent notes, embeddings) that no retention table lists.
"""

import pickle
import secrets
import time
from dataclasses import dataclass
from typing import Callable

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

from .data import RETENTION_DAYS

DAY = 86400
REVIEW_BELOW = 0.6
TEXT_KINDS = ("chat", "agent-memory", "transaction")
RETENTION_CERT_TYPE = "zvault_vault.retention-expiry/v1"


@dataclass(frozen=True)
class Prediction:
    retention_class: str
    confidence: float
    needs_review: bool

    @property
    def days(self) -> int:
        return RETENTION_DAYS[self.retention_class]


def _features(texts, kinds) -> list[str]:
    return [f"kind_{k.replace('-', '_')} {t}" for t, k in zip(texts, kinds)]


class RetentionModel:
    version = "qshelf-tfidf-logreg-v1"

    def __init__(self):
        self.pipeline = make_pipeline(
            TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=1),
            LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced"),
        )

    def fit(self, texts, kinds, labels) -> "RetentionModel":
        self.pipeline.fit(_features(texts, kinds), labels)
        return self

    @property
    def classes(self) -> list[str]:
        return list(self.pipeline.classes_)

    def predict(self, texts, kinds) -> list[Prediction]:
        probs = self.pipeline.predict_proba(_features(texts, kinds))
        out = []
        for p in probs:
            order = np.argsort(p)[::-1]
            best, second = self.classes[order[0]], self.classes[order[1]]
            if p[order[0]] >= REVIEW_BELOW:
                out.append(Prediction(best, float(p[order[0]]), False))
            else:
                longer = max(best, second, key=RETENTION_DAYS.get)
                out.append(Prediction(longer, float(p[order[0]]), True))
        return out

    def explain(self, text: str, kind: str, top: int = 5) -> list[tuple[str, float]]:
        """Words that pushed this copy towards its predicted class."""
        vec, clf = self.pipeline.named_steps["tfidfvectorizer"], self.pipeline.named_steps["logisticregression"]
        x = vec.transform(_features([text], [kind]))
        cls = clf.predict(x)[0]
        weights = clf.coef_[list(clf.classes_).index(cls)]
        names = vec.get_feature_names_out()
        contrib = [(names[i], float(x[0, i] * weights[i])) for i in x.nonzero()[1]]
        return sorted(contrib, key=lambda c: c[1], reverse=True)[:top]

    def save(self, path) -> None:
        with open(path, "wb") as f:
            pickle.dump(self.pipeline, f)

    @classmethod
    def load(cls, path) -> "RetentionModel":
        model = cls()
        with open(path, "rb") as f:
            model.pipeline = pickle.load(f)
        return model


class RetentionScheduler:
    def __init__(self, store, keys, model: RetentionModel, signer, log, clock: Callable[[], float] = time.time):
        self.store, self.keys, self.model, self.signer, self.log = store, keys, model, signer, log
        self._clock = clock

    def assign(self) -> list[dict]:
        """Predict retention for every text copy that has none yet; its embedding gets the same expiry."""
        registry = self.store.registry
        pending = [r for r in registry.all() if r.kind in TEXT_KINDS and r.retention_class is None]
        assigned = []
        for customer_id in sorted({r.customer_id for r in pending}):
            try:
                lease = self.keys.lease(customer_id, purpose="retention classification")
            except Exception:
                continue  # key destroyed or not active: nothing readable to classify
            with lease:
                mine = [r for r in pending if r.customer_id == customer_id]
                texts = [self.store.get_text(lease, r.copy_id) for r in mine]
            for r, p in zip(mine, self.model.predict(texts, [r.kind for r in mine])):
                until = r.created_at + p.days * DAY
                registry.set_retention(r.copy_id, p.retention_class, until)
                if emb := registry.embedding_of(r.copy_id):
                    registry.set_retention(emb.copy_id, p.retention_class, until)
                assigned.append({"copy_id": r.copy_id, "customer_id": customer_id, **p.__dict__,
                                 "retention_until": until})
        return assigned

    def run(self) -> dict:
        """Shred every expired copy not under legal hold; publish one signed record of the run."""
        now = self._clock()
        shredded, held = [], []
        for r in self.store.registry.expired(now):
            if self.store.is_shredded(r.copy_id):
                continue
            info = self.keys.info(r.customer_id)
            if info.legal_hold:
                held.append(r.copy_id)
                continue
            self.store.shred(r.copy_id)
            shredded.append({"copy_id": r.copy_id, "customer_id": r.customer_id, "kind": r.kind,
                             "retention_class": r.retention_class, "expired_at": r.retention_until})
        report = {"run_at": now, "shredded": shredded, "kept_for_legal_hold": held}
        if shredded:
            record = self.signer.sign({"type": RETENTION_CERT_TYPE, "run_id": f"RT-{secrets.token_hex(5).upper()}",
                                       "model": self.model.version, **report})
            report["log_index"] = self.log.append(record)
            report["record"] = record
        return report
