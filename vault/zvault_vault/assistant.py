"""Fraud-analyst assistant: retrieval over the customers in one case, through the broker.

Plaintext exists only in memory for the length of one question. Customers whose key
was destroyed, or who are outside the case, come back as "blocked" with the reason.
"""

from dataclasses import dataclass, field

import numpy as np

from .broker import AccessBroker, AccessDenied
from .store import CopyShreddedError, EncryptedStore

SEARCHABLE = ("chat", "agent-memory", "transaction")


@dataclass
class Answer:
    question: str
    sources: list = field(default_factory=list)   # (score, customer_id, kind, text)
    blocked: list = field(default_factory=list)   # (customer_id, reason)


class AnalystAssistant:
    def __init__(self, broker: AccessBroker, store: EncryptedStore, embedder):
        self.broker, self.store, self.embedder = broker, store, embedder

    def ask(self, analyst_id: str, case_id: str, question: str, k: int = 3) -> Answer:
        answer = Answer(question)
        q = self.embedder.encode([question])[0]
        candidates = []
        for customer_id in self.broker.case_customers(case_id):
            try:
                lease = self.broker.request(analyst_id, case_id, customer_id)
            except AccessDenied as e:
                answer.blocked.append((customer_id, str(e)))
                continue
            with lease:
                for r in self.store.registry.for_customer(customer_id):
                    if r.kind not in SEARCHABLE:
                        continue
                    emb = self.store.registry.embedding_of(r.copy_id)
                    try:
                        text = self.store.get_text(lease, r.copy_id)
                        vector = self.store.get_vector(lease, emb.copy_id) if emb else self.embedder.encode([text])[0]
                    except CopyShreddedError:
                        continue  # expired under the retention policy
                    candidates.append((float(np.dot(q, vector)), customer_id, r.kind, text))
        answer.sources = sorted(candidates, key=lambda c: c[0], reverse=True)[:k]
        return answer
