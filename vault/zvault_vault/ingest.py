"""Turns synthetic bank data into encrypted AI copies: a text copy plus its embedding."""

import time

from .data import Bank
from .keys import KeyService, KeyServiceError
from .store import EncryptedStore

DAY = 86400


def ingest_bank(bank: Bank, keys: KeyService, store: EncryptedStore, embedder, now: float = None,
                verbose: bool = False) -> dict:
    """Creates each customer's key and stores every message encrypted, with its embedding."""
    now = time.time() if now is None else now
    t0 = time.perf_counter()
    vectors = embedder.encode([m.text for m in bank.messages])  # one batch: much faster for neural models
    t_embed = time.perf_counter() - t0
    by_message = {id(m): v for m, v in zip(bank.messages, vectors)}

    copies = {}
    for customer in bank.customers:
        try:
            keys.create_customer_key(customer.customer_id)
        except KeyServiceError:
            pass  # key already exists from an earlier run
        messages = bank.for_customer(customer.customer_id)
        if not messages:
            continue
        with keys.lease(customer.customer_id, purpose="ingest new AI copies") as lease, store.bulk():
            for m in messages:
                created = now - m.days_ago * DAY
                text_id = store.put_text(lease, m.kind, m.text, created_at=created)
                store.put_vector(lease, by_message[id(m)], source_copy_id=text_id, created_at=created)
                copies[text_id] = m
    if verbose:
        print(f"  embedding {len(bank.messages)} messages: {t_embed:.1f} s | "
              f"encrypting + storing: {time.perf_counter() - t0 - t_embed:.1f} s")
    return copies
