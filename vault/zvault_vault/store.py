"""Encrypted store for AI copies of customer data (embeddings, chats, agent memory).

Every copy is encrypted the moment it is written, under its own data key, which is
wrapped under the customer's KEK. Nothing is stored in readable form. Reading needs a
lease on that customer's key, so once the key is destroyed every copy is unreadable,
including copies in backups or replicas of this database.

A single copy can also be shredded on its own (Feature 2): its wrapped data key is
overwritten, so that copy is unreadable even while the customer's key stays active.
"""

import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from .crypto import ossl
from .keys import KeyService, KeyServiceError, Lease, LeaseError
from .registry import CopyRegistry

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sealed_copies (
    copy_id     TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    kind        TEXT NOT NULL,
    wrapped_dek BLOB,
    ciphertext  BLOB NOT NULL
);
"""

LOCATION = "encrypted-store"


class CopyShreddedError(KeyServiceError):
    """This copy's own data key was destroyed; the copy can no longer be decrypted."""


class EncryptedStore:
    def __init__(self, path, keys: KeyService):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path)
        self._db.execute("PRAGMA secure_delete = ON")
        self._db.executescript(_SCHEMA)
        self.keys = keys
        self.registry = CopyRegistry(self._db)
        self._bulk = False

    @contextmanager
    def bulk(self):
        """Write many copies in one transaction: one disk flush instead of one per copy."""
        self._bulk = True
        try:
            yield self
            self._db.commit()
        except BaseException:
            self._db.rollback()
            raise
        finally:
            self._bulk = False

    @staticmethod
    def _aad(copy_id: str, customer_id: str, kind: str) -> bytes:
        return f"copy|{copy_id}|{customer_id}|{kind}".encode()

    def put(self, lease: Lease, kind: str, data: bytes, source_copy_id: Optional[str] = None,
            created_at: Optional[float] = None) -> str:
        """Encrypt and store one AI copy for the lease's customer. Returns its copy id."""
        copy_id = f"{kind}-{secrets.token_hex(6)}"
        aad = self._aad(copy_id, lease.customer_id, kind)
        dek, wrapped_dek = self.keys.new_data_key(lease, aad)
        ciphertext = ossl.aes_gcm_encrypt(dek, data, aad=aad)
        self._db.execute(
            "INSERT INTO sealed_copies VALUES (?, ?, ?, ?, ?)",
            (copy_id, lease.customer_id, kind, wrapped_dek, ciphertext),
        )
        self.registry.register(copy_id, lease.customer_id, kind, LOCATION, source_copy_id, created_at,
                               commit=not self._bulk)
        return copy_id

    def get(self, lease: Lease, copy_id: str) -> bytes:
        customer_id, kind, wrapped_dek, ciphertext = self._sealed(copy_id)
        if customer_id != lease.customer_id:
            raise LeaseError(f"lease is for {lease.customer_id}, copy belongs to another customer")
        if wrapped_dek is None:
            raise CopyShreddedError(f"copy {copy_id} was shredded")
        aad = self._aad(copy_id, customer_id, kind)
        dek = self.keys.open_data_key(lease, wrapped_dek, aad)
        return ossl.aes_gcm_decrypt(dek, ciphertext, aad=aad)

    def put_text(self, lease: Lease, kind: str, text: str, **kw) -> str:
        return self.put(lease, kind, text.encode("utf-8"), **kw)

    def get_text(self, lease: Lease, copy_id: str) -> str:
        return self.get(lease, copy_id).decode("utf-8")

    def put_vector(self, lease: Lease, vector, source_copy_id: str, **kw) -> str:
        from .embeddings import to_bytes

        return self.put(lease, "embedding", to_bytes(vector), source_copy_id=source_copy_id, **kw)

    def get_vector(self, lease: Lease, copy_id: str):
        from .embeddings import from_bytes

        return from_bytes(self.get(lease, copy_id))

    def shred(self, copy_id: str) -> None:
        self._sealed(copy_id)
        with self._db:
            self._db.execute("UPDATE sealed_copies SET wrapped_dek = NULL WHERE copy_id = ?", (copy_id,))

    def is_shredded(self, copy_id: str) -> bool:
        return self._sealed(copy_id)[2] is None

    def sealed(self, copy_id: str) -> dict:
        """What an attacker who copies the disk gets: only ciphertext and a wrapped key."""
        customer_id, kind, wrapped_dek, ciphertext = self._sealed(copy_id)
        return {"customer_id": customer_id, "kind": kind, "wrapped_dek": wrapped_dek, "ciphertext": ciphertext}

    def _sealed(self, copy_id: str):
        row = self._db.execute(
            "SELECT customer_id, kind, wrapped_dek, ciphertext FROM sealed_copies WHERE copy_id = ?", (copy_id,)
        ).fetchone()
        if row is None:
            raise KeyError(copy_id)
        return row

    def close(self) -> None:
        self._db.close()
