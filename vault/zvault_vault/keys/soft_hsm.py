"""Software stand-in for an IBM Crypto Express HSM.

SIMULATED: on real IBM Z the root private key lives inside a tamper-responding
Crypto Express adapter and never leaves it. This LinuxONE environment has no adapter,
so the root key is kept in a local file instead. Everything above this class uses the
same KeyService interface, so a Crypto Express (EP11/CCA) backend can replace it
without changes to the rest of ZVault.
"""

import os
import sqlite3
import time
from pathlib import Path
from typing import Callable

from ..crypto import hybrid, ossl
from .service import (
    DEFAULT_LEASE_SECONDS,
    KeyDestroyedError,
    KeyInfo,
    KeyNotActiveError,
    KeyService,
    KeyServiceError,
    KeyState,
    Lease,
    LegalHoldError,
    UnknownCustomerError,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS customer_keys (
    customer_id     TEXT PRIMARY KEY,
    version         INTEGER NOT NULL,
    state           TEXT NOT NULL,
    wrapped_kek     BLOB,
    created_at      REAL NOT NULL,
    legal_hold      INTEGER NOT NULL DEFAULT 0,
    destruction_due REAL,
    destroyed_at    REAL
);
"""


class SoftHSM(KeyService):
    backend_label = "SIMULATED Crypto Express HSM (software key store)"

    def __init__(self, directory, clock: Callable[[], float] = time.time):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._root = self._load_or_create_root()
        self._root_public = self._root.public_key()
        self._db = sqlite3.connect(self.dir / "keys.db")
        # Overwrite deleted content on disk so a destroyed wrapped KEK does not linger in free pages.
        self._db.execute("PRAGMA secure_delete = ON")
        self._db.executescript(_SCHEMA)
        self._leases: dict[str, list[Lease]] = {}

    def _load_or_create_root(self) -> hybrid.HybridPrivateKey:
        path = self.dir / "root.hybridkey"
        if path.exists():
            return hybrid.HybridPrivateKey.from_bytes(path.read_bytes())
        root = hybrid.HybridPrivateKey.generate()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(root.to_bytes())
        return root

    @property
    def root_public_key(self) -> hybrid.HybridPublicKey:
        return self._root_public

    @staticmethod
    def _context(customer_id: str, version: int) -> bytes:
        return f"kek|{customer_id}|v{version}".encode()

    def _row(self, customer_id: str):
        row = self._db.execute(
            "SELECT customer_id, version, state, created_at, legal_hold, destruction_due, destroyed_at, wrapped_kek "
            "FROM customer_keys WHERE customer_id = ?",
            (customer_id,),
        ).fetchone()
        if row is None:
            raise UnknownCustomerError(customer_id)
        return row

    @staticmethod
    def _info(row) -> KeyInfo:
        return KeyInfo(row[0], row[1], KeyState(row[2]), row[3], bool(row[4]), row[5], row[6])

    # --- KeyService -------------------------------------------------------------------------

    def create_customer_key(self, customer_id: str) -> KeyInfo:
        if self._db.execute("SELECT 1 FROM customer_keys WHERE customer_id = ?", (customer_id,)).fetchone():
            raise KeyServiceError(f"customer {customer_id} already has a key")
        version = 1
        kek = ossl.random_bytes(32)
        wrapped = hybrid.wrap_key(self._root_public, kek, self._context(customer_id, version))
        with self._db:
            self._db.execute(
                "INSERT INTO customer_keys (customer_id, version, state, wrapped_kek, created_at) VALUES (?, ?, ?, ?, ?)",
                (customer_id, version, KeyState.ACTIVE.value, wrapped, self._clock()),
            )
        return self.info(customer_id)

    def info(self, customer_id: str) -> KeyInfo:
        return self._info(self._row(customer_id))

    def customers(self) -> list[str]:
        return [r[0] for r in self._db.execute("SELECT customer_id FROM customer_keys ORDER BY customer_id")]

    def wrapped_kek(self, customer_id: str) -> bytes | None:
        """The stored wrapped KEK, exposed for the demo and the recovery test."""
        return self._row(customer_id)[7]

    def lease(self, customer_id: str, purpose: str, ttl: float = DEFAULT_LEASE_SECONDS) -> Lease:
        if not purpose or not purpose.strip():
            raise KeyServiceError("every key use needs a stated purpose")
        row = self._row(customer_id)
        info = self._info(row)
        if info.state is KeyState.DESTROYED:
            raise KeyDestroyedError(f"key for {customer_id} is destroyed")
        if info.state is not KeyState.ACTIVE:
            raise KeyNotActiveError(f"key for {customer_id} is {info.state.value}")
        kek = hybrid.unwrap_key(self._root, row[7], self._context(customer_id, info.version))
        lease = Lease(customer_id, purpose, kek, ttl, self._clock)
        self._leases.setdefault(customer_id, []).append(lease)
        return lease

    def set_legal_hold(self, customer_id: str, on: bool) -> KeyInfo:
        self._row(customer_id)
        with self._db:
            self._db.execute("UPDATE customer_keys SET legal_hold = ? WHERE customer_id = ?", (int(on), customer_id))
        return self.info(customer_id)

    def schedule_destruction(self, customer_id: str, delay_seconds: float = 0) -> KeyInfo:
        info = self.info(customer_id)
        if info.state is KeyState.DESTROYED:
            raise KeyDestroyedError(f"key for {customer_id} is already destroyed")
        if info.legal_hold:
            raise LegalHoldError(f"key for {customer_id} is under legal hold")
        with self._db:
            self._db.execute(
                "UPDATE customer_keys SET state = ?, destruction_due = ? WHERE customer_id = ?",
                (KeyState.PENDING_DESTRUCTION.value, self._clock() + delay_seconds, customer_id),
            )
        self._revoke_leases(customer_id)
        return self.info(customer_id)

    def cancel_destruction(self, customer_id: str) -> KeyInfo:
        if self.info(customer_id).state is not KeyState.PENDING_DESTRUCTION:
            raise KeyServiceError(f"key for {customer_id} is not pending destruction")
        with self._db:
            self._db.execute(
                "UPDATE customer_keys SET state = ?, destruction_due = NULL WHERE customer_id = ?",
                (KeyState.ACTIVE.value, customer_id),
            )
        return self.info(customer_id)

    def destroy_due(self) -> list[str]:
        due = [
            r[0]
            for r in self._db.execute(
                "SELECT customer_id FROM customer_keys WHERE state = ? AND legal_hold = 0 AND destruction_due <= ?",
                (KeyState.PENDING_DESTRUCTION.value, self._clock()),
            )
        ]
        for customer_id in due:
            self._revoke_leases(customer_id)
            with self._db:
                self._db.execute(
                    "UPDATE customer_keys SET state = ?, wrapped_kek = NULL, destroyed_at = ? WHERE customer_id = ?",
                    (KeyState.DESTROYED.value, self._clock(), customer_id),
                )
        return due

    def _revoke_leases(self, customer_id: str) -> None:
        for lease in self._leases.pop(customer_id, []):
            lease.revoke()

    def close(self) -> None:
        self._db.close()
