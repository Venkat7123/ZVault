"""Copy Registry: where every AI copy of customer data lives.

Data-lineage idea from Meta's privacy-aware infrastructure: an AI copy is registered
at the moment it is created, so the erasure certificate can list exactly which copies
it covers. The encrypted store is the only write path, so nothing goes untracked.
"""

import sqlite3
import time
from dataclasses import dataclass
from typing import Callable, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS copies (
    copy_id         TEXT PRIMARY KEY,
    customer_id     TEXT NOT NULL,
    kind            TEXT NOT NULL,
    location        TEXT NOT NULL,
    created_at      REAL NOT NULL,
    retention_until REAL,
    retention_class TEXT,
    source_copy_id  TEXT
);
CREATE INDEX IF NOT EXISTS copies_by_customer ON copies(customer_id);
"""

_COLUMNS = "copy_id, customer_id, kind, location, created_at, retention_until, retention_class, source_copy_id"


@dataclass(frozen=True)
class CopyRecord:
    copy_id: str
    customer_id: str
    kind: str
    location: str
    created_at: float
    retention_until: Optional[float]
    retention_class: Optional[str]
    source_copy_id: Optional[str]


class CopyRegistry:
    def __init__(self, db: sqlite3.Connection, clock: Callable[[], float] = time.time):
        self._db = db
        self._clock = clock
        self._db.executescript(_SCHEMA)

    def register(self, copy_id: str, customer_id: str, kind: str, location: str,
                 source_copy_id: Optional[str] = None, created_at: Optional[float] = None,
                 commit: bool = True) -> None:
        self._db.execute(
            "INSERT INTO copies (copy_id, customer_id, kind, location, created_at, source_copy_id) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (copy_id, customer_id, kind, location, self._clock() if created_at is None else created_at,
             source_copy_id),
        )
        if commit:
            self._db.commit()

    def get(self, copy_id: str) -> CopyRecord:
        row = self._db.execute(f"SELECT {_COLUMNS} FROM copies WHERE copy_id = ?", (copy_id,)).fetchone()
        if row is None:
            raise KeyError(copy_id)
        return CopyRecord(*row)

    def for_customer(self, customer_id: str) -> list[CopyRecord]:
        rows = self._db.execute(
            f"SELECT {_COLUMNS} FROM copies WHERE customer_id = ? ORDER BY created_at, copy_id", (customer_id,))
        return [CopyRecord(*r) for r in rows]

    def all(self) -> list[CopyRecord]:
        return [CopyRecord(*r) for r in self._db.execute(f"SELECT {_COLUMNS} FROM copies ORDER BY created_at, copy_id")]

    def embedding_of(self, copy_id: str) -> Optional[CopyRecord]:
        row = self._db.execute(
            f"SELECT {_COLUMNS} FROM copies WHERE source_copy_id = ? AND kind = 'embedding'", (copy_id,)).fetchone()
        return CopyRecord(*row) if row else None

    def set_retention(self, copy_id: str, retention_class: Optional[str], retention_until: Optional[float]) -> None:
        with self._db:
            self._db.execute("UPDATE copies SET retention_class = ?, retention_until = ? WHERE copy_id = ?",
                             (retention_class, retention_until, copy_id))

    def expired(self, now: float) -> list[CopyRecord]:
        rows = self._db.execute(
            f"SELECT {_COLUMNS} FROM copies WHERE retention_until IS NOT NULL AND retention_until <= ? "
            "ORDER BY retention_until", (now,))
        return [CopyRecord(*r) for r in rows]

    def record_external(self, customer_id: str, kind: str, location: str) -> CopyRecord:
        """A copy that left ZVault's control (e.g. sent to an outside service). It can never be verified."""
        copy_id = f"external-{kind}-{customer_id}-{int(self._clock() * 1000)}"
        self.register(copy_id, customer_id, kind, location)
        return self.get(copy_id)
