"""Access Broker: the only way an analyst (or the AI acting for one) reaches customer data.

Modelled on Google Cloud Key Access Justifications: every key use must carry a reason,
and policy can refuse it. A request is allowed only if

    the analyst is known and signed in with MFA   (IBM Verify in production; stubbed here)
    the case is open                              (a real purpose)
    the customer is named in that case            (no browsing other customers)
    the customer's key is still active            (erased customers stay erased)

Every decision, allowed or refused, is written to an access log the customer can read.
"""

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .keys import DEFAULT_LEASE_SECONDS, KeyService, KeyServiceError, Lease

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analysts (analyst_id TEXT PRIMARY KEY, name TEXT NOT NULL, mfa_verified INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS cases (case_id TEXT PRIMARY KEY, purpose TEXT NOT NULL, is_open INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS case_customers (case_id TEXT NOT NULL, customer_id TEXT NOT NULL,
                                           PRIMARY KEY (case_id, customer_id));
CREATE TABLE IF NOT EXISTS access_log (at REAL NOT NULL, analyst_id TEXT, case_id TEXT, customer_id TEXT NOT NULL,
                                       allowed INTEGER NOT NULL, reason TEXT NOT NULL);
"""


class AccessDenied(Exception):
    pass


@dataclass(frozen=True)
class AccessDecision:
    at: float
    analyst_id: str
    case_id: str
    customer_id: str
    allowed: bool
    reason: str


class AccessBroker:
    def __init__(self, keys: KeyService, path, clock: Callable[[], float] = time.time):
        self.keys = keys
        self._clock = clock
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path)
        self._db.executescript(_SCHEMA)

    def register_analyst(self, analyst_id: str, name: str, mfa_verified: bool = True) -> None:
        with self._db:
            self._db.execute("INSERT OR REPLACE INTO analysts VALUES (?, ?, ?)", (analyst_id, name, int(mfa_verified)))

    def open_case(self, case_id: str, purpose: str, customer_ids: list[str]) -> None:
        with self._db:
            self._db.execute("INSERT OR REPLACE INTO cases VALUES (?, ?, 1)", (case_id, purpose))
            self._db.executemany("INSERT OR IGNORE INTO case_customers VALUES (?, ?)",
                                 [(case_id, c) for c in customer_ids])

    def close_case(self, case_id: str) -> None:
        with self._db:
            self._db.execute("UPDATE cases SET is_open = 0 WHERE case_id = ?", (case_id,))

    def case_customers(self, case_id: str) -> list[str]:
        return [r[0] for r in self._db.execute(
            "SELECT customer_id FROM case_customers WHERE case_id = ? ORDER BY customer_id", (case_id,))]

    def request(self, analyst_id: str, case_id: str, customer_id: str,
                ttl: float = DEFAULT_LEASE_SECONDS) -> Lease:
        """Returns a lease on the customer's key, or raises AccessDenied with the reason."""
        analyst = self._db.execute("SELECT name, mfa_verified FROM analysts WHERE analyst_id = ?",
                                   (analyst_id,)).fetchone()
        case = self._db.execute("SELECT purpose, is_open FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        in_scope = self._db.execute("SELECT 1 FROM case_customers WHERE case_id = ? AND customer_id = ?",
                                    (case_id, customer_id)).fetchone()
        if analyst is None:
            return self._deny(analyst_id, case_id, customer_id, "unknown analyst")
        if not analyst[1]:
            return self._deny(analyst_id, case_id, customer_id, "analyst has not completed MFA")
        if case is None or not case[1]:
            return self._deny(analyst_id, case_id, customer_id, "no open case with this ID")
        if not in_scope:
            return self._deny(analyst_id, case_id, customer_id, "customer is not part of this case")
        try:
            lease = self.keys.lease(customer_id, purpose=f"{case[0]} [{case_id}] by {analyst_id}", ttl=ttl)
        except KeyServiceError as e:
            return self._deny(analyst_id, case_id, customer_id, f"key unavailable: {e}")
        self._log(analyst_id, case_id, customer_id, True, case[0])
        return lease

    def _deny(self, analyst_id, case_id, customer_id, reason):
        self._log(analyst_id, case_id, customer_id, False, reason)
        raise AccessDenied(reason)

    def _log(self, analyst_id, case_id, customer_id, allowed, reason):
        with self._db:
            self._db.execute("INSERT INTO access_log VALUES (?, ?, ?, ?, ?, ?)",
                             (self._clock(), analyst_id, case_id, customer_id, int(allowed), reason))

    def access_log(self, customer_id: str) -> list[AccessDecision]:
        rows = self._db.execute(
            "SELECT at, analyst_id, case_id, customer_id, allowed, reason FROM access_log "
            "WHERE customer_id = ? ORDER BY at, rowid", (customer_id,))
        return [AccessDecision(r[0], r[1], r[2], r[3], bool(r[4]), r[5]) for r in rows]

    def close(self) -> None:
        self._db.close()
