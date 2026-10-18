"""Key service interface: one key-encryption key (KEK) per customer.

Envelope encryption in the style of AWS KMS / Google Cloud KMS:

    root key (hybrid X25519 + ML-KEM-768, never leaves the key service)
      └─ customer KEK (AES-256, stored only wrapped under the root key)
           └─ data key per AI copy (AES-256, stored only wrapped under the KEK)

Destroying a customer's KEK makes every data key under it, and so every AI copy of
that customer, unreadable at once.

Key states follow AWS KMS key deletion: ACTIVE → PENDING_DESTRUCTION → DESTROYED,
with a legal hold that blocks destruction (DPDP erasure vs. PMLA retention).

Callers never receive a KEK. They get a short-lived Lease (the HashiCorp Vault
pattern) that can produce and open data keys until it expires or is revoked.
"""

import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from ..crypto import ossl

DEFAULT_LEASE_SECONDS = 300


class KeyState(str, Enum):
    ACTIVE = "ACTIVE"
    PENDING_DESTRUCTION = "PENDING_DESTRUCTION"
    DESTROYED = "DESTROYED"


class KeyServiceError(Exception):
    pass


class UnknownCustomerError(KeyServiceError):
    pass


class KeyDestroyedError(KeyServiceError):
    """The customer's key is gone; their AI copies can no longer be decrypted by anyone."""


class KeyNotActiveError(KeyServiceError):
    pass


class LegalHoldError(KeyServiceError):
    pass


class LeaseError(KeyServiceError):
    pass


@dataclass(frozen=True)
class KeyInfo:
    customer_id: str
    version: int
    state: KeyState
    created_at: float
    legal_hold: bool
    destruction_due: Optional[float]
    destroyed_at: Optional[float]


class Lease:
    """Temporary, in-memory access to one customer's KEK for a stated purpose."""

    def __init__(self, customer_id: str, purpose: str, kek: bytes, ttl: float, clock: Callable[[], float]):
        self.lease_id = secrets.token_hex(8)
        self.customer_id = customer_id
        self.purpose = purpose
        self._clock = clock
        self.expires_at = clock() + ttl
        self._kek: Optional[bytearray] = bytearray(kek)

    @property
    def active(self) -> bool:
        return self._kek is not None and self._clock() < self.expires_at

    def _key(self) -> bytes:
        if self._kek is None:
            raise LeaseError(f"lease {self.lease_id} was revoked")
        if self._clock() >= self.expires_at:
            self.revoke()
            raise LeaseError(f"lease {self.lease_id} expired")
        return bytes(self._kek)

    def revoke(self) -> None:
        if self._kek is not None:
            for i in range(len(self._kek)):  # best effort: Python may keep other copies
                self._kek[i] = 0
            self._kek = None

    def __enter__(self) -> "Lease":
        return self

    def __exit__(self, *exc) -> None:
        self.revoke()


class KeyService(ABC):
    """What every key backend provides: the software stand-in now, Crypto Express later."""

    backend_label: str

    @abstractmethod
    def create_customer_key(self, customer_id: str) -> KeyInfo: ...

    @abstractmethod
    def info(self, customer_id: str) -> KeyInfo: ...

    @abstractmethod
    def customers(self) -> list[str]: ...

    @abstractmethod
    def lease(self, customer_id: str, purpose: str, ttl: float = DEFAULT_LEASE_SECONDS) -> Lease: ...

    @abstractmethod
    def set_legal_hold(self, customer_id: str, on: bool) -> KeyInfo: ...

    @abstractmethod
    def schedule_destruction(self, customer_id: str, delay_seconds: float = 0) -> KeyInfo: ...

    @abstractmethod
    def cancel_destruction(self, customer_id: str) -> KeyInfo: ...

    @abstractmethod
    def destroy_due(self) -> list[str]:
        """Destroy every key whose pending window has passed and has no legal hold."""

    # Data keys are wrapped under the leased KEK with AES-256-GCM; `context` (the AI copy
    # id) is bound as associated data so a wrapped data key cannot be moved to another copy.

    def new_data_key(self, lease: Lease, context: bytes) -> tuple[bytes, bytes]:
        self._check_lease(lease)
        dek = ossl.random_bytes(32)
        return dek, ossl.aes_gcm_encrypt(lease._key(), dek, aad=context)

    def open_data_key(self, lease: Lease, wrapped_dek: bytes, context: bytes) -> bytes:
        self._check_lease(lease)
        return ossl.aes_gcm_decrypt(lease._key(), wrapped_dek, aad=context)

    def _check_lease(self, lease: Lease) -> None:
        state = self.info(lease.customer_id).state
        if state is KeyState.DESTROYED:
            lease.revoke()
            raise KeyDestroyedError(f"key for {lease.customer_id} is destroyed")
        if state is not KeyState.ACTIVE:
            raise KeyNotActiveError(f"key for {lease.customer_id} is {state.value}")
