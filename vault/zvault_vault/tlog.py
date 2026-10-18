"""Erasure Transparency Log: an append-only Merkle log of certificates.

Same construction as Certificate Transparency (RFC 6962) and Sigstore Rekor:

    leaf hash = SHA-256(0x00 || entry)      node hash = SHA-256(0x01 || left || right)

Each signed tree head (size + root) is signed with ML-DSA-65. A customer holding their
certificate and an inclusion proof can check it is in the log the bank published, and
the bank cannot later remove or alter it without changing the signed root.
"""

import base64
import hashlib
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .certs import SIGNATURE_ALG, CertificateSigner, canonical
from .crypto import ossl


def leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two smaller than n (RFC 6962 section 2.1)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_path(index: int, leaves: list[bytes]) -> list[bytes]:
    if len(leaves) <= 1:
        return []
    k = _split(len(leaves))
    if index < k:
        return inclusion_path(index, leaves[:k]) + [merkle_root(leaves[k:])]
    return inclusion_path(index - k, leaves[k:]) + [merkle_root(leaves[:k])]


def verify_inclusion(entry: bytes, index: int, size: int, path: list[bytes], root: bytes) -> bool:
    """RFC 9162 section 2.1.3.2 inclusion proof verification."""
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf_hash(entry)
    for p in path:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = node_hash(p, r)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


@dataclass(frozen=True)
class TreeHead:
    size: int
    root: bytes
    signature: bytes

    def body(self) -> bytes:
        return canonical({"log": "zvault_vault-erasure-log/v1", "size": self.size, "root": self.root.hex()})

    def to_dict(self) -> dict:
        return {"size": self.size, "root": self.root.hex(), "algorithm": SIGNATURE_ALG,
                "signature": base64.b64encode(self.signature).decode()}


class TransparencyLog:
    def __init__(self, path, signer: CertificateSigner):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path)
        self._db.execute("CREATE TABLE IF NOT EXISTS entries (idx INTEGER PRIMARY KEY, entry BLOB NOT NULL)")
        self.signer = signer

    def _leaves(self) -> list[bytes]:
        return [leaf_hash(r[0]) for r in self._db.execute("SELECT entry FROM entries ORDER BY idx")]

    def append(self, document: dict) -> int:
        with self._db:
            cur = self._db.execute("INSERT INTO entries (idx, entry) VALUES ((SELECT COUNT(*) FROM entries), ?)",
                                   (canonical(document),))
        return cur.lastrowid

    def size(self) -> int:
        return self._db.execute("SELECT COUNT(*) FROM entries").fetchone()[0]

    def entry(self, index: int) -> bytes:
        return self._db.execute("SELECT entry FROM entries WHERE idx = ?", (index,)).fetchone()[0]

    def tree_head(self) -> TreeHead:
        leaves = self._leaves()
        root = merkle_root(leaves)
        unsigned = TreeHead(len(leaves), root, b"")
        return TreeHead(len(leaves), root, self.signer.sign_bytes(unsigned.body()))

    def inclusion_proof(self, index: int) -> list[bytes]:
        return inclusion_path(index, self._leaves())

    def close(self) -> None:
        self._db.close()


def verify_tree_head(head: TreeHead, public_der: bytes) -> bool:
    return ossl.verify(ossl.PKey.from_public_der(public_der, SIGNATURE_ALG), head.body(), head.signature)
