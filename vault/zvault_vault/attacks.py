"""Recovery test: after erasure, ZVault attacks its own storage with published techniques.

Four checks, each reported in the erasure certificate:

1. Decrypt attempts     every registered copy is opened through the key service
2. Embedding inversion  an attacker turns stored vectors back into text
                        (vec2text when installed; otherwise a dictionary attack that
                        matches vectors against a corpus of plausible bank messages)
3. Membership inference an attacker asks the live retrieval index whether the
                        customer's messages are still in it
4. Residue scan         every data file is searched for the customer's identifiers in
                        readable form (logs, caches, temp files)
"""

import re
from pathlib import Path

import numpy as np

from .embeddings import tokens

_PERSONAL_NUMBER = re.compile(r"\d[\d,]{3,}")


def specific_texts(texts: list[str]) -> list[str]:
    """Messages with a person-specific number (amount, account): the ones membership inference can target.

    Generic messages ("Show my balance please.") are shared by many people and reveal nothing about one.
    """
    return [t for t in texts if _PERSONAL_NUMBER.search(t)]


def token_f1(predicted: str, truth: str) -> float:
    p, t = tokens(predicted), tokens(truth)
    if not p or not t:
        return 0.0
    common = sum(min(p.count(w), t.count(w)) for w in set(p))
    if common == 0:
        return 0.0
    precision, recall = common / len(p), common / len(t)
    return 2 * precision * recall / (precision + recall)


def _normalise(vectors: np.ndarray) -> np.ndarray:
    with np.errstate(invalid="ignore", over="ignore"):  # stolen ciphertext read as floats holds NaN/inf
        v = np.nan_to_num(np.asarray(vectors, dtype=np.float64), nan=0.0, posinf=0.0, neginf=0.0)
        v = np.clip(v, -1e6, 1e6)
    norms = np.linalg.norm(v, axis=1, keepdims=True)
    return v / np.where(norms == 0, 1, norms)


class CandidateInverter:
    """Dictionary inversion: embed a large corpus of plausible messages, return the nearest one."""

    name = "dictionary inversion (nearest candidate)"

    def __init__(self, embedder, candidates: list[str]):
        self.texts = list(candidates)
        self.matrix = _normalise(embedder.encode(self.texts))

    def invert(self, vectors: np.ndarray) -> list[str]:
        scores = _normalise(vectors) @ self.matrix.T
        return [self.texts[i] for i in scores.argmax(axis=1)]


class Vec2TextInverter:
    """Generative inversion with the public vec2text corrector for gtr-t5-base (Morris et al., 2023)."""

    name = "vec2text (gtr-base corrector)"

    def __init__(self, steps: int = 20):
        import torch
        import vec2text

        self._torch, self._vec2text, self.steps = torch, vec2text, steps
        self._corrector = vec2text.load_pretrained_corrector("gtr-base")

    def invert(self, vectors: np.ndarray) -> list[str]:
        emb = self._torch.tensor(np.nan_to_num(np.asarray(vectors, dtype=np.float32)))
        return self._vec2text.invert_embeddings(embeddings=emb, corrector=self._corrector, num_steps=self.steps)


def inversion_result(inverter, vectors: np.ndarray, truths: list[str], identifiers: list[str]) -> dict:
    if len(vectors) == 0:
        return {"attack": inverter.name, "copies_attacked": 0, "mean_token_f1": 0.0, "identifiers_recovered": []}
    guesses = inverter.invert(np.asarray(vectors))
    found = sorted({i for i in identifiers for g in guesses if i and i.lower() in g.lower()})
    return {
        "attack": inverter.name,
        "copies_attacked": len(guesses),
        "mean_token_f1": round(float(np.mean([token_f1(g, t) for g, t in zip(guesses, truths)])), 3),
        "identifiers_recovered": found,
    }


def noise_baseline(inverter, n_vectors: int, n_bytes: int, dim: int, truths: list[str],
                   trials: int = 100, seed: int = 0) -> dict:
    """The same attack run on pure random bytes, many times: what an attacker gets from nothing.

    Stolen ciphertext is indistinguishable from random bytes, so the attack on it is one
    more draw from this distribution. An after-erasure score inside it means nothing leaked.
    """
    from .embeddings import from_bytes

    if n_vectors == 0:
        return {"trials": 0, "mean_token_f1": 0.0, "p95_token_f1": 0.0, "max_token_f1": 0.0}
    rng = np.random.default_rng(seed)
    scores = []
    for _ in range(trials):
        noise = np.array([np.resize(from_bytes(rng.bytes(n_bytes)), dim) for _ in range(n_vectors)])
        guesses = inverter.invert(noise)
        scores.append(float(np.mean([token_f1(g, t) for g, t in zip(guesses, truths)])))
    return {"trials": trials, "mean_token_f1": round(float(np.mean(scores)), 3),
            "p95_token_f1": round(float(np.quantile(scores, 0.95)), 3), "max_token_f1": round(max(scores), 3)}


def membership_scores(embedder, index: np.ndarray, texts: list[str]) -> np.ndarray:
    """For each probe text: highest cosine similarity to anything in the retrieval index."""
    if len(texts) == 0:
        return np.zeros(0)
    if len(index) == 0:
        return np.zeros(len(texts))
    return (_normalise(embedder.encode(list(texts))) @ _normalise(index).T).max(axis=1)


def auc(member_scores, nonmember_scores) -> float:
    """Probability a member scores above a non-member (Mann-Whitney U / ROC AUC). 0.5 = guessing."""
    m, n = np.asarray(member_scores), np.asarray(nonmember_scores)
    if len(m) == 0 or len(n) == 0:
        return 0.5
    greater = (m[:, None] > n[None, :]).sum()
    ties = (m[:, None] == n[None, :]).sum()
    return float((greater + 0.5 * ties) / (len(m) * len(n)))


def residue_scan(paths: list, canaries: list[str]) -> dict:
    """Search every file under `paths` for any canary stored in readable form."""
    needles = sorted({c for c in canaries if c and len(c) >= 6})
    files, hits = 0, []
    for root in paths:
        root = Path(root)
        for f in ([root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())):
            files += 1
            data = f.read_bytes()
            hits += [{"file": f.name, "found": n} for n in needles if n.encode("utf-8") in data]
    return {"files_scanned": files, "identifiers_checked": len(needles), "hits": hits}
