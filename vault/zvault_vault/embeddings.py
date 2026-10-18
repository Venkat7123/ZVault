"""Text embedders for the analyst assistant and the recovery test.

GTREmbedder uses sentence-transformers/gtr-t5-base, the embedder the public vec2text
inversion models were trained against. HashingEmbedder needs only numpy, so the whole
pipeline also runs (and is tested) where PyTorch models cannot be installed.
"""

import hashlib
import re

import numpy as np

DIM = 768
_TOKEN = re.compile(r"[a-z0-9]+")


def tokens(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


class HashingEmbedder:
    name = "hashing-768 (numpy fallback)"
    dim = DIM

    def encode(self, texts: list[str]) -> np.ndarray:
        out = np.zeros((len(texts), DIM), dtype=np.float32)
        for row, text in enumerate(texts):
            toks = tokens(text)
            for feature in toks + [a + "_" + b for a, b in zip(toks, toks[1:])]:
                h = int.from_bytes(hashlib.blake2b(feature.encode(), digest_size=8).digest(), "little")
                out[row, h % DIM] += 1.0 if (h >> 63) & 1 else -1.0
        norms = np.linalg.norm(out, axis=1, keepdims=True)
        return out / np.where(norms == 0, 1, norms)


class GTREmbedder:
    name = "sentence-transformers/gtr-t5-base"
    dim = DIM

    def __init__(self):
        from sentence_transformers import SentenceTransformer

        self._model = SentenceTransformer(self.name, device="cpu")

    def encode(self, texts: list[str]) -> np.ndarray:
        return np.asarray(self._model.encode(list(texts), normalize_embeddings=True), dtype=np.float32)


class CachedEmbedder:
    """Wraps an embedder so each distinct text is embedded once (neural models are slow on CPU)."""

    def __init__(self, inner):
        self.inner, self.name, self.dim = inner, inner.name, inner.dim
        self._cache: dict[str, np.ndarray] = {}

    def encode(self, texts: list[str]) -> np.ndarray:
        missing = [t for t in dict.fromkeys(texts) if t not in self._cache]
        if missing:
            for t, v in zip(missing, self.inner.encode(missing)):
                self._cache[t] = v
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        return np.stack([self._cache[t] for t in texts])


def default_embedder(prefer_gtr: bool = True):
    """gtr-t5-base when sentence-transformers is installed, otherwise the numpy fallback."""
    if prefer_gtr:
        try:
            return GTREmbedder()
        except Exception as e:  # not installed, no network for the model download, etc.
            print(f"gtr-t5-base unavailable ({type(e).__name__}); using {HashingEmbedder.name}")
    return HashingEmbedder()


def to_bytes(vector: np.ndarray) -> bytes:
    return np.asarray(vector, dtype="<f4").tobytes()


def from_bytes(data: bytes) -> np.ndarray:
    usable = len(data) - len(data) % 4
    return np.frombuffer(data[:usable], dtype="<f4").copy()
