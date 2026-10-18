"""
train_qshelf.py - (re)train the QShelf retention model from ZVault's synthetic bank data.

The model reads an AI copy (chat, agent note, transaction text) and predicts how long it must
be kept: short 30 days, service 1 year, regulatory 5 years, contract 20 years.

Everything is reproducible: the same seeds give the same data and the same model, so anyone
(including a judge) can rebuild it instead of trusting a pickle file someone sent them.

Run from the vault/ folder:
    python train_qshelf.py                 # train, report, save models/qshelf.pkl (+ .sha256, .json)
    python train_qshelf.py --verify        # check models/qshelf.pkl against its fingerprint

Needs: numpy, scikit-learn. (OpenSSL 3.5 is NOT needed for training.)
"""
import argparse
import hashlib
import json
import pickle
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import sklearn
from sklearn.metrics import classification_report, confusion_matrix

from zvault_vault.data import FIRST, LAST, RETENTION_DAYS, generate_bank
from zvault_vault.retention import REVIEW_BELOW, RetentionModel

TRAIN_SEED, TEST_SEED, CUSTOMERS = 11, 12, 300
OUT = Path(__file__).resolve().parent / "models"
MODEL = OUT / "qshelf.pkl"

# Real-looking names used by the first version of the data. None may appear in the model.
OLD_NAMES = ["aarav", "diya", "vihaan", "ananya", "arjun", "ishita", "kabir", "meera", "rohan", "saanvi",
             "aditya", "kavya", "farhan", "zoya", "nikhil", "priya", "siddharth", "tara", "yash", "nisha",
             "sharma", "iyer", "reddy", "khan", "patel", "nair", "gupta", "das", "menon", "singh",
             "rao", "joshi", "bose", "kulkarni", "fernandes"]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify() -> int:
    expected = (MODEL.with_suffix(".pkl.sha256")).read_text().split()[0]
    actual = sha256(MODEL)
    print(f"expected {expected}\nactual   {actual}")
    print("OK: model matches its fingerprint" if actual == expected else "MISMATCH: do not load this file")
    return 0 if actual == expected else 1


def train() -> int:
    # 1. Data: train and test use DIFFERENT seeds AND different phrasing families,
    #    so the test is on wordings the model never saw.
    train_msgs = [m for m in generate_bank(CUSTOMERS, seed=TRAIN_SEED).messages if m.family == "train"]
    test_msgs = [m for m in generate_bank(CUSTOMERS, seed=TEST_SEED).messages if m.family == "test"]
    print(f"Generic names in the data, e.g.: {FIRST[0]} {LAST[0]}, {FIRST[1]} {LAST[1]}")
    print(f"Training on {len(train_msgs)} copies, testing on {len(test_msgs)} unseen phrasings")

    # 2. Train
    t0 = time.perf_counter()
    model = RetentionModel().fit([m.text for m in train_msgs], [m.kind for m in train_msgs],
                                 [m.retention for m in train_msgs])
    print(f"Trained in {time.perf_counter() - t0:.2f} s")

    # 3. Evaluate
    preds = model.predict([m.text for m in test_msgs], [m.kind for m in test_msgs])
    y_true = [m.retention for m in test_msgs]
    y_pred = [p.retention_class for p in preds]
    print(classification_report(y_true, y_pred, digits=3))
    labels = sorted(RETENTION_DAYS, key=RETENTION_DAYS.get)
    print("Confusion matrix (rows = true, columns = predicted):", labels)
    print(confusion_matrix(y_true, y_pred, labels=labels))
    accuracy = float(np.mean([a == b for a, b in zip(y_true, y_pred)]))
    too_early = sum(RETENTION_DAYS[p] < RETENTION_DAYS[t] for p, t in zip(y_pred, y_true))
    review = sum(p.needs_review for p in preds)
    print(f"\nAccuracy: {accuracy:.3f}")
    print(f"Deleted earlier than required (must be 0): {too_early} of {len(y_true)}")
    print(f"Flagged for human review (confidence < {REVIEW_BELOW}, longer class kept): {review}")

    # 4. Safety checks before saving
    vocab = set(model.pipeline.named_steps["tfidfvectorizer"].get_feature_names_out())
    leaked = sorted(n for n in OLD_NAMES if any(n == w or w.startswith(n + " ") or w.endswith(" " + n)
                                                  for w in vocab))
    if leaked:
        print(f"STOP: real-looking names found in the model vocabulary: {leaked}")
        return 1
    if too_early:
        print("STOP: the model would delete records earlier than the law requires.")
        return 1
    print("Name check: no real-looking names in the model vocabulary")

    # 5. Save the model + its fingerprint + how it was made
    OUT.mkdir(exist_ok=True)
    model.save(MODEL)
    digest = sha256(MODEL)
    MODEL.with_suffix(".pkl.sha256").write_text(f"{digest}  qshelf.pkl\n")
    MODEL.with_suffix(".json").write_text(json.dumps({
        "model": RetentionModel.version,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sha256": digest,
        "data": {"generator": "zvault_vault.data.generate_bank", "customers": CUSTOMERS,
                 "train_seed": TRAIN_SEED, "test_seed": TEST_SEED,
                 "train_copies": len(train_msgs), "test_copies": len(test_msgs), "names": "generic only"},
        "results": {"accuracy": round(accuracy, 3), "deleted_too_early": too_early,
                    "flagged_for_review": review},
        "versions": {"python": platform.python_version(), "scikit_learn": sklearn.__version__,
                     "numpy": np.__version__, "machine": platform.machine()},
        "load_note": "Load only after checking qshelf.pkl.sha256, with the same scikit-learn version.",
    }, indent=2))
    print(f"\nSaved {MODEL}\n      {MODEL.with_suffix('.pkl.sha256').name}  sha256 {digest[:16]}...\n"
          f"      {MODEL.with_suffix('.json').name}  (how it was made + results)")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Train or verify the QShelf retention model")
    p.add_argument("--verify", action="store_true", help="check models/qshelf.pkl against its fingerprint")
    sys.exit(verify() if p.parse_args().verify else train())
