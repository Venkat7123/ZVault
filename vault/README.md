# ZVault · Quantum-safe AI Data Vault

Every AI copy of customer data (chat text, embedding, agent memory, transaction note) is
**encrypted the moment it is stored, under that customer's own key**. "Forget me" destroys one
key, which makes every copy unreadable at once. ZVault then attacks its own storage to prove it, and
publishes a quantum-safe signed certificate.

## Key hierarchy
```
Root key: hybrid X25519 + ML-KEM-768 (FIPS 203)   → Crypto Express HSM in production
  └─ Customer key (AES-256), stored only wrapped under the root
       └─ Data key per AI copy (AES-256-GCM on CPACF), stored only wrapped under the customer key
```
- An attacker must break **both** X25519 and ML-KEM-768, so keys recorded today stay safe from a future quantum computer.
- Customer and copy IDs are bound into the encryption, so wrapped keys can't be swapped.
- Callers get only a 5-minute **lease**, never a key. Key states: ACTIVE → PENDING_DESTRUCTION → DESTROYED.
- **Legal hold** (PMLA) blocks erasure; the refusal is signed.

## Features
| Module | What it does |
|---|---|
| `crypto/ossl.py` | ctypes binding to system OpenSSL 3.5: AES-256-GCM, ML-KEM-768, ML-DSA-65, X25519, RSA (comparison only) |
| `crypto/hybrid.py` | Hybrid KEM (X-Wing-style combiner) and key wrapping |
| `keys/` | Key service interface + software stand-in for the Crypto Express HSM |
| `store.py`, `registry.py` | Encrypted AI-copy store; every copy registered at creation |
| `broker.py`, `assistant.py` | Access broker (MFA + open case + customer in case) and fraud-analyst assistant |
| `erasure.py`, `attacks.py` | Forget on request + recovery test: decrypt, embedding inversion, membership inference, residue scan |
| `certs.py`, `tlog.py` | ML-DSA-65 erasure certificates, Merkle transparency log (RFC 6962) with inclusion proofs |
| `retention.py` | Retention model (30 d / 1 y / 5 y / 20 y) + scheduler that shreds expired copies |

## Run on IBM LinuxONE (z17) - recommended
pip has no s390x wheels for numpy/scikit-learn, and Ubuntu 24.04 has OpenSSL 3.0, so the vault runs in a
Debian 13 container (OpenSSL 3.5.7 + Debian's pre-built packages). The code is mounted, not copied:

```bash
cd ~/botsbank-project/vault
sudo docker build -t zvault-vault .
RUN="sudo docker run --rm --network none --user $(id -u):$(id -g) -v $HOME/botsbank-project/vault:/vault zvault-vault"
$RUN                              # 83 tests
$RUN python3 train_qshelf.py      # train the retention model on this machine (+ fingerprint)
$RUN python3 run_demo.py          # the full demo as a script
```
Measured on z17: AES-256-GCM 1,776 MiB/s (CPACF), hybrid key wrap 4,756/s, ML-DSA-65 sign 604/s,
erasure: inversion F1 0.915 -> 0.156 (noise 0.173), membership AUC 1.00 -> 0.58, no identifiers recovered.

## Run anywhere else
Requires **OpenSSL 3.5+** (first release with ML-KEM and ML-DSA) and Python 3.11+.

```bash
cd vault
pip install -e ".[test,notebook]"          # numpy, scikit-learn, pytest, pandas, jupyter
# if the system OpenSSL is older than 3.5:
export ZVAULT_LIBCRYPTO=/path/to/openssl-3.5/lib64/libcrypto.so.3
python -m pytest -q                         # automatic tests
jupyter notebook ZVault_Vault_Demo.ipynb    # full demo
```
Optional: `pip install -e ".[embeddings]"` uses the real `gtr-t5-base` embedder (otherwise a numpy fallback).

## Real vs simulated
| Part | Status |
|---|---|
| AES-256-GCM on CPACF (IBM Z) | Real on IBM Z via system OpenSSL |
| Hybrid X25519 + ML-KEM-768 key wrapping | Real (OpenSSL 3.5) |
| ML-DSA-65 certificates + transparency log | Real (OpenSSL 3.5) |
| Crypto Express HSM | Software stand-in with the same interface (no adapter in this environment) |
| IBM Secure Execution attestation | Code measurement computed in software |

All data is synthetic, with generic names only.
