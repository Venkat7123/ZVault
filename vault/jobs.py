"""
jobs.py - scheduled vault work, run inside the vault container next to the running service.

    python3 jobs.py retention     # shred every expired AI copy (legal holds are kept); signed record
    python3 jobs.py info          # model, key backend, transparency-log size

Daily on the server (deploy/zvault-retention.timer):
    sudo docker exec zvault-vault python3 jobs.py retention
"""
import json
import os
import sys
from pathlib import Path

from service import Vault


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("retention", "info"):
        print(__doc__)
        return 2
    here = Path(__file__).resolve().parent
    vault = Vault(os.getenv("VAULT_DATA", "/data"), os.getenv("VAULT_MODELS", str(here / "models")))
    if sys.argv[1] == "retention":
        print(json.dumps(vault.retention_run()))
    else:
        info = vault.public_info()
        print(json.dumps({"model": vault.model_info, "key_backend": vault.hsm.backend_label,
                          "log_size": info["log_size"], "signer_key_id": info["signer_key_id"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
