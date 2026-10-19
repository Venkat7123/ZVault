"""
legal_hold.py - the AUDITOR puts a customer's AI data under legal hold (or lifts it), directly
at the vault on the server. The AI gateway cannot do this: it does not have the auditor token.

While a hold is on, "Forget customer" and copy removal are refused (and the refusal is signed),
and the daily retention run keeps the customer's copies (PMLA: investigations need the records).

Run on LinuxONE:
    export VAULT_AUDITOR_TOKEN=...          # from ~/.zvault_env, never typed into the AI
    python3 tests/legal_hold.py 1001 on
    python3 tests/legal_hold.py 1001 off
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

VAULT = os.getenv("VAULT_URL", "http://127.0.0.1:8090")

if len(sys.argv) != 3 or not re.match(r"^\d{4}$", sys.argv[1]) or sys.argv[2] not in ("on", "off"):
    sys.exit(__doc__)
token = os.environ.get("VAULT_AUDITOR_TOKEN")
if not token:
    sys.exit("Set VAULT_AUDITOR_TOKEN first (see ~/.zvault_env)")

req = urllib.request.Request(
    f"{VAULT}/v1/customers/{sys.argv[1]}/hold", method="POST",
    data=json.dumps({"on": sys.argv[2] == "on", "requested_by": "AUDITOR1"}).encode(),
    headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        out = json.load(resp)
except urllib.error.HTTPError as exc:
    sys.exit(f"Refused (HTTP {exc.code}): {exc.read().decode()[:200]}")
p = out["proofs"]
print(f"Customer {out['customer']}: legal hold {'ON' if out['legal_hold'] else 'OFF'}")
print(f"Signed record ({p['signature_algorithm']}) valid: {p['signature_valid']} | "
      f"in transparency log: {p['in_transparency_log']} (entry {p['log_index']})")
