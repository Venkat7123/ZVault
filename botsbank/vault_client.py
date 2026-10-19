"""
vault_client.py - the gateway's side of the ZVault vault (a separate, local-only service).

The gateway may STORE an AI copy, LIST what is held (metadata only), FORGET a customer and
REMOVE one copy. There is no call that returns a copy's content, and the gateway never holds
a customer key. Legal hold is not here at all: only the auditor's token can set it.
"""
import json
import os
import urllib.error
import urllib.request

VAULT_URL = os.getenv("VAULT_URL", "http://127.0.0.1:8090")
TIMEOUT = int(os.getenv("VAULT_TIMEOUT", "120"))


class VaultUnavailable(Exception):
    """Not configured, not running, or an internal vault error."""


class VaultRefused(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def enabled() -> bool:
    return bool(os.environ.get("VAULT_TOKEN"))


def _call(method: str, path: str, body: dict | None = None) -> dict:
    token = os.environ.get("VAULT_TOKEN")
    if not token:
        raise VaultUnavailable("vault not configured")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(VAULT_URL + path, data=data, method=method,
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        try:
            detail = str(json.load(exc).get("detail", "refused"))
        except Exception:  # noqa: BLE001
            detail = "refused"
        if exc.code >= 500 or exc.code in (401, 403):
            raise VaultUnavailable(f"vault error {exc.code}") from None
        raise VaultRefused(exc.code, detail) from None
    except (urllib.error.URLError, OSError, ValueError):
        raise VaultUnavailable("vault not reachable") from None


def store(customer: str, fields: dict, source: str, requested_by: str) -> dict:
    return _call("POST", "/v1/copies", {"customer": customer, "fields": fields, "source": source,
                                        "requested_by": requested_by})


def copies(customer: str) -> dict:
    return _call("GET", f"/v1/customers/{customer}/copies")


def forget(customer: str, requested_by: str, identity_verified: bool) -> dict:
    return _call("POST", f"/v1/customers/{customer}/forget",
                 {"requested_by": requested_by, "identity_verified": identity_verified})


def remove(customer: str, copy_id: str, reason: str, requested_by: str) -> dict:
    return _call("POST", f"/v1/customers/{customer}/copies/{copy_id}/remove",
                 {"reason": reason, "requested_by": requested_by})
