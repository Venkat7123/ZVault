"""
auth.py - login and short-lived tokens.

DIRECTORY stands in for the bank's identity system (RACF / IBM Verify in
production). The token carries who the employee is; Db2 still makes the
final access decision.
"""
import hmac
import os
import time

import jwt

TOKEN_MINUTES = 15

# Only staff who use the AI assistant. Auditors are deliberately NOT here:
# they read the audit log directly in Db2, never through the AI, so the
# gateway can never switch to an all-branches identity.
DIRECTORY = {
    "CLERK1":   {"role": "CLERK",   "branch": "CHN01"},
    "CLERK2":   {"role": "CLERK",   "branch": "MUM01"},
    "MANAGER1": {"role": "MANAGER", "branch": "CHN01"},
}


def _secret() -> str:
    secret = os.environ.get("JWT_SECRET")
    if not secret or len(secret) < 32:
        raise RuntimeError("JWT_SECRET must be set (32+ characters)")
    return secret


def login(user_id: str, password: str) -> str | None:
    user_id = user_id.strip().upper()
    demo_password = os.environ.get("DEMO_PASSWORD", "")
    if user_id not in DIRECTORY or not demo_password:
        return None
    if not hmac.compare_digest(password.encode(), demo_password.encode()):
        return None
    now = int(time.time())
    claims = {
        "sub": user_id,
        "role": DIRECTORY[user_id]["role"],
        "branch": DIRECTORY[user_id]["branch"],
        "iat": now,
        "exp": now + TOKEN_MINUTES * 60,
    }
    return jwt.encode(claims, _secret(), algorithm="HS256")


def verify(token: str) -> dict:
    """Return the token's claims, or raise jwt.InvalidTokenError."""
    claims = jwt.decode(token, _secret(), algorithms=["HS256"])
    if claims.get("sub") not in DIRECTORY:
        raise jwt.InvalidTokenError("unknown user")
    return claims
