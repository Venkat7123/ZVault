"""
main.py - Bots Bank secure AI gateway (FastAPI).

Flow for /ask:
  token -> Granite picks a read-only tool -> rule check -> AI intent check
  -> Db2 trusted connection switched to the real employee
  -> Db2 row rules + column masks -> answer -> audit log

Run:
  uvicorn botsbank.main:app --host 127.0.0.1 --port 8000
"""
import os
import re
import threading
import time
from collections import deque
from pathlib import Path

import jwt
from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from . import auth, db, docscan, guard, llm
from .tools import TOOLS, ToolError, build_query, extract_args

# PUBLIC_MODE=1 when the site is reachable from the internet: hides /docs.
PUBLIC_MODE = os.getenv("PUBLIC_MODE", "0") == "1"

app = FastAPI(title="Bots Bank Secure AI Gateway",
              redirect_slashes=False,  # "/signin/" is a 404, not a redirect
              docs_url=None if PUBLIC_MODE else "/docs", redoc_url=None,
              openapi_url=None if PUBLIC_MODE else "/openapi.json")

# ---------- Abuse limits (in memory, per gateway process) ----------
LOGIN_FAILS_PER_USER = 5      # per 5 minutes
LOGIN_FAILS_TOTAL = 30        # per 5 minutes, all users together
ASKS_PER_USER = 10            # per minute
LLM_WAIT_SECONDS = 120        # Granite answers one question at a time
TOKEN_FAIL_LOGS = 60          # max bad-token log rows per minute (stops log flooding)
DOCS_PER_USER = 5             # document scans per minute
DOC_UPLOAD_LIMIT = docscan.MAX_BYTES + 64 * 1024   # file + multipart overhead
DOC_AI_CHECK = os.getenv("DOC_AI_CHECK", "1") == "1"  # Granite second opinion (block only)

_hits: dict[str, deque] = {}
_hits_lock = threading.Lock()
_llm_slot = threading.Semaphore(1)


def _count(key: str, window: int, add: bool = False) -> int:
    """Number of events for key in the last window seconds (optionally record one)."""
    now = time.time()
    with _hits_lock:
        q = _hits.setdefault(key, deque())
        while q and q[0] < now - window:
            q.popleft()
        if add:
            q.append(now)
        return len(q)

# Old plain page (kept at /legacy until the React app is proven on the server).
STATIC = Path(__file__).parent / "static"
STATIC_FILES = {"app.css": "text/css", "app.js": "text/javascript"}

# React app (frontend/ -> `npm run build` writes botsbank/dist).
DIST = Path(__file__).parent / "dist"
PAGE_ROUTES = ("/", "/signin", "/assistant", "/documents", "/how-it-works", "/limits")
ASSET_NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
ASSET_TYPES = {".js": "text/javascript", ".css": "text/css", ".woff2": "font/woff2",
               ".woff": "font/woff", ".svg": "image/svg+xml", ".png": "image/png"}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Refuse oversized uploads BEFORE the body is read (no Content-Length = refused too).
    if request.url.path == "/documents/scan" and request.method == "POST":
        try:
            size = int(request.headers.get("content-length", ""))
        except ValueError:
            return JSONResponse({"detail": "Upload size missing"}, status_code=411)
        if size > DOC_UPLOAD_LIMIT:
            return JSONResponse({"detail": "File is larger than 2 MB"}, status_code=413)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    # /docs (FastAPI's test page) loads its own scripts; everything else is locked down.
    if not request.url.path.startswith(("/docs", "/openapi.json")):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; frame-ancestors 'none'; form-action 'self'")
    return response


def web_page():
    """index.html for "/" and the four page routes only; every other path is a 404."""
    index = DIST / "index.html"
    if index.is_file():
        return FileResponse(index, media_type="text/html")
    raise HTTPException(404)


for _path in PAGE_ROUTES:
    app.add_api_route(_path, web_page, methods=["GET"], include_in_schema=False)


@app.get("/assets/{name}", include_in_schema=False)
def asset_file(name: str):
    # Plain file names with a known type, inside dist/assets only.
    suffix = Path(name).suffix
    path = DIST / "assets" / name
    if not ASSET_NAME.match(name) or suffix not in ASSET_TYPES or not path.is_file():
        raise HTTPException(404)
    return FileResponse(path, media_type=ASSET_TYPES[suffix])


@app.get("/legacy", include_in_schema=False)
def legacy_page():
    return FileResponse(STATIC / "index.html", media_type="text/html")


@app.get("/static/{name}", include_in_schema=False)
def static_file(name: str):
    # Only the two known files; no path from the request reaches the disk.
    if name not in STATIC_FILES:
        raise HTTPException(404)
    return FileResponse(STATIC / name, media_type=STATIC_FILES[name])


class LoginRequest(BaseModel):
    user_id: str = Field(max_length=30)
    password: str = Field(max_length=100)


class AskRequest(BaseModel):
    question: str = Field(min_length=3, max_length=500)


def client_ip(request: Request) -> str | None:
    """The connecting address. X-Forwarded-For is ignored: there is no trusted proxy in front."""
    return request.client.host if request.client else None


def _token_refused(request: Request, reason: str, message: str):
    # The token's own user name is not trusted (it failed checks), so the row says UNKNOWN.
    if _count("tokfail:*", 60, add=True) <= TOKEN_FAIL_LOGS:
        db.write_log("UNKNOWN", "token", "BLOCK", None, reason, client_ip(request))
    raise HTTPException(401, message)


def current_user(request: Request, authorization: str = Header(default="")) -> dict:
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing token")
    try:
        user = auth.verify(authorization.removeprefix("Bearer ").strip())
    except jwt.ExpiredSignatureError:
        _token_refused(request, "expired token", "Token expired, please log in again")
    except jwt.InvalidTokenError:
        _token_refused(request, "invalid token", "Invalid token")
    user["_ip"] = client_ip(request)
    return user


@app.get("/me")
def me(user: dict = Depends(current_user)):
    """Who the verified token says you are. Reads the token only: no Db2, no Granite."""
    return {"sub": user["sub"], "role": user.get("role"),
            "branch": user.get("branch"), "exp": user.get("exp")}


@app.get("/health")
def health():
    return {"status": "ok", "db": db.ping(), "llm": llm.ping()}


@app.post("/login")
def login(req: LoginRequest, request: Request):
    user_id = req.user_id.strip().upper()[:30] or "UNKNOWN"
    ip = client_ip(request)
    if (_count(f"fail:{user_id}", 300) >= LOGIN_FAILS_PER_USER
            or _count("fail:*", 300) >= LOGIN_FAILS_TOTAL):
        db.write_log(user_id, "login", "BLOCK", None, "too many failed sign-ins", ip)
        raise HTTPException(429, "Too many failed sign-ins. Try again in 5 minutes.")
    token = auth.login(req.user_id, req.password)
    if not token:
        _count(f"fail:{user_id}", 300, add=True)
        _count("fail:*", 300, add=True)
        db.write_log(user_id, "login", "BLOCK", None, "bad credentials", ip)
        raise HTTPException(401, "Invalid user or password")
    return {"token": token, "expires_in_minutes": auth.TOKEN_MINUTES}


def _blocked(user_id: str, tool: str, reason: str, stage: str, ip: str | None = None) -> dict:
    """stage = which layer stopped it: guard | intent | tool | db2 | volume."""
    db.write_log(user_id, tool, "BLOCK", None, reason, ip)
    return {"decision": "BLOCKED", "tool": tool, "reason": reason, "stage": stage,
            "rows": [], "answer": f"Request blocked: {reason}."}


def _answer(tool: str, args: dict, rows: list[dict]) -> str:
    if tool in {"get_customer", "customer_loans"} and not rows:
        return f"No records for customer {args.get('cust_id')} in the data you are allowed to see."
    if not rows:
        return "No matching records in the data you are allowed to see."
    noun = "row" if len(rows) == 1 else "rows"
    return f"Found {len(rows)} {noun} you are allowed to see."


@app.post("/ask")
def ask(req: AskRequest, user: dict = Depends(current_user)):
    user_id, ip = user["sub"], user.get("_ip")
    if _count(f"ask:{user_id}", 60, add=True) > ASKS_PER_USER:
        db.write_log(user_id, "ask", "BLOCK", None, "too many questions per minute", ip)
        raise HTTPException(429, "Too many questions. Please wait a minute.")
    # Granite runs on 3 CPUs: one question at a time, others wait in line.
    if not _llm_slot.acquire(timeout=LLM_WAIT_SECONDS):
        raise HTTPException(503, "The assistant is busy. Please try again shortly.")
    try:
        return _ask(user_id, req.question.strip(), ip)
    finally:
        _llm_slot.release()


def _ask(user_id: str, question: str, ip: str | None = None) -> dict:

    # 1. Granite chooses ONE read-only tool (it never writes SQL).
    try:
        choice = llm.choose_tool(question)
    except RuntimeError as exc:
        db.write_log(user_id, "route", "ERROR", None, str(exc), ip)
        raise HTTPException(503, "AI model unavailable") from None
    tool = choice.get("tool", "none")
    # Values come from plain code, never from the AI.
    args = extract_args(question, tool)

    # 2. Predictable rules (block only).
    allowed, reason = guard.check(question, tool, args)
    if not allowed:
        return _blocked(user_id, tool, reason, "guard", ip)

    # 3. AI intent check (block only).
    if not llm.intent_check(question, tool, args):
        return _blocked(user_id, tool, "AI intent check: request does not match the question", "intent", ip)

    # 4. Fixed SQL + validated parameters.
    try:
        sql, params = build_query(tool, args)
    except ToolError as exc:
        return _blocked(user_id, tool, str(exc), "tool", ip)

    # 5. Db2 runs it AS the employee: row rules and masks apply here.
    try:
        rows = db.run_as(user_id, sql, params)
    except db.AccessDenied:
        return _blocked(user_id, tool, "Db2 denied access for this employee", "db2", ip)

    # 6. Volume rule: more rows than this tool should ever return.
    if len(rows) > TOOLS[tool]["max_rows"]:
        return _blocked(user_id, tool, f"returned more than {TOOLS[tool]['max_rows']} rows", "volume", ip)

    db.write_log(user_id, tool, "ALLOW", len(rows), f"args={args}", ip)
    return {"decision": "ALLOWED", "tool": tool, "args": args, "stage": None,
            "answer": _answer(tool, args, rows), "rows": rows}


@app.get("/logs")
def logs(user: dict = Depends(current_user)):
    """Staff cannot read the audit log through the gateway. Db2 refuses it
    (only the AUDITOR role may SELECT it), and auditors use read_audit_log.py
    directly instead of the AI."""
    try:
        db.run_as(user["sub"],
                  "SELECT LOG_ID FROM BANK.ACCESS_LOG FETCH FIRST 1 ROWS ONLY")
    except db.AccessDenied:
        db.write_log(user["sub"], "read_logs", "BLOCK", None, "Db2 denied log access", user.get("_ip"))
        return JSONResponse(
            {"detail": "Db2 denied: only auditors can read the audit log, "
                       "directly and not through the AI", "stage": "db2"},
            status_code=403)
    raise HTTPException(500, "Unexpected: Db2 allowed log access; check grants")


# ---------- Loan documents: scan BEFORE any AI reads them ----------

def _doc_reply(verdict: str, result, findings: list, fields: list | None = None) -> dict:
    return {"verdict": verdict, "sha256": result.sha256[:16], "pages": result.pages,
            "findings": findings, "fields": fields or [],
            "visible_text": result.visible_text[:3000],
            "note": ("AI summary of the visible text only. Values are shown only when found in the "
                     "document. You make the decision.") if verdict == "CLEAN" else
                    "Quarantined: the AI did not read this document. Hidden content is shown below."}


@app.post("/documents/scan")
def scan_document(file: UploadFile = File(...), user: dict = Depends(current_user)):
    """1. code scan -> 2. Granite injection check (block only) -> 3. Granite fills 5 fields
    -> 4. code verifies each value is in the visible text. Anything suspicious = QUARANTINED,
    and then the AI never reads the document. The file is never stored."""
    user_id, ip = user["sub"], user.get("_ip")
    if _count(f"doc:{user_id}", 60, add=True) > DOCS_PER_USER:
        db.write_log(user_id, "doc_scan", "BLOCK", None, "too many document scans per minute", ip)
        raise HTTPException(429, "Too many documents. Please wait a minute.")
    data = file.file.read(docscan.MAX_BYTES + 1)
    try:
        result = docscan.scan(data)
    except docscan.DocRejected as exc:
        db.write_log(user_id, "doc_scan", "BLOCK", None, f"document rejected: {exc}", ip)
        raise HTTPException(400, f"Document not accepted: {exc}") from None
    tag = f"sha256={result.sha256[:16]}"

    if result.verdict == "QUARANTINED":
        db.write_log(user_id, "doc_scan", "BLOCK", None,
                     f"document quarantined: {', '.join(result.kinds)} {tag}", ip)
        return _doc_reply("QUARANTINED", result, result.findings)

    if not _llm_slot.acquire(timeout=LLM_WAIT_SECONDS):
        raise HTTPException(503, "The assistant is busy. Please try again shortly.")
    try:
        if DOC_AI_CHECK and not llm.doc_injection_check(result.visible_text):
            finding = {"kind": "ai_check", "where": "visible text", "text": "",
                       "detail": "Granite found text that tries to instruct an AI"}
            db.write_log(user_id, "doc_scan", "BLOCK", None, f"document quarantined: ai_check {tag}", ip)
            return _doc_reply("QUARANTINED", result, [finding])
        try:
            raw = llm.extract_fields(result.visible_text)
        except RuntimeError as exc:
            db.write_log(user_id, "doc_scan", "ERROR", None, str(exc), ip)
            raise HTTPException(503, "AI model unavailable") from None
    finally:
        _llm_slot.release()

    fields = docscan.verify_fields(raw, llm.FIELDS, result.visible_text)
    verified = sum(f["verified"] for f in fields)
    db.write_log(user_id, "doc_scan", "ALLOW", verified, f"document clean {tag}", ip)
    return _doc_reply("CLEAN", result, [], fields)
