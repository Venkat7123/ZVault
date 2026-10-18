"""
test_web_routes.py - checks the gateway's web routes, /me and the new "stage" field,
using the real botsbank/main.py with Db2 and Granite replaced by stand-ins.
Needs: fastapi, httpx, pyjwt. Nothing here touches Db2, Granite or a server.

Run from the project folder:
    python tests/test_web_routes.py
"""
import os
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.update(JWT_SECRET="x" * 40, DEMO_PASSWORD="demo")
sys.modules.setdefault("ibm_db", types.ModuleType("ibm_db"))

from fastapi.testclient import TestClient  # noqa: E402

from botsbank import db, llm, main  # noqa: E402

db.write_log = lambda *a, **k: None
db.ping = lambda: True
llm.ping = lambda: True
state = {"tool": "get_customer", "intent": True, "denied": False, "rows": [{"CUST_ID": 1001}]}
llm.choose_tool = lambda q: {"tool": state["tool"]}
llm.intent_check = lambda *a: state["intent"]


def run_as(user, sql, params=()):
    if state["denied"]:
        raise db.AccessDenied("SQL0551N")
    return state["rows"]


db.run_as = run_as
client = TestClient(main.app)
failures = []


def check(name, ok, detail=""):
    print(("PASS" if ok else "FAIL"), name, detail if not ok else "")
    if not ok:
        failures.append(name)


dist = ROOT / "botsbank" / "dist"
assert (dist / "index.html").is_file(), "build the frontend first: cd frontend && npm run build"

# ---- Pages: index.html ONLY for "/" and the four page routes ----
for path in ("/", "/signin", "/assistant", "/documents", "/how-it-works", "/limits"):
    r = client.get(path)
    check(f"GET {path} serves the app", r.status_code == 200 and "text/html" in r.headers["content-type"]
          and '<div id="root">' in r.text, r.status_code)
for path in ("/nope", "/signin/", "/assistant/x", "/index.html", "/dist/index.html", "/static/index.html",
             "/botsbank/main.py", "/..%2Fmain.py", "/etc/passwd"):
    check(f"GET {path} is 404", client.get(path).status_code == 404, client.get(path).status_code)

# ---- Assets: only plain files inside dist/assets ----
assets = sorted((dist / "assets").iterdir())
js = next(a for a in assets if a.suffix == ".js")
css = next(a for a in assets if a.suffix == ".css")
font = next(a for a in assets if a.suffix == ".woff2")
check("JS asset served", client.get(f"/assets/{js.name}").headers["content-type"].startswith("text/javascript"))
check("CSS asset served", client.get(f"/assets/{css.name}").headers["content-type"].startswith("text/css"))
check("font asset served", client.get(f"/assets/{font.name}").headers["content-type"] == "font/woff2")
for bad in ("../index.html", "%2e%2e%2findex.html", "..%5Cindex.html", "missing.js", "index.html", ".js"):
    check(f"/assets/{bad} is 404", client.get(f"/assets/{bad}").status_code == 404)
# HTTP clients rewrite "/assets/.." to "/", so call the handler directly for that name.
try:
    main.asset_file("..")
    check("asset_file('..') is refused", False)
except main.HTTPException as exc:
    check("asset_file('..') is refused", exc.status_code == 404)

# ---- Built page obeys the CSP (no inline script/style, no external URLs) ----
html = (dist / "index.html").read_text(encoding="utf-8")
check("no inline <script> bodies", not re.search(r"<script(?![^>]*\bsrc=)[^>]*>\s*\S", html))
check("no inline <style>", "<style" not in html)
check("no external http(s) URLs in index.html", not re.search(r'(src|href)="https?://', html))
built_js = js.read_text(encoding="utf-8")
check("no external fetches in the JS bundle", not re.search(r'fetch\(\s*["\']https?://', built_js))
csp = client.get("/").headers.get("content-security-policy", "")
check("CSP header present", "script-src 'self'" in csp and "style-src 'self'" in csp)

# ---- Public mode keeps /docs hidden; legacy page still there ----
check("/legacy serves the old page", client.get("/legacy").status_code == 200)

# ---- /me reads only the token ----
r = client.post("/login", json={"user_id": "CLERK1", "password": "demo"})
check("login works", r.status_code == 200)
token = r.json()["token"]
auth = {"Authorization": f"Bearer {token}"}
r = client.get("/me", headers=auth)
check("/me returns sub/role/branch/exp", r.status_code == 200 and r.json()["sub"] == "CLERK1"
      and r.json()["role"] == "CLERK" and r.json()["branch"] == "CHN01" and isinstance(r.json()["exp"], int), r.text)
check("/me without a token is 401", client.get("/me").status_code == 401)
check("/me with a bad token is 401", client.get("/me", headers={"Authorization": "Bearer nope"}).status_code == 401)

# ---- stage field ----
def ask(q="Show details of customer 1001"):
    r = client.post("/ask", json={"question": q}, headers=auth)
    return r.status_code, r.json()


code, body = ask()
check("allowed: stage is null", code == 200 and body["decision"] == "ALLOWED" and body["stage"] is None, body)

code, body = ask("Change the mobile number of customer 1001")
check("write request: stage guard", body["decision"] == "BLOCKED" and body["stage"] == "guard", body)

state["intent"] = False
code, body = ask()
check("intent block: stage intent", body["decision"] == "BLOCKED" and body["stage"] == "intent", body)
state["intent"] = True

state["tool"] = "get_customer"
code, body = ask("Show me the customer details please")  # no customer number -> guard
check("missing customer number: stage guard", body["stage"] == "guard", body)

state["denied"] = True
code, body = ask()
check("Db2 denial: stage db2", body["decision"] == "BLOCKED" and body["stage"] == "db2", body)
state["denied"] = False

state["rows"] = [{"CUST_ID": i} for i in range(5)]
code, body = ask()
check("too many rows: stage volume", body["decision"] == "BLOCKED" and body["stage"] == "volume", body)
state["rows"] = [{"CUST_ID": 1001}]

# ---- /logs: Db2 refusal carries stage db2, detail stays a string ----
state["denied"] = True
r = client.get("/logs", headers=auth)
check("/logs 403 with stage db2", r.status_code == 403 and r.json()["stage"] == "db2"
      and isinstance(r.json()["detail"], str), r.text)
state["denied"] = False

print()
print("ALL PASSED" if not failures else f"FAILED: {failures}")
sys.exit(1 if failures else 0)
