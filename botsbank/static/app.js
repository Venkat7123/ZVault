// app.js - Bots Bank assistant web page.
// The token is kept in memory only (not in browser storage): reloading the
// page signs the employee out. All data is shown with textContent, never as
// HTML, so nothing in a question or a row can run as code in the page.
"use strict";

const $ = (id) => document.getElementById(id);
let token = null;
let expiresAt = 0;
let timer = null;

const ROLES = {
  CLERK1: "Clerk, Chennai (CHN01)",
  CLERK2: "Clerk, Mumbai (MUM01)",
  MANAGER1: "Manager, Chennai (CHN01)",
};

// ---------- HTTP ----------
async function api(method, path, body) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const resp = await fetch(path, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data;
  try { data = await resp.json(); } catch { data = { detail: `HTTP ${resp.status}` }; }
  return { status: resp.status, data };
}

// ---------- Login / logout ----------
$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const user = $("user").value;
  const err = $("login-error");
  err.classList.add("hidden");
  const { status, data } = await api("POST", "/login", {
    user_id: user, password: $("password").value,
  });
  $("password").value = "";
  if (status !== 200) {
    err.textContent = user === "AUDITOR1" && status === 401
      ? "Sign-in refused (expected). Auditors can see every branch, so they can never use the AI assistant. They read the audit log directly in Db2."
      : `Sign-in refused: ${data.detail || "invalid user or password"}`;
    err.classList.remove("hidden");
    return;
  }
  token = data.token;
  expiresAt = Date.now() + data.expires_in_minutes * 60 * 1000;
  $("whoami").textContent = `Signed in as ${user} · ${ROLES[user] || ""}`;
  $("login-view").classList.add("hidden");
  $("app-view").classList.remove("hidden");
  $("session").classList.remove("hidden");
  $("history").replaceChildren(li("No questions yet.", "muted"));
  $("result").classList.add("hidden");
  timer = setInterval(tick, 1000);
  tick();
  $("question").focus();
});

function logout(message) {
  token = null;
  clearInterval(timer);
  $("app-view").classList.add("hidden");
  $("session").classList.add("hidden");
  $("login-view").classList.remove("hidden");
  const err = $("login-error");
  if (message) { err.textContent = message; err.classList.remove("hidden"); }
  else err.classList.add("hidden");
}
$("logout").addEventListener("click", () => logout());

function tick() {
  const left = Math.max(0, Math.round((expiresAt - Date.now()) / 1000));
  const m = Math.floor(left / 60), s = String(left % 60).padStart(2, "0");
  $("countdown").textContent = `token expires in ${m}:${s}`;
  if (left === 0) logout("Your 15-minute token expired. Please sign in again.");
}

// ---------- Asking ----------
$("ask-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const q = $("question").value.trim();
  if (q.length >= 3) ask(q);
});

document.querySelectorAll(".chip").forEach((chip) => {
  if (chip.id === "logs-btn") return;
  chip.addEventListener("click", () => { $("question").value = chip.textContent; ask(chip.textContent); });
});
$("logs-btn").addEventListener("click", readLogs);

function busy(on) {
  $("ask-btn").disabled = on;
  $("thinking").classList.toggle("hidden", !on);
  document.querySelectorAll(".chip").forEach((c) => { c.disabled = on; });
}

async function ask(question) {
  busy(true);
  try {
    const { status, data } = await api("POST", "/ask", { question });
    if (status === 401) return logout(data.detail || "Please sign in again.");
    if (status !== 200) {
      return show(question, { decision: "BLOCKED", tool: "-", reason: data.detail || `HTTP ${status}`,
                              answer: "The request failed.", rows: [] }, "error");
    }
    show(question, data);
  } catch (e) {
    show(question, { decision: "BLOCKED", tool: "-", reason: "gateway not reachable",
                     answer: "Could not reach the gateway.", rows: [] }, "error");
  } finally {
    busy(false);
  }
}

async function readLogs() {
  busy(true);
  try {
    const { status, data } = await api("GET", "/logs");
    if (status === 401) return logout(data.detail || "Please sign in again.");
    show("Open the audit log", {
      decision: status === 403 ? "BLOCKED" : "ALLOWED", tool: "read_logs",
      reason: "Db2 denied access for this employee",
      answer: data.detail || `HTTP ${status}`, rows: [],
    });
  } finally {
    busy(false);
  }
}

// ---------- Which security layer decided ----------
const STEPS = [
  "Signed in: token checked (15 minutes, signed by the gateway)",
  "Granite chose one read-only tool (it never writes SQL)",
  "Rule check: write words, one-customer vs list, customer number",
  "Granite intent check (can only block)",
  "Fixed SQL with checked values (no free text reaches Db2)",
  "Db2 ran it as the employee: branch rows + column masks",
  "Volume check: not more rows than this tool should return",
];

const TOOL_ERRORS = ["a valid customer number is needed", "customer number out of range",
                     "invalid balance", "invalid loan status", "unknown tool"];

function stopStep(data, kind) {
  if (kind === "error") return 1;
  if (data.decision !== "BLOCKED") return -1;
  const r = data.reason || "";
  if (r.startsWith("AI intent check")) return 3;
  if (r.startsWith("Db2 denied")) return 5;
  if (r.startsWith("returned more than")) return 6;
  if (TOOL_ERRORS.some((t) => r.startsWith(t))) return 4;
  return 2;
}

function show(question, data, kind) {
  const blocked = data.decision === "BLOCKED";
  const badge = $("badge");
  badge.textContent = blocked ? "BLOCKED" : "ALLOWED";
  badge.className = `badge ${blocked ? "blocked" : "allowed"}`;
  $("answer").textContent = data.answer || "";

  const parts = [`Question: "${question}"`, `Tool: ${data.tool || "-"}`];
  if (data.args && Object.keys(data.args).length) parts.push(`Values: ${JSON.stringify(data.args)}`);
  if (blocked) parts.push(`Reason: ${data.reason}`);
  $("meta").textContent = parts.join("  ·  ");

  // Security trail
  const stop = stopStep(data, kind);
  const rows = data.rows || [];
  const trail = STEPS.map((text, i) => {
    let cls = "pass", mark = "✓", note = text;
    if (i === 1) note = `${text}: ${data.tool || "-"}`;
    if (stop >= 0 && i === stop) { cls = "stop"; mark = "✕"; note = `${text} — stopped here`; }
    else if (stop >= 0 && i > stop) { cls = "skip"; mark = "–"; note = `${text} (not reached)`; }
    else if (stop < 0 && i === 5 && rows.length === 0) {
      cls = "note"; mark = "!"; note = `${text} — 0 rows this employee may see`;
    }
    const item = document.createElement("li");
    item.className = cls;
    item.append(span(mark, "mark"), span(note));
    return item;
  });
  $("trail").replaceChildren(...trail);

  renderRows(rows);
  $("result").classList.remove("hidden");
  addHistory(question, data.decision, rows.length);
}

function renderRows(rows) {
  const table = $("rows");
  $("rows-title").classList.toggle("hidden", rows.length === 0);
  table.parentElement.classList.toggle("hidden", rows.length === 0);
  if (!rows.length) { table.replaceChildren(); return; }
  const cols = Object.keys(rows[0]);
  const head = document.createElement("tr");
  cols.forEach((c) => { const th = document.createElement("th"); th.textContent = c; head.append(th); });
  const body = rows.map((r) => {
    const tr = document.createElement("tr");
    cols.forEach((c) => {
      const td = document.createElement("td");
      const v = r[c];
      if (typeof v === "number") {
        td.textContent = v.toLocaleString("en-IN", { maximumFractionDigits: 2 });
        td.className = "num";
      } else {
        td.textContent = v === null || v === undefined ? "" : String(v);
        if (String(v).includes("XXXX")) td.className = "masked";
      }
      tr.append(td);
    });
    return tr;
  });
  const thead = document.createElement("thead"); thead.append(head);
  const tbody = document.createElement("tbody"); tbody.append(...body);
  table.replaceChildren(thead, tbody);
}

function addHistory(question, decision, n) {
  const list = $("history");
  if (list.firstElementChild && list.firstElementChild.classList.contains("muted")) list.replaceChildren();
  const blocked = decision === "BLOCKED";
  const item = document.createElement("li");
  item.append(span(blocked ? "BLOCKED" : "ALLOWED", `d ${blocked ? "blocked" : "allowed"}`),
              span(question),
              span(blocked ? "" : ` (${n} row${n === 1 ? "" : "s"})`, "muted"));
  list.prepend(item);
}

function span(text, cls) {
  const s = document.createElement("span");
  s.textContent = text;
  if (cls) s.className = cls;
  return s;
}
function li(text, cls) {
  const l = document.createElement("li");
  l.textContent = text;
  if (cls) l.className = cls;
  return l;
}
