// Typed client for the Bots Bank gateway. Same origin by default; VITE_API_BASE overrides it.
const BASE: string = import.meta.env.VITE_API_BASE ?? "";

/** The layer that stopped a request, as reported by the gateway. */
export type Stage = "guard" | "intent" | "tool" | "db2" | "volume";
export type Decision = "ALLOWED" | "BLOCKED";
export type Cell = string | number | null;
export type Row = Record<string, Cell>;

export interface LoginResult {
  token: string;
  expires_in_minutes: number;
}

export interface Me {
  sub: string;
  role: string | null;
  branch: string | null;
  exp: number | null;
}

export interface AskResult {
  decision: Decision;
  tool: string;
  args?: Record<string, string | number>;
  answer: string;
  rows: Row[];
  reason?: string;
  stage?: Stage | null;
}

/** Loan-document scan (POST /documents/scan). */
export type DocVerdict = "CLEAN" | "QUARANTINED";

export interface DocFinding {
  kind: string;
  where: string;
  detail: string;
  text: string;
}

export interface DocField {
  name: string;
  label: string;
  value: string;
  verified: boolean;
}

/** What happened to the verified summary in the quantum-safe vault (clean documents only). */
export interface DocStored {
  saved: boolean;
  customer?: string;
  reason?: string;
  copy_id?: string;
  retention_class?: string;
  retention_days?: number;
  needs_review?: boolean;
  encryption?: string;
  key?: string;
}

export interface DocResult {
  stored?: DocStored;
  verdict: DocVerdict;
  sha256: string;
  pages: number;
  findings: DocFinding[];
  fields: DocField[];
  visible_text: string;
  note: string;
}

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function send(method: string, path: string, body?: unknown, token?: string) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  let resp: Response;
  try {
    resp = await fetch(BASE + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
    });
  } catch {
    throw new ApiError(0, "Could not reach the gateway.");
  }
  let data: unknown = null;
  try {
    data = await resp.json();
  } catch {
    /* non-JSON error body */
  }
  return { status: resp.status, ok: resp.ok, data };
}

function detailOf(data: unknown, status: number): string {
  if (data && typeof data === "object" && "detail" in data) {
    const detail = (data as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
  }
  return `The request failed (HTTP ${status}).`;
}

async function json<T>(method: string, path: string, body?: unknown, token?: string): Promise<T> {
  const r = await send(method, path, body, token);
  if (!r.ok) throw new ApiError(r.status, detailOf(r.data, r.status));
  return r.data as T;
}

export const login = (userId: string, password: string) =>
  json<LoginResult>("POST", "/login", { user_id: userId, password });

export const getMe = (token: string) => json<Me>("GET", "/me", undefined, token);

export const ask = (token: string, question: string) =>
  json<AskResult>("POST", "/ask", { question }, token);

/**
 * "Open the audit log" demo. Db2 refuses it for staff (HTTP 403 with stage "db2"),
 * which we present as a blocked request. Any other outcome is an error.
 */
export async function readAuditLog(token: string): Promise<AskResult> {
  const r = await send("GET", "/logs", undefined, token);
  if (r.status === 403 && r.data && typeof r.data === "object") {
    const d = r.data as { detail?: unknown; stage?: unknown };
    if (d.stage === "db2" && typeof d.detail === "string") {
      return { decision: "BLOCKED", tool: "read_logs", answer: d.detail, reason: d.detail,
               stage: "db2", rows: [] };
    }
  }
  throw new ApiError(r.status, detailOf(r.data, r.status));
}

/** Upload one PDF. No Content-Type header: the browser sets the multipart boundary itself. */
export async function scanDocument(token: string, file: File): Promise<DocResult> {
  const form = new FormData();
  form.append("file", file);
  let resp: Response;
  try {
    resp = await fetch(BASE + "/documents/scan", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: form,
      cache: "no-store",
    });
  } catch {
    throw new ApiError(0, "Could not reach the gateway.");
  }
  let data: unknown = null;
  try {
    data = await resp.json();
  } catch {
    /* non-JSON error body */
  }
  if (!resp.ok) throw new ApiError(resp.status, detailOf(data, resp.status));
  return data as DocResult;
}

// ---------- Customer privacy (branch managers only; the gateway enforces it) ----------

export interface PrivacyCopy {
  copy_id: string;
  kind: string;
  created_at: number;
  retention_class: string | null;
  retention_until: number | null;
  status: "encrypted" | "removed" | "erased";
}

export interface PrivacyView {
  customer: string;
  key_state: string;
  legal_hold: boolean;
  key: string;
  copies: PrivacyCopy[];
}

export interface Proofs {
  signature_valid: boolean;
  tree_head_valid: boolean;
  in_transparency_log: boolean;
  log_index: number;
  log_size: number;
  signature_algorithm: string;
  signer_key_id: string;
}

export interface ForgetSummary {
  copies_erased: number;
  copies_failed: number;
  not_verifiable: string[];
  key_state: string;
  inversion_f1_before: number;
  inversion_f1_after: number;
  noise_baseline_f1: number;
  identifiers_recovered: string[];
  customer_detected_before: boolean;
  customer_detected_after: boolean;
  residue_files_scanned: number;
  residue_leaks: number;
}

export interface ForgetResult {
  request_id: string;
  status: string;
  reason?: string | null;
  summary?: ForgetSummary;
  proofs: Proofs;
  certificate: unknown;
}

export interface RemoveResult {
  request_id: string;
  status: string;
  copies: { copy_id: string; result: string; evidence: string }[];
  proofs: Proofs;
  certificate: unknown;
}

export type RemovalReason = "poisoned" | "wrong_customer" | "duplicate";

export const getPrivacy = (token: string, customer: string) =>
  json<PrivacyView>("GET", `/privacy/customers/${encodeURIComponent(customer)}`, undefined, token);

export const forgetCustomer = (token: string, customer: string, confirm: string) =>
  json<ForgetResult>("POST", `/privacy/customers/${encodeURIComponent(customer)}/forget`,
    { identity_verified: true, confirm }, token);

export const removeCopy = (token: string, customer: string, copyId: string, reason: RemovalReason) =>
  json<RemoveResult>("POST",
    `/privacy/customers/${encodeURIComponent(customer)}/copies/${encodeURIComponent(copyId)}/remove`,
    { reason }, token);
