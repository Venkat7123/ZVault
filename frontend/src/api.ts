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
