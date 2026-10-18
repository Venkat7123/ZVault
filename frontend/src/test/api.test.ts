import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, ask, getMe, login, readAuditLog, scanDocument } from "../api";

function reply(status: number, body: unknown) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });
}

afterEach(() => vi.unstubAllGlobals());

describe("api client", () => {
  it("login posts credentials and returns the token", async () => {
    const f = reply(200, { token: "t", expires_in_minutes: 15 });
    vi.stubGlobal("fetch", f);
    await expect(login("CLERK1", "pw")).resolves.toEqual({ token: "t", expires_in_minutes: 15 });
    const [url, init] = f.mock.calls[0];
    expect(url).toBe("/login");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toEqual({ user_id: "CLERK1", password: "pw" });
    expect(init.headers.Authorization).toBeUndefined();
  });

  it("sends the bearer token on /me", async () => {
    const f = reply(200, { sub: "CLERK1", role: "CLERK", branch: "CHN01", exp: 1 });
    vi.stubGlobal("fetch", f);
    await getMe("abc");
    expect(f.mock.calls[0][0]).toBe("/me");
    expect(f.mock.calls[0][1].headers.Authorization).toBe("Bearer abc");
  });

  it("turns a 401 into an ApiError with the server message", async () => {
    vi.stubGlobal("fetch", reply(401, { detail: "Invalid user or password" }));
    await expect(login("CLERK1", "bad")).rejects.toMatchObject({ status: 401, message: "Invalid user or password" });
  });

  it("keeps 429 messages and survives non-JSON error bodies", async () => {
    vi.stubGlobal("fetch", reply(429, { detail: "Too many questions. Please wait a minute." }));
    await expect(ask("t", "hello there")).rejects.toMatchObject({ status: 429 });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => {
          throw new Error("not json");
        },
      }),
    );
    await expect(ask("t", "hello there")).rejects.toMatchObject({
      status: 500,
      message: "The request failed (HTTP 500).",
    });
  });

  it("reports a network failure as status 0", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("fetch failed")));
    const err = await login("a", "b").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(0);
  });

  it("readAuditLog turns the Db2 403 into a blocked result at stage db2", async () => {
    vi.stubGlobal("fetch", reply(403, { detail: "Db2 denied: only auditors", stage: "db2" }));
    await expect(readAuditLog("t")).resolves.toMatchObject({
      decision: "BLOCKED",
      stage: "db2",
      tool: "read_logs",
      rows: [],
    });
  });

  it("readAuditLog treats a 403 without a stage as an error", async () => {
    vi.stubGlobal("fetch", reply(403, { detail: "nope" }));
    await expect(readAuditLog("t")).rejects.toBeInstanceOf(ApiError);
  });
});

describe("document upload", () => {
  it("posts the file as form data with the bearer token and no JSON content type", async () => {
    const f = reply(200, { verdict: "CLEAN", sha256: "a", pages: 1, findings: [], fields: [], visible_text: "", note: "" });
    vi.stubGlobal("fetch", f);
    const file = new File(["%PDF-1.7"], "loan.pdf", { type: "application/pdf" });
    await expect(scanDocument("abc", file)).resolves.toMatchObject({ verdict: "CLEAN" });
    const [url, init] = f.mock.calls[0];
    expect(url).toBe("/documents/scan");
    expect(init.method).toBe("POST");
    expect(init.headers.Authorization).toBe("Bearer abc");
    expect(init.headers["Content-Type"]).toBeUndefined();
    expect(init.body).toBeInstanceOf(FormData);
    expect((init.body as FormData).get("file")).toBe(file);
  });

  it("turns a 400 into an ApiError with the server message", async () => {
    vi.stubGlobal("fetch", reply(400, { detail: "Document not accepted: only PDF files are accepted" }));
    await expect(scanDocument("abc", new File(["x"], "x.txt"))).rejects.toMatchObject({
      status: 400, message: "Document not accepted: only PDF files are accepted" });
  });
});
