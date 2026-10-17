// Session timing: a 15-minute idle limit (sign out after inactivity) on top of the
// 15-minute token, which stays the hard limit. Pure functions so they are easy to test.
export const IDLE_LIMIT_MS = 15 * 60 * 1000;

export interface SessionClock {
  idleLeftMs: number;
  tokenLeftMs: number;
  /** Which limit ended the session first, or null while it is still valid. */
  expired: "idle" | "token" | null;
}

export function sessionClock(now: number, lastActivity: number, tokenExpiresAt: number): SessionClock {
  const idleLeftMs = Math.max(0, lastActivity + IDLE_LIMIT_MS - now);
  const tokenLeftMs = Math.max(0, tokenExpiresAt - now);
  const expired = tokenLeftMs === 0 ? "token" : idleLeftMs === 0 ? "idle" : null;
  return { idleLeftMs, tokenLeftMs, expired };
}

export function formatClock(ms: number): string {
  const total = Math.ceil(ms / 1000);
  const m = Math.floor(total / 60);
  const s = String(total % 60).padStart(2, "0");
  return `${m}:${s}`;
}
