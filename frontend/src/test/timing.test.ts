import { describe, expect, it } from "vitest";
import { formatClock, IDLE_LIMIT_MS, sessionClock } from "../timing";

const MIN = 60_000;

describe("sessionClock", () => {
  it("is valid while both limits have time left", () => {
    const c = sessionClock(5 * MIN, 0, 15 * MIN);
    expect(c.expired).toBeNull();
    expect(c.idleLeftMs).toBe(10 * MIN);
    expect(c.tokenLeftMs).toBe(10 * MIN);
  });

  it("expires on idle when the token still has time", () => {
    const c = sessionClock(IDLE_LIMIT_MS, 0, 60 * MIN);
    expect(c.expired).toBe("idle");
  });

  it("recent activity pushes the idle limit out", () => {
    const c = sessionClock(14 * MIN + 1000, 14 * MIN, 60 * MIN);
    expect(c.expired).toBeNull();
    expect(c.idleLeftMs).toBe(15 * MIN - 1000);
  });

  it("the token is a hard limit even with constant activity", () => {
    const c = sessionClock(15 * MIN, 15 * MIN - 1, 15 * MIN);
    expect(c.expired).toBe("token");
  });

  it("never goes negative", () => {
    const c = sessionClock(99 * MIN, 0, 15 * MIN);
    expect(c.idleLeftMs).toBe(0);
    expect(c.tokenLeftMs).toBe(0);
  });
});

describe("formatClock", () => {
  it("formats minutes and seconds", () => {
    expect(formatClock(0)).toBe("0:00");
    expect(formatClock(61_000)).toBe("1:01");
    expect(formatClock(15 * MIN)).toBe("15:00");
    expect(formatClock(59_001)).toBe("1:00");
  });
});
