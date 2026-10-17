import { describe, expect, it } from "vitest";
import { LAYERS, trailStates } from "../trail";

describe("trailStates", () => {
  it("marks every layer passed for an allowed request with rows", () => {
    expect(trailStates("ALLOWED", null, 3)).toEqual(Array(LAYERS.length).fill("pass"));
  });

  it("flags the Db2 layer when an allowed request returned no rows", () => {
    const s = trailStates("ALLOWED", null, 0)!;
    expect(s[LAYERS.findIndex((l) => l.id === "db2")]).toBe("note");
  });

  it.each([
    ["guard", 2],
    ["intent", 3],
    ["tool", 4],
    ["db2", 5],
    ["volume", 6],
  ] as const)("stage %s stops at layer %i, passes earlier ones, skips later ones", (stage, index) => {
    const s = trailStates("BLOCKED", stage, 0)!;
    expect(s[index]).toBe("stop");
    expect(s.slice(0, index).every((x) => x === "pass")).toBe(true);
    expect(s.slice(index + 1).every((x) => x === "skipped")).toBe(true);
  });

  it("returns null for a blocked request with no stage (no guessing)", () => {
    expect(trailStates("BLOCKED", undefined, 0)).toBeNull();
    expect(trailStates("BLOCKED", null, 0)).toBeNull();
  });
});
