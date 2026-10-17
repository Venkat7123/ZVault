import type { Decision, Stage } from "./api";

export interface Layer {
  id: string;
  label: string;
  /** Present only for layers that can stop a request. */
  stage?: Stage;
}

// Order matches the gateway's request flow (main.py).
export const LAYERS: Layer[] = [
  { id: "token", label: "Signed-in token verified (15 minutes, signed by the gateway)" },
  { id: "route", label: "Granite chose one read-only tool and never writes SQL" },
  { id: "guard", label: "Rule check: write words, one customer vs a list, customer number", stage: "guard" },
  { id: "intent", label: "Granite intent check (it can only block)", stage: "intent" },
  { id: "tool", label: "Fixed SQL with checked values; free text never reaches Db2", stage: "tool" },
  { id: "db2", label: "Db2 ran it as this employee: branch rows and column masks", stage: "db2" },
  { id: "volume", label: "Volume check: no more rows than this tool should return", stage: "volume" },
];

export type StepState = "pass" | "stop" | "skipped" | "note";

/**
 * Per-layer state for the SecurityTrail. Uses ONLY the gateway's `stage` field.
 * A blocked request without a stage returns null: we do not guess from reason text.
 */
export function trailStates(decision: Decision, stage: Stage | null | undefined, rowCount: number): StepState[] | null {
  if (decision === "ALLOWED") {
    return LAYERS.map((l) => (l.id === "db2" && rowCount === 0 ? "note" : "pass"));
  }
  const stopAt = LAYERS.findIndex((l) => l.stage !== undefined && l.stage === stage);
  if (stopAt < 0) return null;
  return LAYERS.map((_, i) => (i < stopAt ? "pass" : i === stopAt ? "stop" : "skipped"));
}
