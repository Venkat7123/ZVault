import type { AskResult } from "../api";
import { LAYERS, trailStates, type StepState } from "../trail";

const MARK: Record<StepState, { sym: string; sr: string }> = {
  pass: { sym: "✓", sr: "Passed" },
  stop: { sym: "✕", sr: "Stopped here" },
  skipped: { sym: "–", sr: "Not reached" },
  note: { sym: "!", sr: "Passed, but no rows" },
};

export function SecurityTrail({ result }: { result: AskResult }) {
  const states = trailStates(result.decision, result.stage, result.rows.length);
  if (!states) {
    return <p className="muted">The gateway did not report which layer decided, so no trail is shown.</p>;
  }
  return (
    <ol className="trail" aria-label="Security checks">
      {LAYERS.map((layer, i) => {
        const state = states[i];
        return (
          <li key={layer.id} className={`trail-${state}`}>
            <span className="trail-mark" aria-hidden="true">{MARK[state].sym}</span>
            <span className="sr-only">{MARK[state].sr}: </span>
            <span>
              {layer.label}
              {state === "stop" && " (stopped here)"}
              {state === "note" && " (0 rows this employee may see)"}
            </span>
          </li>
        );
      })}
    </ol>
  );
}
