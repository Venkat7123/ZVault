import type { Decision } from "../api";

export function DecisionBadge({ decision }: { decision: Decision }) {
  const allowed = decision === "ALLOWED";
  return (
    <span className={`badge ${allowed ? "badge-allow" : "badge-block"}`}>
      <span aria-hidden="true">{allowed ? "✓" : "✕"}</span> {decision}
    </span>
  );
}
