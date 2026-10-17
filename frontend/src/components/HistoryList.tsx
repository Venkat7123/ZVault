import type { HistoryItem } from "../session";

export function HistoryList({ items }: { items: HistoryItem[] }) {
  if (items.length === 0) return <p className="muted">No questions yet.</p>;
  return (
    <ul className="history">
      {items.map((h) => (
        <li key={h.id}>
          <span className={h.decision === "ALLOWED" ? "tag-allow" : "tag-block"}>{h.decision}</span>{" "}
          <span>{h.question}</span>
          {h.decision === "ALLOWED" && (
            <span className="muted"> ({h.rowCount} {h.rowCount === 1 ? "row" : "rows"})</span>
          )}
        </li>
      ))}
    </ul>
  );
}
