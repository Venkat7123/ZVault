import type { Cell, Row } from "../api";

// Every value is rendered as a plain text child: React escapes it, nothing is parsed as HTML.
function show(value: Cell): { text: string; masked: boolean; numeric: boolean } {
  if (typeof value === "number") {
    return { text: value.toLocaleString("en-IN", { maximumFractionDigits: 2 }), masked: false, numeric: true };
  }
  const text = value === null ? "" : String(value);
  return { text, masked: text.includes("XXXX"), numeric: false };
}

export function ResultTable({ rows }: { rows: Row[] }) {
  if (rows.length === 0) return null;
  const columns = Object.keys(rows[0]);
  return (
    <div className="table-wrap" tabIndex={0} role="region" aria-label="Rows returned by Db2 for this employee">
      <table>
        <thead>
          <tr>{columns.map((c) => <th key={c} scope="col">{c}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>
              {columns.map((c) => {
                const v = show(row[c] ?? null);
                return (
                  <td key={c} className={v.numeric ? "num" : v.masked ? "masked" : undefined}>{v.text}</td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
