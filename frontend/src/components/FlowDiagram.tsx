interface Step {
  title: string;
  lines: [string, string];
  ai?: boolean;
  db?: boolean;
}

const STEPS: Step[] = [
  { title: "Employee", lines: ["signs in and gets a", "15-minute token"] },
  { title: "Gateway", lines: ["checks the token", "and the abuse limits"] },
  { title: "Granite (AI)", lines: ["sees only the question", "and picks ONE tool name"], ai: true },
  { title: "Plain-code rules", lines: ["pull out the values and", "can only block, never grant"] },
  { title: "Db2 on IBM Z", lines: ["runs fixed SQL as this", "employee: rows and masks"], db: true },
  { title: "Employee", lines: ["gets the rows directly,", "branch-filtered, masked"] },
];

const BOX_W = 138;
const GAP = 22;
const BOX_H = 92;
const TOP = 36;

export function FlowDiagram() {
  const width = STEPS.length * BOX_W + (STEPS.length - 1) * GAP + 20;
  return (
    <svg className="flow" viewBox={`0 0 ${width} 220`} role="img" aria-labelledby="flow-title flow-desc">
      <title id="flow-title">How a question travels through ZVault</title>
      <desc id="flow-desc">
        The employee signs in and the gateway checks the token. Granite picks one read-only tool name.
        Plain-code rules can only block. Db2 runs fixed SQL as the real employee, applying branch row rules and
        column masks. The rows go straight to the employee and never pass through the AI.
      </desc>
      {STEPS.map((s, i) => {
        const x = 10 + i * (BOX_W + GAP);
        const cls = s.ai ? "flow-box flow-ai" : s.db ? "flow-box flow-db" : "flow-box";
        return (
          <g key={i}>
            <rect className={cls} x={x} y={TOP} width={BOX_W} height={BOX_H} rx="8" />
            <text className="flow-title" x={x + BOX_W / 2} y={TOP + 28} textAnchor="middle">{s.title}</text>
            <text className="flow-line" x={x + BOX_W / 2} y={TOP + 52} textAnchor="middle">{s.lines[0]}</text>
            <text className="flow-line" x={x + BOX_W / 2} y={TOP + 70} textAnchor="middle">{s.lines[1]}</text>
            {i < STEPS.length - 1 && (
              <path className="flow-arrow" d={`M${x + BOX_W + 3} ${TOP + BOX_H / 2} h${GAP - 6}`} markerEnd="url(#arrow)" />
            )}
          </g>
        );
      })}
      <defs>
        <marker id="arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
          <path className="flow-head" d="M0 0 L8 4 L0 8 z" />
        </marker>
      </defs>
      {/* The AI is not on the data path. */}
      <path
        className="flow-bypass"
        d={`M${10 + 4 * (BOX_W + GAP) + BOX_W / 2} ${TOP + BOX_H + 6} v34 h${BOX_W + GAP} v-34`}
        markerEnd="url(#arrow)"
      />
      <text className="flow-note" x={10 + 4 * (BOX_W + GAP) + BOX_W / 2 + (BOX_W + GAP) / 2} y={TOP + BOX_H + 62} textAnchor="middle">
        The AI never sees these rows
      </text>
    </svg>
  );
}
