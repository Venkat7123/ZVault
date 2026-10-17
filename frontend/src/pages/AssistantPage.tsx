import { useRef, useState } from "react";
import { Navigate } from "react-router-dom";
import { ApiError, ask, readAuditLog, type AskResult } from "../api";
import { DecisionBadge } from "../components/DecisionBadge";
import { ExamplePicker } from "../components/ExamplePicker";
import { HistoryList } from "../components/HistoryList";
import { QuestionBox } from "../components/QuestionBox";
import { ResultTable } from "../components/ResultTable";
import { SecurityTrail } from "../components/SecurityTrail";
import { useSession } from "../session";

interface Shown {
  question: string;
  result: AskResult;
}

export function AssistantPage() {
  const { session, history, signOut, touch, addHistory } = useSession();
  const [question, setQuestion] = useState("");
  const [busy, setBusy] = useState(false);
  const [shown, setShown] = useState<Shown | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);

  if (!session) return <Navigate to="/signin" replace />;
  const token = session.token;

  async function run(label: string, call: () => Promise<AskResult>) {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    touch();
    try {
      const result = await call();
      setShown({ question: label, result });
      addHistory({ question: label, decision: result.decision, rowCount: result.rows.length });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        signOut("Your session is no longer valid. Please sign in again.");
        return;
      }
      setError(err instanceof ApiError ? err.message : "Something went wrong. Please try again.");
    } finally {
      inFlight.current = false;
      setBusy(false);
      touch();
    }
  }

  const doAsk = (q: string) => run(q, () => ask(token, q));
  const pick = (q: string) => {
    setQuestion(q);
    void doAsk(q);
  };

  return (
    <div className="assistant">
      <section className="card" aria-labelledby="ask-title">
        <h1 id="ask-title" className="sr-only">Assistant</h1>
        <QuestionBox busy={busy} value={question} onChange={setQuestion} onAsk={(q) => void doAsk(q)} />
        <ExamplePicker
          disabled={busy}
          onPick={pick}
          onAuditLog={() => void run("Open the audit log", () => readAuditLog(token))}
        />
      </section>

      <section className="card result" aria-live="polite" aria-label="Result">
        {error && <p className="error" role="alert">{error}</p>}
        {!shown && !error && <p className="muted">Ask a question or pick an example. The result appears here.</p>}
        {shown && (
          <>
            <div className="result-head">
              <DecisionBadge decision={shown.result.decision} />
              <p className="answer">{shown.result.answer}</p>
            </div>
            <dl className="meta">
              <div><dt>Question</dt><dd>{shown.question}</dd></div>
              <div><dt>Tool</dt><dd>{shown.result.tool}</dd></div>
              {shown.result.args && Object.keys(shown.result.args).length > 0 && (
                <div>
                  <dt>Values</dt>
                  <dd>{Object.entries(shown.result.args).map(([k, v]) => `${k}=${v}`).join(", ")}</dd>
                </div>
              )}
              {shown.result.decision === "BLOCKED" && shown.result.reason && (
                <div><dt>Reason</dt><dd>{shown.result.reason}</dd></div>
              )}
            </dl>

            <h2>Security checks</h2>
            <SecurityTrail result={shown.result} />

            {shown.result.rows.length > 0 && (
              <>
                <h2>Rows returned by Db2</h2>
                <ResultTable rows={shown.result.rows} />
                <p className="muted small">
                  The AI never sees these rows. Branch filtering and masking (XXXX) are done by Db2 itself for the
                  signed-in employee.
                </p>
              </>
            )}
          </>
        )}
      </section>

      <aside className="card history-card" aria-labelledby="history-title">
        <h2 id="history-title">This session</h2>
        <HistoryList items={history} />
      </aside>
    </div>
  );
}
