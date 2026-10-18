import { useRef, useState, type FormEvent } from "react";
import { Navigate } from "react-router-dom";
import { ApiError, scanDocument, type DocResult } from "../api";
import { useSession } from "../session";

const MAX_BYTES = 2 * 1024 * 1024;

// Plain-language names for what the scan found. Unknown kinds are shown as they are.
const KIND_LABELS: Record<string, string> = {
  hidden_white_text: "Hidden white text",
  hidden_tiny_text: "Hidden tiny text",
  hidden_offpage_text: "Text placed off the page",
  hidden_invisible_mode: "Text drawn invisibly",
  invisible_characters: "Invisible characters",
  metadata_instructions: "Instructions in the file details",
  annotation_text: "Hidden comment",
  active_content: "Active content",
  instruction_phrases: "Instruction aimed at an AI",
  ai_check: "Flagged by Granite",
};

function VerdictBadge({ verdict }: { verdict: DocResult["verdict"] }) {
  const clean = verdict === "CLEAN";
  return (
    <span className={`badge ${clean ? "badge-allow" : "badge-block"}`}>
      <span aria-hidden="true">{clean ? "✓" : "✕"}</span> {verdict}
    </span>
  );
}

export function DocumentsPage() {
  const { session, signOut, touch } = useSession();
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<DocResult | null>(null);
  const [checkedName, setCheckedName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);

  if (!session) return <Navigate to="/signin" replace />;
  const token = session.token;

  function choose(f: File | null) {
    setError(null);
    if (f && f.size > MAX_BYTES) {
      setFile(null);
      setError("This file is larger than 2 MB.");
      return;
    }
    setFile(f);
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!file || inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    setResult(null);
    touch();
    try {
      setResult(await scanDocument(token, file));
      setCheckedName(file.name);
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

  return (
    <div className="docs">
      <section className="card" aria-labelledby="docs-title">
        <h1 id="docs-title">Loan documents</h1>
        <p className="muted">
          ZVault checks a document for hidden instructions before any AI reads it. If anything is found, the
          document is quarantined and the AI never sees it. The file is not stored.
        </p>
        <form onSubmit={(e) => void submit(e)}>
          <label htmlFor="doc-file">Loan application (PDF, up to 2 MB, 5 pages)</label>
          <input
            id="doc-file"
            type="file"
            accept="application/pdf,.pdf"
            disabled={busy}
            onChange={(e) => choose(e.target.files?.[0] ?? null)}
          />
          <div className="row doc-actions">
            <button className="btn btn-primary" type="submit" disabled={!file || busy}>
              Check document
            </button>
            {busy && (
              <span className="muted" role="status">
                <span className="spinner" aria-hidden="true" /> Checking. The AI step can take up to a minute.
              </span>
            )}
          </div>
        </form>
      </section>

      <section className="card result" aria-live="polite" aria-label="Document result">
        {error && <p className="error" role="alert">{error}</p>}
        {!result && !error && <p className="muted">Choose a PDF and press Check document. The result appears here.</p>}
        {result && (
          <>
            <div className="result-head">
              <VerdictBadge verdict={result.verdict} />
              <p className="answer">{checkedName}</p>
            </div>
            <p className={result.verdict === "CLEAN" ? "muted" : "doc-warning"}>{result.note}</p>
            <dl className="meta">
              <div><dt>Pages</dt><dd>{result.pages}</dd></div>
              <div><dt>Fingerprint</dt><dd className="mono">sha256 {result.sha256}…</dd></div>
            </dl>

            {result.verdict === "QUARANTINED" ? (
              <div className="doc-compare">
                <div>
                  <h2>What a person sees</h2>
                  <pre className="doctext">{result.visible_text || "(no visible text)"}</pre>
                </div>
                <div>
                  <h2>Hidden content found</h2>
                  <ul className="findings">
                    {result.findings.map((f, i) => (
                      <li key={i} className="finding">
                        <p className="finding-head">
                          <span className="tag-block">{KIND_LABELS[f.kind] ?? f.kind}</span>
                          <span className="muted"> · {f.where}</span>
                        </p>
                        <p className="small muted">{f.detail}</p>
                        {f.text && <pre className="doctext hidden-text">{f.text}</pre>}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ) : (
              <>
                <h2>Summary (filled by Granite, checked by code)</h2>
                <div className="table-wrap" role="region" aria-label="Document summary" tabIndex={0}>
                  <table>
                    <thead>
                      <tr><th scope="col">Field</th><th scope="col">Value</th><th scope="col">In document</th></tr>
                    </thead>
                    <tbody>
                      {result.fields.map((f) => (
                        <tr key={f.name}>
                          <td>{f.label}</td>
                          <td className={f.verified ? undefined : "muted"}>
                            {f.verified ? f.value : "Not found in the document"}
                          </td>
                          <td className={f.verified ? "tag-allow" : "muted"}>{f.verified ? "✓ Yes" : "No"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <details className="doc-details">
                  <summary>Show the document text</summary>
                  <pre className="doctext">{result.visible_text}</pre>
                </details>
              </>
            )}
          </>
        )}
      </section>
    </div>
  );
}
