import { useRef, useState, type FormEvent } from "react";
import { Navigate } from "react-router-dom";
import {
  ApiError,
  forgetCustomer,
  getPrivacy,
  removeCopy,
  type ForgetResult,
  type PrivacyView,
  type Proofs,
  type RemovalReason,
  type RemoveResult,
} from "../api";
import { useSession } from "../session";

const REASONS: { value: RemovalReason; label: string }[] = [
  { value: "poisoned", label: "Poisoned (hidden instructions found later)" },
  { value: "wrong_customer", label: "Saved to the wrong customer" },
  { value: "duplicate", label: "Duplicate" },
];

const day = (epoch: number | null) =>
  epoch ? new Date(epoch * 1000).toLocaleDateString("en-IN", { year: "numeric", month: "short", day: "numeric" }) : "-";

function yesNo(ok: boolean) {
  return <span className={ok ? "tag-allow" : "tag-block"}>{ok ? "✓ Yes" : "✕ No"}</span>;
}

function ProofRows({ proofs }: { proofs: Proofs }) {
  return (
    <>
      <tr><td>Signature ({proofs.signature_algorithm}, quantum-safe)</td><td>{yesNo(proofs.signature_valid)}</td></tr>
      <tr><td>Recorded in the public transparency log</td>
        <td>{yesNo(proofs.in_transparency_log)} <span className="muted">entry {proofs.log_index} of {proofs.log_size}</span></td></tr>
      <tr><td>Signing key</td><td className="mono">{proofs.signer_key_id}</td></tr>
    </>
  );
}

function ForgetCertificate({ out }: { out: ForgetResult }) {
  const held = out.status === "refused_legal_hold";
  const s = out.summary;
  return (
    <section className="card result" aria-label="Erasure certificate">
      <div className="result-head">
        <span className={`badge ${held ? "badge-block" : "badge-allow"}`}>
          <span aria-hidden="true">{held ? "✕" : "✓"}</span> {held ? "REFUSED: LEGAL HOLD" : out.status.toUpperCase().replace(/_/g, " ")}
        </span>
        <p className="answer">Certificate {out.request_id}</p>
      </div>
      {held && <p className="doc-warning">{out.reason}</p>}
      <div className="table-wrap" role="region" aria-label="Certificate details" tabIndex={0}>
        <table>
          <tbody>
            {s && (
              <>
                <tr><td>AI copies erased</td><td>{s.copies_erased}{s.copies_failed > 0 && ` (${s.copies_failed} failed)`}</td></tr>
                <tr><td>Customer key</td><td>{s.key_state}</td></tr>
                <tr><td>Text recovered from stored embeddings (token F1, before → after)</td>
                  <td>{s.inversion_f1_before} → {s.inversion_f1_after} <span className="muted">(random noise: {s.noise_baseline_f1})</span></td></tr>
                <tr><td>Can an attacker tell the customer was here? (before → after)</td>
                  <td>{s.customer_detected_before ? "yes" : "no"} → {s.customer_detected_after ? "yes" : "no"}</td></tr>
                <tr><td>Customer identifiers recovered after erasure</td>
                  <td>{s.identifiers_recovered.length === 0 ? "none" : s.identifiers_recovered.join(", ")}</td></tr>
                <tr><td>Readable leftovers in vault files</td>
                  <td>{s.residue_leaks} in {s.residue_files_scanned} files</td></tr>
                {s.not_verifiable.length > 0 && (
                  <tr><td>Could not be verified from here</td><td>{s.not_verifiable.join(", ")}</td></tr>
                )}
              </>
            )}
            <ProofRows proofs={out.proofs} />
          </tbody>
        </table>
      </div>
      <details className="doc-details">
        <summary>Show the signed certificate</summary>
        <pre className="doctext">{JSON.stringify(out.certificate, null, 2)}</pre>
      </details>
    </section>
  );
}

function RemovalRecord({ out }: { out: RemoveResult }) {
  return (
    <section className="card result" aria-label="Removal record">
      <div className="result-head">
        <span className={`badge ${out.status === "removed" ? "badge-allow" : "badge-block"}`}>
          {out.status.toUpperCase()}
        </span>
        <p className="answer">Removal record {out.request_id}</p>
      </div>
      <div className="table-wrap" role="region" aria-label="Removal details" tabIndex={0}>
        <table>
          <tbody>
            {out.copies.map((c) => (
              <tr key={c.copy_id}><td className="mono">{c.copy_id}</td><td>{c.result}: {c.evidence}</td></tr>
            ))}
            <ProofRows proofs={out.proofs} />
          </tbody>
        </table>
      </div>
      <p className="muted small">The customer&apos;s other copies are untouched.</p>
    </section>
  );
}

export function PrivacyPage() {
  const { session, signOut, touch } = useSession();
  const [customer, setCustomer] = useState("");
  const [view, setView] = useState<PrivacyView | null>(null);
  const [verified, setVerified] = useState(false);
  const [confirm, setConfirm] = useState("");
  const [reasons, setReasons] = useState<Record<string, RemovalReason>>({});
  const [forgot, setForgot] = useState<ForgetResult | null>(null);
  const [removed, setRemoved] = useState<RemoveResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);

  if (!session) return <Navigate to="/signin" replace />;
  if (session.user.role !== "MANAGER") {
    return (
      <section className="card prose">
        <h1>Customer privacy</h1>
        <p>Viewing and erasing a customer&apos;s AI data is for branch managers only.</p>
      </section>
    );
  }
  const token = session.token;

  async function run<T>(call: () => Promise<T>): Promise<T | null> {
    if (inFlight.current) return null;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    touch();
    try {
      return await call();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        signOut("Your session is no longer valid. Please sign in again.");
        return null;
      }
      setError(err instanceof ApiError ? err.message : "Something went wrong. Please try again.");
      return null;
    } finally {
      inFlight.current = false;
      setBusy(false);
      touch();
    }
  }

  async function lookUp(e?: FormEvent) {
    e?.preventDefault();
    if (!/^\d{4}$/.test(customer)) {
      setError("Enter a 4-digit customer number.");
      return;
    }
    setForgot(null);
    setRemoved(null);
    const v = await run(() => getPrivacy(token, customer));
    if (v) setView(v);
  }

  async function doForget() {
    if (!view) return;
    const out = await run(() => forgetCustomer(token, view.customer, confirm));
    if (out) {
      setForgot(out);
      setVerified(false);
      setConfirm("");
      const v = await run(() => getPrivacy(token, view.customer));
      if (v) setView(v);
    }
  }

  async function doRemove(copyId: string) {
    if (!view) return;
    const out = await run(() => removeCopy(token, view.customer, copyId, reasons[copyId] ?? "poisoned"));
    if (out) {
      setRemoved(out);
      const v = await run(() => getPrivacy(token, view.customer));
      if (v) setView(v);
    }
  }

  const expected = view ? `FORGET ${view.customer}` : "";
  const canForget = !!view && view.key_state === "ACTIVE" && verified && confirm.trim().toUpperCase() === expected && !busy;

  return (
    <div className="docs">
      <section className="card" aria-labelledby="privacy-title">
        <h1 id="privacy-title">Customer privacy</h1>
        <p className="muted">
          AI copies about a customer are kept encrypted under that customer&apos;s own quantum-safe key. You can see what
          is held (never the content), remove one bad copy, or erase everything when the customer asks. Db2 decides which
          customers you can see. Legal holds are set by the auditor, not here.
        </p>
        <form onSubmit={(e) => void lookUp(e)} className="row">
          <label htmlFor="privacy-customer" className="sr-only">Customer number</label>
          <input id="privacy-customer" className="input-short" inputMode="numeric" maxLength={4}
            placeholder="Customer number, e.g. 1002" value={customer} disabled={busy}
            onChange={(e) => setCustomer(e.target.value.replace(/\D/g, ""))} />
          <button className="btn btn-primary" type="submit" disabled={busy || customer.length !== 4}>Look up</button>
          {busy && <span className="muted" role="status"><span className="spinner" aria-hidden="true" /> Working…</span>}
        </form>
        {error && <p className="error" role="alert">{error}</p>}
      </section>

      {view && (
        <section className="card" aria-label="AI copies held">
          <h2>Customer {view.customer}</h2>
          <dl className="meta">
            <div><dt>Key</dt><dd>{view.key_state === "NONE" ? "no AI copies held" : `${view.key_state} · ${view.key}`}</dd></div>
            <div><dt>Legal hold</dt><dd>{view.legal_hold ? <span className="tag-block">ON (set by the auditor)</span> : "off"}</dd></div>
          </dl>
          {view.copies.length > 0 && (
            <div className="table-wrap" role="region" aria-label="AI copies" tabIndex={0}>
              <table>
                <thead>
                  <tr><th scope="col">Copy</th><th scope="col">Saved</th><th scope="col">Keep until</th>
                    <th scope="col">Status</th><th scope="col">Remove one copy</th></tr>
                </thead>
                <tbody>
                  {view.copies.map((c) => (
                    <tr key={c.copy_id}>
                      <td>{c.kind}<br /><span className="mono muted">{c.copy_id}</span></td>
                      <td>{day(c.created_at)}</td>
                      <td>{day(c.retention_until)}{c.retention_class && <span className="muted"> ({c.retention_class})</span>}</td>
                      <td className={c.status === "encrypted" ? undefined : "muted"}>{c.status}</td>
                      <td>
                        {c.status === "encrypted" && view.key_state === "ACTIVE" && (
                          <div className="row">
                            <label htmlFor={`reason-${c.copy_id}`} className="sr-only">Reason</label>
                            <select id={`reason-${c.copy_id}`} value={reasons[c.copy_id] ?? "poisoned"} disabled={busy}
                              onChange={(e) => setReasons({ ...reasons, [c.copy_id]: e.target.value as RemovalReason })}>
                              {REASONS.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
                            </select>
                            <button className="btn btn-ghost" type="button" disabled={busy}
                              onClick={() => void doRemove(c.copy_id)}>Remove</button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {view.key_state === "ACTIVE" && (
            <div className="forget-box">
              <h3>Forget this customer</h3>
              <p className="muted small">
                Destroys the customer&apos;s key, so every AI copy becomes unreadable at once. ZVault then attacks its own
                storage to prove nothing can be recovered and issues a signed certificate. Core banking records in Db2
                are not touched.
              </p>
              <label className="check">
                <input type="checkbox" checked={verified} disabled={busy} onChange={(e) => setVerified(e.target.checked)} />
                The customer&apos;s identity was verified in the branch
              </label>
              <label htmlFor="forget-confirm">Type <span className="mono">{expected}</span> to confirm</label>
              <input id="forget-confirm" className="input-short" value={confirm} disabled={busy}
                onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />
              <div className="row doc-actions">
                <button className="btn btn-danger" type="button" disabled={!canForget} onClick={() => void doForget()}>
                  Forget customer
                </button>
              </div>
            </div>
          )}
        </section>
      )}

      {forgot && <ForgetCertificate out={forgot} />}
      {removed && <RemovalRecord out={removed} />}
    </div>
  );
}
