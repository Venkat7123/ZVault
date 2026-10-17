import { useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { ApiError } from "../api";
import { DEMO_EMPLOYEES } from "../branches";
import { useSession } from "../session";

function messageFor(err: unknown, userId: string): string {
  if (err instanceof ApiError) {
    if (err.status === 401) {
      return userId === "AUDITOR1"
        ? "Sign-in refused, as expected. Auditors can see every branch, so they never use the AI assistant. They read the audit log directly in Db2."
        : "Sign-in refused: invalid user or password.";
    }
    if (err.status === 429) return err.message;
    if (err.status === 0) return err.message;
  }
  return "Sign-in failed. Please try again.";
}

export function SignInPage() {
  const { session, notice, signIn, clearNotice } = useSession();
  const navigate = useNavigate();
  const [userId, setUserId] = useState<string>(DEMO_EMPLOYEES[0].id);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (session) return <Navigate to="/assistant" replace />;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    clearNotice();
    try {
      await signIn(userId, password);
      navigate("/assistant");
    } catch (err) {
      setError(messageFor(err, userId));
    } finally {
      setPassword("");
      setBusy(false);
    }
  }

  return (
    <section className="center">
      <form className="card signin" onSubmit={submit}>
        <h1>Employee sign in</h1>
        <p className="muted">Db2 decides what each employee can see. The AI holds no master key.</p>

        {notice && <p className="notice" role="status">{notice}</p>}

        <label htmlFor="employee">
          Employee <span className="demo-flag">Demo only - real banks do not list users</span>
        </label>
        <select id="employee" value={userId} onChange={(e) => setUserId(e.target.value)}>
          {DEMO_EMPLOYEES.map((u) => <option key={u.id} value={u.id}>{u.label}</option>)}
        </select>

        <label htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <button className="btn btn-primary" type="submit" disabled={busy || password.length === 0}>
          {busy ? "Signing in" : "Sign in"}
        </button>
        {error && <p className="error" role="alert">{error}</p>}
      </form>
    </section>
  );
}
