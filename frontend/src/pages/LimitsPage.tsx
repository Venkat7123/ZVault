const LIMITS: { title: string; text: string }[] = [
  {
    title: "Tokens cannot be cancelled before they expire",
    text: "Tokens cannot be cancelled before expiry; next step is a server-side session list.",
  },
  {
    title: "Insiders using their own access",
    text: "ZVault does not stop an employee from misusing access they legitimately have. Every request is written to the audit log; automatic alerts are future work.",
  },
  {
    title: "Roles are enforced as designed",
    text: "Db2 enforces the roles exactly as defined. A badly designed role is enforced badly, and role drift needs regular access reviews.",
  },
  {
    title: "The gateway password is the key to protect",
    text: "Someone who steals the gateway account password could act as a listed clerk or manager, but not as an auditor. In production it belongs in a vault.",
  },
  {
    title: "Changes are not built",
    text: "ZVault is read-only. Changes are designed to go through a one-time code and maker-checker approval, but that is not built.",
  },
  {
    title: "Demo sign-in",
    text: "The demo lists its employees and uses one shared password. A real bank signs staff in with its own identity system.",
  },
  {
    title: "Plain HTTP in the current demo",
    text: "The demo link is not encrypted. Encryption (TLS) is required before any real use.",
  },
  {
    title: "The database owner remains",
    text: "The Db2 instance owner can still stop or drop the database, even though it can no longer change the security rules.",
  },
  {
    title: "Speed",
    text: "Granite runs on the CPU and takes 10 to 30 seconds per question.",
  },
];

export function LimitsPage() {
  return (
    <article className="prose">
      <h1>Known limits</h1>
      <p className="lead">What ZVault does not do yet, stated plainly.</p>
      <ul className="limits">
        {LIMITS.map((l) => (
          <li key={l.title} className="card">
            <h2>{l.title}</h2>
            <p>{l.text}</p>
          </li>
        ))}
      </ul>
    </article>
  );
}
