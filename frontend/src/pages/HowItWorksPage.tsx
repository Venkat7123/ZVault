import { FlowDiagram } from "../components/FlowDiagram";

export function HowItWorksPage() {
  return (
    <article className="prose">
      <h1>How ZVault protects bank data</h1>
      <p className="lead">
        Most AI assistants query the database with one all-powerful service account, so anyone who can talk to the
        assistant, or inject text into it, can get any data. ZVault removes that master key.
      </p>

      <div className="card diagram">
        <FlowDiagram />
      </div>

      <h2>The core rule</h2>
      <p>
        <strong>The AI never holds a master key. Db2 itself enforces what each employee can see.</strong> The gateway
        opens a fresh Db2 connection per request and switches it to the real employee, so Db2 applies that
        employee&rsquo;s branch rows and column masks. The gateway account on its own has no data access at all.
      </p>

      <h2>What the AI does and does not do</h2>
      <div className="two-col">
        <section className="card">
          <h3>The AI can</h3>
          <ul>
            <li>Read the question and pick one read-only tool by name.</li>
            <li>Give a second opinion that can only <em>block</em> a request.</li>
          </ul>
        </section>
        <section className="card">
          <h3>The AI never</h3>
          <ul>
            <li>Writes SQL or sees data rows.</li>
            <li>Grants access. Rules grant it; the AI can only block.</li>
            <li>Changes data. ZVault is read-only.</li>
          </ul>
        </section>
      </div>

      <h2>The seven checks</h2>
      <ol className="steps">
        <li><strong>Token.</strong> A signed 15-minute token says who the employee is.</li>
        <li><strong>Tool choice.</strong> Granite sees only the question and returns one tool name.</li>
        <li><strong>Rules.</strong> Plain code blocks write words, a list asked for when one customer was named, and a missing customer number.</li>
        <li><strong>Intent check.</strong> Granite can block a request that does not match the question.</li>
        <li><strong>Fixed SQL.</strong> Values come from plain code and go in as parameters; free text never reaches Db2.</li>
        <li><strong>Db2 as the employee.</strong> Row permissions limit the branch; masks hide Aadhaar, PAN and mobile numbers.</li>
        <li><strong>Volume check.</strong> A tool never returns more rows than it should.</li>
      </ol>

      <h2>Every request is logged</h2>
      <p>
        Allowed and blocked requests are written to an audit log that only the auditor role can read, directly in
        Db2 and never through the AI.
      </p>
    </article>
  );
}
