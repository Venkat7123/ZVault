import { useState, type FormEvent } from "react";

interface Props {
  busy: boolean;
  onAsk: (question: string) => void;
  value: string;
  onChange: (v: string) => void;
}

export function QuestionBox({ busy, onAsk, value, onChange }: Props) {
  const [touched, setTouched] = useState(false);
  const tooShort = value.trim().length < 3;

  function submit(e: FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (!tooShort) onAsk(value.trim());
  }

  return (
    <form onSubmit={submit} noValidate>
      <label htmlFor="question">Ask about customers and loans</label>
      <textarea
        id="question"
        rows={3}
        maxLength={500}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="For example: Show customers with balance above 1 crore"
        aria-describedby="question-help"
        aria-invalid={touched && tooShort}
      />
      <p id="question-help" className="muted small">
        {touched && tooShort ? "Please type at least 3 characters." : "Read-only. Up to 500 characters."}
      </p>
      <div className="row">
        <button className="btn btn-primary" type="submit" disabled={busy}>Ask</button>
        {busy && (
          <span className="muted" role="status">
            <span className="spinner" aria-hidden="true" /> Granite is working on IBM Z. This can take 10 to 30 seconds.
          </span>
        )}
      </div>
    </form>
  );
}
