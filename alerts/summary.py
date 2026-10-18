"""
summary.py - a plain-language alert text for the auditor.

Granite writes it ONLY after a rule has fired, and only from safe facts:
the rule title, the severity, a sanitised subject and a few counts. It never sees
the raw log text (which may contain attacker-typed input) and never decides severity.
If Granite is slow, down or answers oddly, a fixed template is used instead.
"""
import re

from .rules import TITLES, Finding

MAX_CHARS = 400

SYSTEM = (
    "You write short security alerts for a bank auditor. Use ONLY the facts given. "
    "Write two plain sentences: what happened, and what the auditor should check. "
    "Do not invent names, numbers or causes. No lists, no markdown, no links."
)

_ALLOWED = re.compile(r"^[A-Za-z0-9 .,;:'()%/\-]+$")


def template(f: Finding) -> str:
    facts = ", ".join(f"{k.replace('_', ' ')}: {v}" for k, v in f.facts.items())
    return (f"{f.severity} alert: {TITLES.get(f.rule, f.rule)} for {f.subject}"
            f" ({facts}). Please review the evidence log entries and confirm whether this was expected.")


def clean(text: str) -> str | None:
    """Accept Granite's text only if it is short, plain and safe to display."""
    text = " ".join((text or "").split())
    if not text or len(text) > MAX_CHARS or not _ALLOWED.match(text):
        return None
    if "http" in text.lower() or "ignore" in text.lower():
        return None
    return text


def write(f: Finding, chat=None) -> tuple[str, str]:
    """(summary, "granite" | "template"). `chat` is botsbank.llm._chat (injected for tests)."""
    if chat is not None:
        facts = "; ".join(f"{k.replace('_', ' ')} = {v}" for k, v in f.facts.items())
        prompt = (f"Alert: {TITLES.get(f.rule, f.rule)}. Severity: {f.severity}. "
                  f"Account or address: {f.subject}. Facts: {facts}.")
        try:
            text = clean(chat([{"role": "system", "content": SYSTEM},
                               {"role": "user", "content": prompt}], max_tokens=90))
            if text:
                return text, "granite"
        except Exception:  # noqa: BLE001 - Granite down or slow: fall back
            pass
    return template(f), "template"
