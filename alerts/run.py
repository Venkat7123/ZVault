"""
run.py - the alert engine loop. Runs as its own service, separate from the gateway.

    python -m alerts.run             # every 30 s, forever (the service)
    python -m alerts.run --once      # one pass, then exit
    python -m alerts.run --dry-run   # one pass, print findings, write nothing

Secrets come from the environment (~/.botsbank_alerts_env via start_alerts.sh).
"""
import argparse
import os
import sys
import time

from . import rules, store, summary

POLL_SECONDS = int(os.getenv("ALERT_POLL_SECONDS", "30"))
GRANITE_PER_CYCLE = int(os.getenv("ALERT_GRANITE_PER_CYCLE", "2"))  # Granite is shared with staff
USE_GRANITE = os.getenv("ALERT_USE_GRANITE", "1") == "1"


def _chat():
    if not USE_GRANITE:
        return None
    try:
        from botsbank import llm
        return llm._chat
    except Exception:  # noqa: BLE001
        return None


def one_pass(dry_run: bool = False) -> int:
    conn = store.connect()
    try:
        now, events = store.recent_events(conn)
        findings = rules.evaluate(events, now)
        findings.sort(key=lambda f: -rules.SEVERITY_ORDER[f.severity])   # worst first gets Granite
        budget = {"granite": GRANITE_PER_CYCLE}
        chat = _chat()

        def write_summary(f):
            use = chat if budget["granite"] > 0 else None
            text, by = summary.write(f, use)
            if use is not None:
                budget["granite"] -= 1
            return text, by

        changed = 0
        for f in findings:
            if dry_run:
                print(f"[dry-run] {f.severity:6} {f.rule:17} {f.subject:18} events={f.count} {f.facts}")
                continue
            result = store.save(conn, f, write_summary)
            if result:
                changed += 1
                print(f"{result:7} {f.severity:6} {f.rule:17} {f.subject:18} events={f.count}", flush=True)
        return changed
    finally:
        store.ibm_db.close(conn)


def main() -> None:
    p = argparse.ArgumentParser(description="ZVault suspicious-access alert engine")
    p.add_argument("--once", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args()
    if a.once or a.dry_run:
        one_pass(a.dry_run)
        return
    print(f"Alert engine started: every {POLL_SECONDS} s, Granite summaries "
          f"{'on' if USE_GRANITE else 'off'}", flush=True)
    while True:
        try:
            one_pass()
        except Exception as exc:  # noqa: BLE001 - keep running; Db2 may be restarting
            print(f"WARNING: alert pass failed: {exc}", file=sys.stderr, flush=True)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
