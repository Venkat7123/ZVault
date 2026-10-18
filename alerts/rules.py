"""
rules.py - suspicious-access rules over the audit log (BANK.ACCESS_LOG).

Plain, predictable code: the rules decide WHAT is suspicious and HOW severe.
Granite only words the alert afterwards (summary.py) and never changes a decision.

Every user name in the log may be attacker-typed text (failed logins record whatever
was typed), so subjects are sanitised here before they go anywhere else.
"""
import hashlib
import ipaddress
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
READ_WINDOW_MINUTES = 30          # how far back each check looks
IST = timedelta(hours=5, minutes=30)  # the log is written in UTC

LOGIN_ACTIONS = {"login", "token"}
_SAFE_ID = re.compile(r"^[A-Z0-9_]{1,30}$")


@dataclass(frozen=True)
class Event:
    log_id: int
    time: datetime          # UTC, as written by Db2
    emp_id: str
    action: str
    decision: str
    rows: int | None
    reason: str
    ip: str | None = None


@dataclass
class Finding:
    rule: str
    severity: str
    subject: str            # sanitised: an employee id, "unknown:<hash>" or "ip:<address>"
    start: datetime
    end: datetime
    log_ids: list[int]
    facts: dict = field(default_factory=dict)   # small integers only; this is what Granite sees

    @property
    def count(self) -> int:
        return len(self.log_ids)


TITLES = {
    "FAILED_LOGINS": "Repeated failed sign-ins",
    "PASSWORD_SPRAY": "Password spraying (many accounts tried)",
    "BLOCK_BURST": "Burst of blocked AI requests",
    "AUDIT_LOG_PROBE": "Attempt to read the audit log",
    "WRITE_ATTEMPTS": "Attempts to change data through the AI",
    "DB2_DENIAL": "Db2 refused data access",
    "RATE_LIMITED": "Automated or very fast questioning",
    "BULK_READING": "Unusually large amount of data read",
    "OFF_HOURS": "Use of the AI assistant outside working hours",
    "LOGIN_THEN_PROBE": "Failed sign-ins followed by blocked requests",
    "BAD_TOKENS": "Forged or tampered sign-in tokens",
}


def safe_subject(emp_id: str) -> str:
    """A real-looking employee id is kept; anything else becomes a short hash."""
    emp = (emp_id or "").strip().upper()
    if _SAFE_ID.match(emp) and emp != "UNKNOWN":
        return emp
    return "unknown:" + hashlib.sha256((emp_id or "").encode("utf-8", "replace")).hexdigest()[:8]


def safe_ip(ip: str | None) -> str:
    try:
        return "ip:" + str(ipaddress.ip_address((ip or "").strip()))
    except ValueError:
        return "ip:unknown"


def _work_hours() -> tuple[int, int]:
    try:
        start, end = os.getenv("ALERT_WORK_HOURS", "8-20").split("-")
        return int(start), int(end)
    except ValueError:
        return 8, 20


def _recent(events, now, minutes):
    edge = now - timedelta(minutes=minutes)
    return [e for e in events if e.time > edge]


def _group(events, key):
    groups: dict[str, list[Event]] = {}
    for e in events:
        groups.setdefault(key(e), []).append(e)
    return groups


def _finding(rule, severity, subject, evs, **facts) -> Finding:
    evs = sorted(evs, key=lambda e: (e.time, e.log_id))
    return Finding(rule, severity, subject, evs[0].time, evs[-1].time,
                   [e.log_id for e in evs], {k: int(v) for k, v in facts.items()})


def _failed_login(e: Event) -> bool:
    return e.action == "login" and e.decision == "BLOCK"


def _ai_block(e: Event) -> bool:
    return e.decision == "BLOCK" and e.action not in LOGIN_ACTIONS


def evaluate(events: list[Event], now: datetime) -> list[Finding]:
    """All findings for the events of the last READ_WINDOW_MINUTES, newest state."""
    events = sorted(events, key=lambda e: (e.time, e.log_id))
    found: list[Finding] = []

    # 1. Repeated failed sign-ins for one account (5 min)
    for subj, evs in _group([e for e in _recent(events, now, 5) if _failed_login(e)],
                            lambda e: safe_subject(e.emp_id)).items():
        lockout = any("too many" in e.reason for e in evs)
        if len(evs) >= 5 or lockout:
            found.append(_finding("FAILED_LOGINS", "HIGH", subj, evs, failed_sign_ins=len(evs),
                                  window_minutes=5, lockout=lockout))
        elif len(evs) >= 3:
            found.append(_finding("FAILED_LOGINS", "MEDIUM", subj, evs, failed_sign_ins=len(evs),
                                  window_minutes=5))

    # 2. Password spraying: one address tries many different accounts (10 min)
    for subj, evs in _group([e for e in _recent(events, now, 10) if _failed_login(e)],
                            lambda e: safe_ip(e.ip)).items():
        accounts = {safe_subject(e.emp_id) for e in evs}
        if len(accounts) >= 4:
            found.append(_finding("PASSWORD_SPRAY", "HIGH", subj, evs, accounts_tried=len(accounts),
                                  failed_sign_ins=len(evs), window_minutes=10))

    by_emp_10 = _group([e for e in _recent(events, now, 10) if e.action not in LOGIN_ACTIONS],
                       lambda e: safe_subject(e.emp_id))

    # 3. Burst of blocked AI requests (2 min)
    for subj, evs in _group([e for e in _recent(events, now, 2) if _ai_block(e)],
                            lambda e: safe_subject(e.emp_id)).items():
        if len(evs) >= 5:
            found.append(_finding("BLOCK_BURST", "HIGH", subj, evs, blocked_requests=len(evs),
                                  window_minutes=2))
        elif len(evs) >= 3:
            found.append(_finding("BLOCK_BURST", "MEDIUM", subj, evs, blocked_requests=len(evs),
                                  window_minutes=2))

    for subj, evs in by_emp_10.items():
        # 4. Audit-log probe: staff are never allowed to read the log
        probes = [e for e in evs if e.action == "read_logs" and e.decision == "BLOCK"]
        if probes:
            found.append(_finding("AUDIT_LOG_PROBE", "HIGH", subj, probes, attempts=len(probes),
                                  window_minutes=10))
        # 5. Write attempts through a read-only assistant
        writes = [e for e in evs if e.decision == "BLOCK" and e.reason.startswith("write request")]
        if writes:
            found.append(_finding("WRITE_ATTEMPTS", "MEDIUM" if len(writes) >= 2 else "LOW", subj,
                                  writes, attempts=len(writes), window_minutes=10))
        # 6. Db2 itself refused the employee
        denials = [e for e in evs if e.reason.startswith("Db2 denied access")]
        if denials:
            found.append(_finding("DB2_DENIAL", "MEDIUM", subj, denials, denials=len(denials),
                                  window_minutes=10))
        # 7. Hit the questions-per-minute limit (automation)
        limited = [e for e in evs if e.reason.startswith("too many questions")]
        if limited:
            found.append(_finding("RATE_LIMITED", "MEDIUM", subj, limited, times_limited=len(limited),
                                  window_minutes=10))
        # 8. Bulk reading: many allowed answers or many rows (scraping)
        allowed = [e for e in evs if e.decision == "ALLOW"]
        rows = sum(e.rows or 0 for e in allowed)
        if len(allowed) >= 15 or rows >= 30:
            found.append(_finding("BULK_READING", "MEDIUM", subj, allowed, answers=len(allowed),
                                  rows_read=rows, window_minutes=10))

    # 9. Use outside working hours (IST), real employees only (30 min)
    start_h, end_h = _work_hours()
    late = [e for e in _recent(events, now, READ_WINDOW_MINUTES)
            if e.action not in LOGIN_ACTIONS and not safe_subject(e.emp_id).startswith("unknown:")
            and not (start_h <= (e.time + IST).hour < end_h)]
    for subj, evs in _group(late, lambda e: safe_subject(e.emp_id)).items():
        found.append(_finding("OFF_HOURS", "LOW", subj, evs, requests=len(evs),
                              work_start_hour=start_h, work_end_hour=end_h))

    # 10. Failed sign-ins, then blocked requests from the same account (10 min)
    recent10 = _recent(events, now, 10)
    for subj, fails in _group([e for e in recent10 if _failed_login(e)],
                              lambda e: safe_subject(e.emp_id)).items():
        if len(fails) < 2 or subj.startswith("unknown:"):
            continue
        after = [e for e in recent10 if _ai_block(e) and safe_subject(e.emp_id) == subj
                 and e.time >= fails[0].time]
        if after:
            found.append(_finding("LOGIN_THEN_PROBE", "HIGH", subj, fails + after,
                                  failed_sign_ins=len(fails), blocked_requests=len(after),
                                  window_minutes=10))

    # 11. Forged or tampered tokens from one address (5 min)
    for subj, evs in _group([e for e in _recent(events, now, 5)
                             if e.action == "token" and e.reason == "invalid token"],
                            lambda e: safe_ip(e.ip)).items():
        if len(evs) >= 5:
            found.append(_finding("BAD_TOKENS", "MEDIUM", subj, evs, invalid_tokens=len(evs),
                                  window_minutes=5))
    return found
