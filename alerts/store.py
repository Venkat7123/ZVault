"""
store.py - Db2 access for the alert engine, as its own user ALERTSVC.

ALERTSVC can read BANK.ACCESS_LOG and write BANK.ALERTS. It has no access to
customer data (07_alerts.sql). All SQL is fixed with ? parameters.
"""
import os
from datetime import datetime

import ibm_db

from .rules import READ_WINDOW_MINUTES, SEVERITY_ORDER, Event, Finding

MAX_EVENTS = 5000
EVIDENCE_CHARS = 1000


def connect():
    password = os.environ.get("ALERTSVC_PASSWORD")
    if not password:
        raise RuntimeError("ALERTSVC_PASSWORD is not set (see ~/.botsbank_alerts_env)")
    dsn = (f"DATABASE={os.getenv('DB_NAME', 'BOTSBANK')};HOSTNAME={os.getenv('DB_HOST', '127.0.0.1')};"
           f"PORT={os.getenv('DB_PORT', '50000')};PROTOCOL=TCPIP;"
           f"UID={os.getenv('ALERTSVC_USER', 'alertsvc')};PWD={password};")
    return ibm_db.connect(dsn, "", "")


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d-%H.%M.%S.%f")


def _rows(stmt):
    out, row = [], ibm_db.fetch_assoc(stmt)
    while row:
        out.append(row)
        row = ibm_db.fetch_assoc(stmt)
    return out


def recent_events(conn) -> tuple[datetime, list[Event]]:
    """Db2's clock and the log rows of the last READ_WINDOW_MINUTES (newest MAX_EVENTS)."""
    now = _rows(ibm_db.exec_immediate(conn, "SELECT CURRENT TIMESTAMP AS NOW FROM SYSIBM.SYSDUMMY1"))[0]["NOW"]
    stmt = ibm_db.exec_immediate(
        conn,
        "SELECT LOG_ID, EVENT_TIME, EMP_ID, ACTION, DECISION, ROWS_RETURNED, REASON, CLIENT_IP "
        "FROM BANK.ACCESS_LOG "
        f"WHERE EVENT_TIME > CURRENT TIMESTAMP - {int(READ_WINDOW_MINUTES)} MINUTES "
        f"ORDER BY LOG_ID DESC FETCH FIRST {int(MAX_EVENTS)} ROWS ONLY")
    events = [Event(int(r["LOG_ID"]), r["EVENT_TIME"], (r["EMP_ID"] or "").strip(),
                    (r["ACTION"] or "").strip(), (r["DECISION"] or "").strip(), r["ROWS_RETURNED"],
                    (r["REASON"] or "").strip(), (r["CLIENT_IP"] or None))
              for r in _rows(stmt)]
    return now, list(reversed(events))


def _evidence(ids: set[int]) -> str:
    text = ""
    for i in sorted(ids, reverse=True):          # keep the newest ids that fit
        part = str(i) if not text else f"{i},{text}"
        if len(part) > EVIDENCE_CHARS:
            break
        text = part
    return text


def save(conn, f: Finding, write_summary) -> str | None:
    """Insert a new alert or update the open one for this rule + subject.
    Returns "new", "updated" or None (nothing new). write_summary(f) -> (text, by)."""
    stmt = ibm_db.prepare(
        conn,
        "SELECT ALERT_ID, SEVERITY, STATUS, EVIDENCE_LOG_IDS FROM BANK.ALERTS "
        "WHERE RULE_ID = ? AND SUBJECT = ? "
        f"AND WINDOW_END > CURRENT TIMESTAMP - {int(READ_WINDOW_MINUTES)} MINUTES "
        "ORDER BY ALERT_ID DESC FETCH FIRST 1 ROW ONLY")
    ibm_db.execute(stmt, (f.rule, f.subject))
    found = _rows(stmt)
    ids = set(f.log_ids)
    if found:
        old = found[0]
        old_ids = {int(x) for x in (old["EVIDENCE_LOG_IDS"] or "").split(",") if x.strip().isdigit()}
        if not ids - old_ids:
            return None                              # nothing the auditor hasn't seen
        if old["STATUS"].strip() == "OPEN":
            merged = ids | old_ids
            old_sev = old["SEVERITY"].strip()
            severity = max(old_sev, f.severity, key=SEVERITY_ORDER.get)
            sql = ("UPDATE BANK.ALERTS SET UPDATED_AT = CURRENT TIMESTAMP, SEVERITY = ?, "
                   "WINDOW_END = ?, EVENT_COUNT = ?, EVIDENCE_LOG_IDS = ?")
            params = [severity, _ts(f.end), len(merged), _evidence(merged)]
            if SEVERITY_ORDER[severity] > SEVERITY_ORDER[old_sev]:   # worse: re-word it
                f.severity = severity
                text, by = write_summary(f)
                sql += ", SUMMARY = ?, SUMMARY_BY = ?"
                params += [text[:600], by]
            upd = ibm_db.prepare(conn, sql + " WHERE ALERT_ID = ?")
            ibm_db.execute(upd, tuple(params + [int(old["ALERT_ID"])]))
            return "updated"
        f.log_ids = sorted(ids - old_ids)            # reviewed already: only the new part

    text, by = write_summary(f)
    ins = ibm_db.prepare(
        conn,
        "INSERT INTO BANK.ALERTS (RULE_ID, SEVERITY, SUBJECT, WINDOW_START, WINDOW_END, EVENT_COUNT, "
        "EVIDENCE_LOG_IDS, SUMMARY, SUMMARY_BY, DEDUPE_KEY) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    ibm_db.execute(ins, (f.rule, f.severity, f.subject, _ts(f.start), _ts(f.end), len(f.log_ids),
                         _evidence(set(f.log_ids)), text[:600], by,
                         f"{f.rule}:{f.subject}:{_ts(f.start)}:{min(f.log_ids)}"[:160]))
    return "new"
