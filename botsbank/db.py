"""
db.py - every data access goes through a Db2 TRUSTED connection that is
switched to the real employee. The gateway account (AIGW) has no data
access of its own, so there is no master key.

A new connection is opened per request, so one employee's session can never
leak into another's.
"""
import datetime
import os
from decimal import Decimal

import ibm_db

DB_NAME = os.getenv("DB_NAME", "BOTSBANK")
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "50000")
GW_USER = os.getenv("DB_GW_USER", "aigw")


class AccessDenied(Exception):
    """Db2 refused the operation for this employee (SQL0551N)."""


def _dsn() -> str:
    password = os.environ.get("DB_GW_PASSWORD")
    if not password:
        raise RuntimeError("DB_GW_PASSWORD is not set")
    return (f"DATABASE={DB_NAME};HOSTNAME={DB_HOST};PORT={DB_PORT};"
            f"PROTOCOL=TCPIP;UID={GW_USER};PWD={password};")


def _clean(value):
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (datetime.datetime, datetime.date)):
        return value.isoformat(sep=" ", timespec="seconds") \
            if isinstance(value, datetime.datetime) else value.isoformat()
    if isinstance(value, str):
        return value.strip()
    return value


def _fetch_all(stmt) -> list[dict]:
    rows = []
    row = ibm_db.fetch_assoc(stmt)
    while row:
        rows.append({k: _clean(v) for k, v in row.items()})
        row = ibm_db.fetch_assoc(stmt)
    return rows


def run_as(user_id: str, sql: str, params: tuple = ()) -> list[dict]:
    """Run a fixed, parameterised query AS the given employee."""
    conn = ibm_db.connect(_dsn(), "", "",
                          {ibm_db.SQL_ATTR_USE_TRUSTED_CONTEXT: ibm_db.SQL_TRUE})
    try:
        if not ibm_db.get_option(conn, ibm_db.SQL_ATTR_USE_TRUSTED_CONTEXT, 1):
            raise RuntimeError("Connection is not trusted; refusing to continue")

        ibm_db.set_option(conn, {ibm_db.SQL_ATTR_TRUSTED_CONTEXT_USERID: user_id}, 1)

        # Fail closed: confirm Db2 really switched to this employee.
        stmt = ibm_db.exec_immediate(conn, "SELECT SESSION_USER AS U FROM SYSIBM.SYSDUMMY1")
        who = _fetch_all(stmt)[0]["U"]
        if who != user_id:
            raise RuntimeError(f"Identity switch failed (session is {who})")

        stmt = ibm_db.prepare(conn, sql)
        if params:
            ibm_db.execute(stmt, tuple(params))
        else:
            ibm_db.execute(stmt)
        return _fetch_all(stmt)
    except Exception as exc:  # noqa: BLE001 - translate Db2 privilege errors
        if "SQL0551N" in str(exc):
            raise AccessDenied(str(exc)) from exc
        raise
    finally:
        ibm_db.close(conn)


# True until Db2 says ACCESS_LOG has no CLIENT_IP column (sql/07_alerts.sql not run yet).
_LOG_HAS_IP = True


def write_log(emp_id: str, action: str, decision: str,
              rows_returned: int | None, reason: str, client_ip: str | None = None) -> None:
    """Append one audit record. AIGW may only INSERT into the log."""
    global _LOG_HAS_IP
    try:
        conn = ibm_db.connect(_dsn(), "", "")
        try:
            values = (emp_id[:30], action[:30], decision[:10], rows_returned, reason[:500])
            if _LOG_HAS_IP:
                try:
                    stmt = ibm_db.prepare(
                        conn,
                        "INSERT INTO BANK.ACCESS_LOG "
                        "(EMP_ID, ACTION, DECISION, ROWS_RETURNED, REASON, CLIENT_IP) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                    )
                    ibm_db.execute(stmt, values + ((client_ip or "")[:45] or None,))
                    return
                except Exception as exc:  # noqa: BLE001
                    if "SQL0206N" not in str(exc):  # anything but "no such column"
                        raise
                    _LOG_HAS_IP = False
            stmt = ibm_db.prepare(
                conn,
                "INSERT INTO BANK.ACCESS_LOG (EMP_ID, ACTION, DECISION, ROWS_RETURNED, REASON) "
                "VALUES (?, ?, ?, ?, ?)",
            )
            ibm_db.execute(stmt, values)
        finally:
            ibm_db.close(conn)
    except Exception as exc:  # noqa: BLE001 - never crash a request on logging
        print(f"WARNING: audit log write failed: {exc}")


def ping() -> bool:
    try:
        conn = ibm_db.connect(_dsn(), "", "")
        ibm_db.close(conn)
        return True
    except Exception:  # noqa: BLE001
        return False
