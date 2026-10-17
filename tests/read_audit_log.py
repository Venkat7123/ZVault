"""
read_audit_log.py - the auditor reads the audit log DIRECTLY in Db2,
with their own login. The AI gateway is not involved at all.

Run (needs the OS user auditor1 inside the Db2 container):
    export AUDITOR1_PASSWORD='...'
    python read_audit_log.py
"""
import os
import sys

import ibm_db

password = os.environ.get("AUDITOR1_PASSWORD")
if not password:
    sys.exit("Set it first:  export AUDITOR1_PASSWORD='...'")

dsn = (f"DATABASE={os.getenv('DB_NAME', 'BOTSBANK')};HOSTNAME=127.0.0.1;PORT=50000;"
       f"PROTOCOL=TCPIP;UID=auditor1;PWD={password};")
conn = ibm_db.connect(dsn, "", "")
stmt = ibm_db.exec_immediate(
    conn,
    "SELECT LOG_ID, EVENT_TIME, EMP_ID, ACTION, DECISION, ROWS_RETURNED, REASON "
    "FROM BANK.ACCESS_LOG ORDER BY LOG_ID DESC FETCH FIRST 20 ROWS ONLY",
)
print(f"{'ID':>5}  {'TIME':19}  {'EMPLOYEE':9} {'ACTION':15} {'DECISION':8} {'ROWS':>4}  REASON")
row = ibm_db.fetch_tuple(stmt)
while row:
    log_id, when, emp, action, decision, rows, reason = row
    print(f"{log_id:>5}  {str(when)[:19]:19}  {emp:9} {action:15} {decision:8} "
          f"{'' if rows is None else rows:>4}  {reason}")
    row = ibm_db.fetch_tuple(stmt)
ibm_db.close(conn)
