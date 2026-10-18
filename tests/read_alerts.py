"""
read_alerts.py - the auditor reads suspicious-access alerts DIRECTLY in Db2,
with their own login. The AI gateway is not involved.

Run (needs the OS user auditor1 inside the Db2 container):
    export AUDITOR1_PASSWORD='...'
    python tests/read_alerts.py              # newest 20 alerts
    python tests/read_alerts.py --open       # open alerts only
    python tests/read_alerts.py --review 7   # mark alert 7 as REVIEWED
"""
import argparse
import os
import sys

import ibm_db

password = os.environ.get("AUDITOR1_PASSWORD")
if not password:
    sys.exit("Set it first:  export AUDITOR1_PASSWORD='...'")

p = argparse.ArgumentParser()
p.add_argument("--open", action="store_true", help="only alerts not yet reviewed")
p.add_argument("--review", type=int, metavar="ALERT_ID", help="mark one alert as REVIEWED")
args = p.parse_args()


def plain(value) -> str:
    """Show stored text as plain text only (no terminal control characters)."""
    return "".join(ch if ch.isprintable() else "?" for ch in str(value or ""))


dsn = (f"DATABASE={os.getenv('DB_NAME', 'BOTSBANK')};HOSTNAME=127.0.0.1;PORT=50000;"
       f"PROTOCOL=TCPIP;UID=auditor1;PWD={password};")
conn = ibm_db.connect(dsn, "", "")

if args.review:
    stmt = ibm_db.prepare(conn, "UPDATE BANK.ALERTS SET STATUS = 'REVIEWED' WHERE ALERT_ID = ?")
    ibm_db.execute(stmt, (args.review,))
    print(f"Alert {args.review}: {'marked REVIEWED' if ibm_db.num_rows(stmt) else 'not found'}")
    ibm_db.close(conn)
    sys.exit(0)

where = "WHERE STATUS = 'OPEN' " if args.open else ""
stmt = ibm_db.exec_immediate(
    conn,
    "SELECT ALERT_ID, UPDATED_AT, SEVERITY, RULE_ID, SUBJECT, EVENT_COUNT, STATUS, SUMMARY_BY, "
    "SUMMARY, EVIDENCE_LOG_IDS FROM BANK.ALERTS " + where +
    "ORDER BY ALERT_ID DESC FETCH FIRST 20 ROWS ONLY")
row = ibm_db.fetch_assoc(stmt)
if not row:
    print("No alerts.")
while row:
    print(f"#{row['ALERT_ID']}  {str(row['UPDATED_AT'])[:19]} UTC  {plain(row['SEVERITY']).strip():6} "
          f"{plain(row['RULE_ID']).strip():17} {plain(row['SUBJECT']).strip():18} "
          f"events={row['EVENT_COUNT']}  {plain(row['STATUS']).strip()}")
    print(f"     {plain(row['SUMMARY'])}  [{plain(row['SUMMARY_BY']).strip()}]")
    print(f"     evidence log ids: {plain(row['EVIDENCE_LOG_IDS'])}")
    row = ibm_db.fetch_assoc(stmt)
ibm_db.close(conn)
