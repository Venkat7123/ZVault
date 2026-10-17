"""
find_client_ip.py - show the client IP address Db2 sees for connections
from this server. That address must be in the trusted context.

Run:
    export DB2INST1_PW='<db2inst1 password from ~/.db2_env>'
    python find_client_ip.py
"""
import os
import sys

import ibm_db

password = os.environ.get("DB2INST1_PW")
if not password:
    sys.exit("Set it first:  export DB2INST1_PW='...'")

dsn = ("DATABASE=BOTSBANK;HOSTNAME=127.0.0.1;PORT=50000;PROTOCOL=TCPIP;"
       f"UID=db2inst1;PWD={password};")
conn = ibm_db.connect(dsn, "", "")
stmt = ibm_db.exec_immediate(
    conn,
    "SELECT CLIENT_IPADDR FROM TABLE("
    "MON_GET_CONNECTION(MON_GET_APPLICATION_HANDLE(), -1))",
)
row = ibm_db.fetch_tuple(stmt)
print(f"Db2 sees this server as: {row[0].strip() if row else 'unknown'}")
ibm_db.close(conn)
