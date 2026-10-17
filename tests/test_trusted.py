"""
test_trusted.py - prove the master-key fix on Bots Bank (Db2 on IBM Z).

The gateway (AIGW) opens a trusted connection, then switches to each
employee. Db2 itself decides what each one can see.

Run:
    export DB_GW_PASSWORD='<aigw password>'
    python test_trusted.py
"""
import os
import sys

import ibm_db

DB_NAME = os.getenv("DB_NAME", "BOTSBANK")
GW_PASSWORD = os.environ.get("DB_GW_PASSWORD")
if not GW_PASSWORD:
    sys.exit("Set the gateway password first:  export DB_GW_PASSWORD='...'")

DSN = (f"DATABASE={DB_NAME};HOSTNAME=127.0.0.1;PORT=50000;PROTOCOL=TCPIP;"
       f"UID=aigw;PWD={GW_PASSWORD};")
CUSTOMER_QUERY = ("SELECT CUST_ID, FULL_NAME, BRANCH_ID, BALANCE, AADHAAR, PAN, MOBILE "
                  "FROM BANK.CUSTOMERS ORDER BY CUST_ID")


def connect():
    conn = ibm_db.connect(DSN, "", "", {ibm_db.SQL_ATTR_USE_TRUSTED_CONTEXT: ibm_db.SQL_TRUE})
    if not ibm_db.get_option(conn, ibm_db.SQL_ATTR_USE_TRUSTED_CONTEXT, 1):
        sys.exit("Not trusted: check the address in the trusted context.")
    return conn


def run(conn, sql):
    stmt = ibm_db.exec_immediate(conn, sql)
    rows, row = [], ibm_db.fetch_tuple(stmt)
    while row:
        rows.append(row)
        row = ibm_db.fetch_tuple(stmt)
    return rows


def show(title, rows):
    print(f"\n--- {title}: {len(rows)} row(s) ---")
    for cust_id, name, branch, balance, aadhaar, pan, mobile in rows:
        print(f"{cust_id:<6} {name:<14} {branch:<6} {float(balance):>14,.2f}  "
              f"{aadhaar.strip():<13} {pan.strip():<11} {mobile}")


def main():
    conn = connect()
    print("Trusted connection: True")

    # 1. Gateway on its own: no data rights at all.
    try:
        show("Gateway alone as AIGW", run(conn, CUSTOMER_QUERY))
        print("WARNING: the gateway can read data on its own!")
    except Exception:
        print("\n--- Gateway alone as AIGW: no access (expected) ---")

    # 2. Employees the gateway is allowed to act for.
    for user in ["CLERK1", "CLERK2", "MANAGER1"]:
        ibm_db.set_option(conn, {ibm_db.SQL_ATTR_TRUSTED_CONTEXT_USERID: user}, 1)
        who = run(conn, "SELECT SESSION_USER FROM SYSIBM.SYSDUMMY1")[0][0].strip()
        if who != user:
            sys.exit(f"Switch to {user} did not happen (still {who}).")
        show(f"Switched to {who}", run(conn, CUSTOMER_QUERY))
    ibm_db.close(conn)

    # 3. Identities the gateway must NOT be able to become.
    #    A failed switch breaks the connection, so each test gets a fresh one.
    for user in ["AUDITOR1", "HACKER"]:
        print(f"\n--- Switch to {user} ---")
        conn = connect()
        try:
            ibm_db.set_option(conn, {ibm_db.SQL_ATTR_TRUSTED_CONTEXT_USERID: user}, 1)
            run(conn, "SELECT SESSION_USER FROM SYSIBM.SYSDUMMY1")
            print("WARNING: switch was allowed - check the trusted context!")
        except Exception:
            print("Refused by Db2 (expected)")
        finally:
            try:
                ibm_db.close(conn)
            except Exception:
                pass


if __name__ == "__main__":
    main()
