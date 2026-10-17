"""
tools.py - the ONLY things the AI can ask for.

Every tool is read-only, with fixed SQL and validated parameters. The AI
never writes SQL; it only picks a tool name and fills in simple values.
Db2's row permissions and column masks then decide what comes back.
"""
import re

CUSTOMER_COLUMNS = "CUST_ID, FULL_NAME, BRANCH_ID, BALANCE, AADHAAR, PAN, MOBILE"
LOAN_STATUSES = {"ACTIVE", "OVERDUE", "CLOSED"}

TOOLS = {
    "list_customers": {
        "description": "List customers, optionally only those with balance at least min_balance (rupees).",
        "max_rows": 50,
    },
    "get_customer": {
        "description": "Details of ONE customer by cust_id (4-digit number).",
        "max_rows": 1,
    },
    "customer_loans": {
        "description": "Loans of ONE customer by cust_id.",
        "max_rows": 10,
    },
    "list_loans": {
        "description": "List loans, optionally filtered by status (ACTIVE, OVERDUE, CLOSED).",
        "max_rows": 50,
    },
    "branch_summary": {
        "description": "Number of customers and total balance per branch.",
        "max_rows": 10,
    },
}


class ToolError(ValueError):
    """The AI asked for a tool or value that is not allowed."""


# Which values each tool may receive. Anything else is dropped.
TOOL_ARGS = {
    "list_customers": ["min_balance"],
    "get_customer": ["cust_id"],
    "customer_loans": ["cust_id"],
    "list_loans": ["status"],
    "branch_summary": [],
}

_CUST_ID = re.compile(r"\b(\d{4})\b")
_AMOUNT_UNIT = re.compile(r"(\d[\d,]*(?:\.\d+)?)\s*(crores?|cr|lakhs?|lacs?)\b", re.I)
_AMOUNT_PLAIN = re.compile(
    r"(?:above|over|more than|at least|greater than|>=?)\s*(?:rs\.?|inr|₹)?\s*(\d[\d,]*(?:\.\d+)?)", re.I)
_STATUS = re.compile(r"\b(active|overdue|closed)\b", re.I)


def extract_args(question: str, tool: str) -> dict:
    """Pull values from the question with plain code (not the AI),
    keeping only the values this tool accepts."""
    found = {}

    m = _CUST_ID.search(question)
    if m:
        found["cust_id"] = int(m.group(1))

    m = _AMOUNT_UNIT.search(question)
    if m:
        number = float(m.group(1).replace(",", ""))
        unit = m.group(2).lower()
        found["min_balance"] = number * (10_000_000 if unit.startswith("cr") else 100_000)
    else:
        m = _AMOUNT_PLAIN.search(question)
        if m:
            found["min_balance"] = float(m.group(1).replace(",", ""))

    m = _STATUS.search(question)
    if m:
        found["status"] = m.group(1).upper()

    return {k: v for k, v in found.items() if k in TOOL_ARGS.get(tool, [])}


def _cust_id(args: dict) -> int:
    try:
        value = int(args.get("cust_id"))
    except (TypeError, ValueError):
        raise ToolError("a valid customer number is needed") from None
    if not 1 <= value <= 999999:
        raise ToolError("customer number out of range")
    return value


def build_query(tool: str, args: dict) -> tuple[str, tuple]:
    """Turn a tool choice into fixed SQL + safe parameters."""
    if tool == "list_customers":
        try:
            min_balance = float(args.get("min_balance") or 0)
        except (TypeError, ValueError):
            raise ToolError("invalid balance") from None
        if min_balance < 0:
            raise ToolError("invalid balance")
        return (f"SELECT {CUSTOMER_COLUMNS} FROM BANK.CUSTOMERS "
                "WHERE BALANCE >= ? ORDER BY BALANCE DESC FETCH FIRST 51 ROWS ONLY",
                (min_balance,))

    if tool == "get_customer":
        return (f"SELECT {CUSTOMER_COLUMNS} FROM BANK.CUSTOMERS WHERE CUST_ID = ?",
                (_cust_id(args),))

    if tool == "customer_loans":
        return ("SELECT LOAN_ID, CUST_ID, BRANCH_ID, AMOUNT, STATUS FROM BANK.LOANS "
                "WHERE CUST_ID = ? ORDER BY LOAN_ID FETCH FIRST 11 ROWS ONLY",
                (_cust_id(args),))

    if tool == "list_loans":
        status = (args.get("status") or "").upper()
        if status:
            if status not in LOAN_STATUSES:
                raise ToolError("invalid loan status")
            return ("SELECT LOAN_ID, CUST_ID, BRANCH_ID, AMOUNT, STATUS FROM BANK.LOANS "
                    "WHERE STATUS = ? ORDER BY LOAN_ID FETCH FIRST 51 ROWS ONLY", (status,))
        return ("SELECT LOAN_ID, CUST_ID, BRANCH_ID, AMOUNT, STATUS FROM BANK.LOANS "
                "ORDER BY LOAN_ID FETCH FIRST 51 ROWS ONLY", ())

    if tool == "branch_summary":
        return ("SELECT BRANCH_ID, COUNT(*) AS CUSTOMERS, SUM(BALANCE) AS TOTAL_BALANCE "
                "FROM BANK.CUSTOMERS GROUP BY BRANCH_ID ORDER BY BRANCH_ID", ())

    raise ToolError(f"unknown tool '{tool}'")
