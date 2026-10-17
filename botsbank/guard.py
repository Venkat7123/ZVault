"""
guard.py - simple, predictable rules checked before any data is fetched.
They can only block. Db2 remains the final authority on what is visible.
"""
import re

WRITE_WORDS = re.compile(
    r"\b(change|update|modify|edit|delete|remove|transfer|set|insert|drop|alter)\b", re.I)
CUSTOMER_NUMBER = re.compile(r"\b\d{4}\b")


def check(question: str, tool: str, args: dict) -> tuple[bool, str]:
    """Return (allowed, reason)."""
    if WRITE_WORDS.search(question):
        return False, "write request: the assistant is read-only"

    if tool == "none":
        return False, "no read-only tool matches this request"

    mentions_one_customer = bool(CUSTOMER_NUMBER.search(question))
    if mentions_one_customer and tool in {"list_customers", "list_loans", "branch_summary"}:
        return False, "question is about one customer but the request was for a list"

    if tool in {"get_customer", "customer_loans"} and not args.get("cust_id"):
        return False, "a customer number is needed"

    return True, "rules passed"
