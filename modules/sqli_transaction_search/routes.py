"""
Module: sqli_transaction_search
Difficulty: Intermediate
OWASP: A03:2021 Injection
CWE: CWE-89 (SQL Injection)

Business context: customers can search their own transaction history
by description keyword. The safe list endpoint (GET /transactions)
uses the ORM correctly. The search endpoint was added later by
someone reaching for raw SQL for a "more flexible" LIKE query and
building it with an f-string instead of bound parameters.

Player path: search for something normal first, then break out of the
string with a UNION SELECT. Column count/types must match the
underlying query (4 columns: id, description, amount, txn_date) --
this is deliberately non-trivial the way real UNION-based SQLi against
Postgres actually is (SQLite is much more permissive about type
mismatches across UNION branches and would give a false sense of what
"works"; this module targets Postgres specifically since that's what
docker-compose runs).

Verified working payload against Postgres:
    nonexistent%' UNION SELECT id, username || ':' || password_hash, 0, NULL FROM users -- 
"""
from flask import Blueprint, request, jsonify, session, abort
from sqlalchemy import text

from app import db
from .models import Transaction

bp = Blueprint("sqli_transaction_search", __name__, url_prefix="/transactions")


def _require_login():
    if "user_id" not in session:
        abort(401)


@bp.route("")
def list_transactions():
    """Safe endpoint -- parameterized via the ORM, not vulnerable."""
    _require_login()
    txns = Transaction.query.filter_by(customer_id=session["user_id"]).all()
    return jsonify([{
        "id": t.id, "description": t.description,
        "amount": str(t.amount), "txn_date": t.txn_date.isoformat() if t.txn_date else None,
    } for t in txns])


@bp.route("/search")
def search_transactions():
    """
    VULNERABLE: search_term is interpolated directly into the SQL
    string instead of being passed as a bound parameter.
    """
    _require_login()
    search_term = request.args.get("q", "")
    customer_id = session["user_id"]

    query = (
        f"SELECT id, description, amount, txn_date FROM transactions "
        f"WHERE customer_id = {customer_id} AND LOWER(description) LIKE LOWER('%{search_term}%')"
    )
    result = db.session.execute(text(query))
    rows = result.fetchall()

    def _fmt_date(val):
        if val is None:
            return None
        if hasattr(val, "isoformat"):
            return val.isoformat()
        return str(val)  # SQLite's driver returns raw strings for raw text() queries; Postgres returns datetime objects

    return jsonify([{
        "id": r[0], "description": r[1],
        "amount": str(r[2]) if r[2] is not None else None,
        "txn_date": _fmt_date(r[3]),
    } for r in rows])


def register_reset():
    from .seed import run_seed
    run_seed(db)
