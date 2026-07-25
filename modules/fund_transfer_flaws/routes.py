"""
Module: fund_transfer_flaws
Difficulty: Easy
OWASP: A01:2021 Broken Access Control (CSRF) + business logic (amount
       validation) -- deliberately two findings on one realistic
       endpoint, since that's how real assessments actually go: one
       feature, multiple issues.
CWE: CWE-352 (CSRF) + CWE-841 (Improper Enforcement of Behavioral
     Workflow -- missing amount validation)

Business context: customers transfer funds to a saved beneficiary.
No CSRF token exists on the form (paired with config.py's
SESSION_COOKIE_SAMESITE = "None", which is what makes the CSRF
actually exploitable cross-site -- see docs). Separately, the amount
field is never validated as positive, so submitting a negative number
increases the sender's own balance instead of decreasing it.

Player path (CSRF): host the provided csrf_poc.html anywhere, get a
logged-in victim to open it, their browser silently submits a
transfer using their session cookie.

Player path (business logic): submit amount=-5000 for your own
account and watch your balance increase instead of decrease.
"""
from decimal import Decimal, InvalidOperation

from flask import Blueprint, request, jsonify, session, abort

from app import db
from app.core.models import User
from modules.idor_beneficiary.models import Beneficiary

bp = Blueprint("fund_transfer_flaws", __name__)


def _require_login():
    if "user_id" not in session:
        abort(401)


@bp.route("/transfer", methods=["POST"])
def transfer():
    """
    VULNERABLE (x2):
    1. No CSRF token -- only relies on the session cookie, which is
       sent cross-site because SESSION_COOKIE_SAMESITE = "None".
    2. No check that `amount` is positive.
    """
    _require_login()
    user = User.query.get(session["user_id"])

    data = request.get_json(silent=True) or request.form
    beneficiary_id = data.get("beneficiary_id")
    raw_amount = data.get("amount")

    beneficiary = Beneficiary.query.filter_by(id=beneficiary_id, owner_id=user.id).first()
    if not beneficiary:
        return jsonify({"error": "beneficiary not found"}), 404

    try:
        amount = Decimal(str(raw_amount))
    except (InvalidOperation, TypeError):
        return jsonify({"error": "invalid amount"}), 400

    # Insufficient-funds check, but read-then-write with NO row lock
    # (no with_for_update()) -- this is what makes double-spending via
    # concurrent requests possible (see race_condition_double_spend
    # module). Two requests can both read the same starting balance
    # and both pass this check before either commits.
    current_balance = user.balance or Decimal("0")
    if amount > 0 and current_balance < amount:
        return jsonify({"error": "insufficient funds"}), 400

    # THE BUG: no `if amount <= 0: reject` check here.
    user.balance = current_balance - amount
    db.session.commit()

    return jsonify({
        "message": f"Transferred {amount} to {beneficiary.name}",
        "new_balance": str(user.balance),
    }), 200


@bp.route("/account/balance")
def balance():
    _require_login()
    user = User.query.get(session["user_id"])
    return jsonify({"balance": str(user.balance)})


def register_reset():
    User.query.update({User.balance: 5000.00})
    db.session.commit()
