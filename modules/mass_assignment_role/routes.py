"""
Module: mass_assignment_role
Difficulty: Medium
OWASP: A08:2021 Software and Data Integrity Failures (mass assignment)
CWE: CWE-915 (Improperly Controlled Modification of Dynamically-
     Determined Object Attributes)

Business context: a "update your profile" feature lets customers
change their display username and email. The handler loops over
every field in the submitted JSON and sets it directly on the User
object -- convenient for the developer (no need to list allowed
fields explicitly), but it means any column name the client sends
gets applied, including `role`.

Player path: submit a profile update including "role": "admin" in
the JSON body. Nothing in the UI exposes this field, but the API
doesn't restrict it either.
"""
from flask import Blueprint, request, jsonify, session, abort

from app import db
from app.core.models import User

bp = Blueprint("mass_assignment_role", __name__)

ALLOWED_DISPLAY_FIELDS = {"username", "email"}  # intended allowlist -- never enforced below


@bp.route("/profile", methods=["GET"])
def get_profile():
    if "user_id" not in session:
        abort(401)
    user = User.query.get(session["user_id"])
    return jsonify(user.to_public_dict())


@bp.route("/profile", methods=["PATCH"])
def update_profile():
    if "user_id" not in session:
        abort(401)
    user = User.query.get(session["user_id"])

    data = request.get_json(silent=True) or {}

    was_admin_before = user.role == "admin"

    # VULNERABLE: iterates every submitted key and setattr()s it
    # directly, instead of only pulling from ALLOWED_DISPLAY_FIELDS.
    for key, value in data.items():
        if hasattr(user, key):
            setattr(user, key, value)

    db.session.commit()
    # Session role isn't refreshed automatically, but the DB is now
    # tampered -- next login (or a role check that re-reads from DB
    # instead of trusting the stale session value) reflects it.
    result = user.to_public_dict()
    if user.role == "admin" and not was_admin_before:
        result["flag"] = "DARKVAULT{pr0m0ted_mys3lf_n0_hr_n33ded}"
    return jsonify(result)
