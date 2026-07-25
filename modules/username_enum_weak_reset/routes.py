"""
Module: username_enum_weak_reset
Difficulty: Easy
OWASP: A07:2021 Identification and Authentication Failures
CWE: CWE-204 (Username Enumeration) chained with CWE-640 (Weak
     Password Recovery Mechanism)

Business context: a legacy "forgot password" feature, separate from
core auth's login (which deliberately gives generic failure messages
-- see app/core/auth.py). This endpoint was added later by a
different dev and leaks whether an account exists, then generates a
reset token derived only from public/guessable values with no server
secret or expiry.

Player path:
1. POST /forgot-password with a guessed username -> compare response
   for a known-valid username (e.g. attacker) vs a made-up one.
2. Once a target username is confirmed to exist (e.g. "admin"), and
   given user IDs are small sequential integers (discoverable via
   other modules, e.g. IDOR), compute the reset token yourself:
   sha256(f"reset:{username}:{user_id}")[:16]
3. POST /reset-password with that token to set a new password.
4. Log in as the victim.
"""
import hashlib

from flask import Blueprint, request, jsonify

from app import db
from app.core.models import User

bp = Blueprint("username_enum_weak_reset", __name__)


def _compute_reset_token(username: str, user_id: int) -> str:
    # VULNERABLE: no server-side secret, no expiry, no randomness --
    # purely a function of values an attacker can already discover.
    return hashlib.sha256(f"reset:{username}:{user_id}".encode()).hexdigest()[:16]


@bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json(silent=True) or request.form
    username = data.get("username", "")

    user = User.query.filter_by(username=username).first()

    # VULNERABLE: existence leaked via distinguishable response.
    if not user:
        return jsonify({"error": "No account found with that username."}), 404

    masked_email = user.email[0] + "***@" + user.email.split("@")[-1]
    return jsonify({"message": f"Reset instructions sent to {masked_email}"}), 200


@bp.route("/reset-password", methods=["POST"])
def reset_password():
    from werkzeug.security import generate_password_hash

    data = request.get_json(silent=True) or request.form
    username = data.get("username", "")
    token = data.get("token", "")
    new_password = data.get("new_password", "")

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "invalid request"}), 400

    expected = _compute_reset_token(user.username, user.id)
    if token != expected:
        return jsonify({"error": "invalid or expired token"}), 400

    if len(new_password) < 8:
        return jsonify({"error": "password too short"}), 400

    user.password_hash = generate_password_hash(new_password)
    user.is_locked = False
    user.failed_login_count = 0
    db.session.commit()

    response = {"message": "password updated"}
    if user.username == "admin":
        response["flag"] = "DARKVAULT{f0rg0t_my_p4ssw0rd_4nd_my_ethics}"
    return jsonify(response), 200
