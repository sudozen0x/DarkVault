"""
Module: jwt_alg_confusion
Difficulty: Advanced
OWASP: A02:2021 Cryptographic Failures / A07:2021 Identification and
       Authentication Failures
CWE: CWE-347 (Improper Verification of Cryptographic Signature)

Business context: DarkVault's mobile app talks to a separate API
(/api/mobile/*) that uses JWT bearer tokens instead of the web app's
session cookies -- a common real pattern where mobile auth gets
bolted on separately from the original web session system, often by
a different team, years apart.

Player path:
1. GET /api/mobile/public-key -- legitimately exposed, mobile clients
   need it to verify tokens.
2. Log in via POST /api/mobile/login as a normal customer, inspect
   the JWT header -- note alg is RS256.
3. Realize the server accepts alg=HS256 too (see jwt_utils.verify_token),
   and that HS256 just needs a shared secret -- try the public key PEM
   itself as that secret (classic alg confusion, this is what jwt_tool's
   -X k flag automates).
4. Forge a token with role=admin, hit GET /api/mobile/admin/overview.
"""
from flask import Blueprint, request, jsonify

from werkzeug.security import check_password_hash

from app.core.models import User
from .jwt_utils import issue_token, verify_token, TokenError, PUBLIC_KEY_PEM

bp = Blueprint("jwt_alg_confusion", __name__, url_prefix="/api/mobile")


@bp.route("/public-key")
def public_key():
    return PUBLIC_KEY_PEM, 200, {"Content-Type": "text/plain"}


@bp.route("/login", methods=["POST"])
def mobile_login():
    data = request.get_json(silent=True) or request.form
    username = data.get("username", "")
    password = data.get("password", "")

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "invalid credentials"}), 401

    token = issue_token({"user_id": user.id, "username": user.username, "role": user.role})
    return jsonify({"token": token})


def _authenticated_claims():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[len("Bearer "):]
    try:
        return verify_token(token)
    except TokenError:
        return None


@bp.route("/account")
def mobile_account():
    claims = _authenticated_claims()
    if not claims:
        return jsonify({"error": "unauthorized"}), 401

    user = User.query.get(claims["user_id"])
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    return jsonify(user.to_public_dict())


@bp.route("/admin/overview")
def mobile_admin_overview():
    claims = _authenticated_claims()
    if not claims:
        return jsonify({"error": "unauthorized"}), 401
    if claims.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403

    # Realistic sensitive payload -- what an attacker is actually after
    # once they've forged their way in.
    total_customers = User.query.filter_by(role="customer").count()
    return jsonify({
        "total_customers": total_customers,
        "internal_note": "Q3 fraud review flagged 4 accounts for manual hold.",
        "system": "core-banking-gateway v2",
        "flag": "DARKVAULT{rs256_hs256_sh0uld_n3v3r_m33t}",
    })
