"""
Core auth. Deliberately the ONLY place session cookies / JWTs get
minted, so vuln modules that need to *break* auth (JWT alg confusion,
IDOR via predictable session IDs, etc.) can do so by calling into
this module's helpers rather than reimplementing auth per-challenge.

Keep this file itself free of the vulnerabilities you're teaching --
individual modules should monkey-patch/override specific behaviors
(e.g. modules/jwt_alg_confusion/routes.py registers its own
/api/token endpoint with the weakened verification), not this core.
"""
from flask import Blueprint, render_template, request, session, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app import db

auth_bp = Blueprint("auth", __name__, template_folder="templates/auth")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # TODO: wire to User model once schema is finalized
        pass
    return render_template("auth/register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # TODO: replace with real lookup; keep this correct/secure --
        # broken-auth modules should override this route themselves,
        # not weaken it here.
        pass
    return render_template("auth/login.html")


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
