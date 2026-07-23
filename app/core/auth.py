"""
Core auth. Deliberately the ONLY place session cookies get minted,
so vuln modules that need to *break* auth (JWT alg confusion, IDOR
via predictable session IDs, etc.) can do so by calling into these
helpers rather than reimplementing auth per-module.

Kept intentionally correct/secure -- broken-auth modules should
override specific behaviors in their own route (e.g.
modules/broken_login_ratelimit/routes.py registers its own POST
/login that skips the lockout check below), not weaken this file.
"""
from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from werkzeug.security import check_password_hash, generate_password_hash

from app import db
from app.core.models import User

auth_bp = Blueprint("auth", __name__, template_folder="templates")

MAX_FAILED_ATTEMPTS = 5


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or len(password) < 8:
            flash("Username, email, and a password of at least 8 characters are required.")
            return render_template("auth/register.html")

        if User.query.filter((User.username == username) | (User.email == email)).first():
            # Same generic message for "username taken" vs "email taken" --
            # a module further down the pipeline (username_enumeration)
            # deliberately weakens THIS check to demonstrate the enum flaw;
            # core stays safe by default.
            flash("Registration failed. Please try different details.")
            return render_template("auth/register.html")

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role="customer",
        )
        db.session.add(user)
        db.session.commit()
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()

        if user and user.is_locked:
            flash("Account locked due to repeated failed attempts. Contact support.")
            return render_template("auth/login.html")

        if user and check_password_hash(user.password_hash, password):
            user.failed_login_count = 0
            db.session.commit()

            session.clear()
            session["user_id"] = user.id
            session["role"] = user.role

            if user.mfa_enabled:
                session["mfa_pending"] = True
                return redirect(url_for("auth.mfa_verify"))

            return redirect(url_for("dashboard.index"))

        # Generic failure message regardless of whether username existed --
        # keeps core resistant to username enumeration by default.
        if user:
            user.failed_login_count = (user.failed_login_count or 0) + 1
            if user.failed_login_count >= MAX_FAILED_ATTEMPTS:
                user.is_locked = True
            db.session.commit()

        flash("Invalid username or password.")
        return render_template("auth/login.html")

    return render_template("auth/login.html")


@auth_bp.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    # TODO: modules/mfa_bypass or similar owns the real TOTP logic and
    # the intentional bypass flaw. Core just gates the session here.
    if not session.get("mfa_pending"):
        return redirect(url_for("auth.login"))
    return render_template("auth/mfa_verify.html")


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
