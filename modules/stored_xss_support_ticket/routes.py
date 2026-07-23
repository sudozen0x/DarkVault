"""
Module: stored_xss_support_ticket
Difficulty: Intermediate
OWASP: A03:2021 Injection (XSS)
CWE: CWE-79 (Stored XSS), chained with CWE-1004 (missing HttpOnly,
     see config.py SESSION_COOKIE_HTTPONLY)

Business context: customers submit support tickets. Their own ticket
view escapes output correctly. The admin queue -- built later, by a
different "developer" in the fiction of this app -- renders message
bodies with `|safe` to support "rich text" customers were asking for.
Nobody revisited whether that was safe once tickets became
attacker-controlled input.

Player path: submit a ticket with a <script> payload that calls the
collector endpoint with document.cookie. Log in as admin (or ask an
"admin" to review tickets -- represents a real assessment scenario
where you'd get a colleague/support contact to trigger a blind XSS).
The payload fires in admin's real session, exfiltrates their cookie
to the collector, and the attacker retrieves it and hijacks the
admin session.
"""
from flask import Blueprint, render_template, request, session, redirect, url_for, jsonify, abort

from app import db
from .models import SupportTicket, CollectedSession

bp = Blueprint("stored_xss_support_ticket", __name__, template_folder="templates")


def _require_login():
    if "user_id" not in session:
        abort(401)


def _require_admin():
    if session.get("role") != "admin":
        abort(403)


@bp.route("/support", methods=["GET", "POST"])
def support_tickets():
    _require_login()

    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()
        ticket = SupportTicket(customer_id=session["user_id"], subject=subject, message=message)
        db.session.add(ticket)
        db.session.commit()
        return redirect(url_for("stored_xss_support_ticket.support_tickets"))

    tickets = SupportTicket.query.filter_by(customer_id=session["user_id"]).all()
    # Customer's own view escapes normally (Jinja autoescape, no |safe) --
    # this endpoint is NOT the vulnerable one.
    return render_template("support/list.html", tickets=tickets)


@bp.route("/admin/support")
def admin_support_queue():
    _require_login()
    _require_admin()

    tickets = SupportTicket.query.order_by(SupportTicket.created_at.desc()).all()
    # VULNERABLE: template renders ticket.message with |safe.
    return render_template("support/admin_queue.html", tickets=tickets)


@bp.route("/api/support/collector", methods=["POST"])
def collector_report():
    """
    Stands in for an attacker's external listener (see models.py).
    No auth on purpose -- an attacker's own infrastructure doesn't
    require the victim to authenticate to it.
    """
    data = request.get_json(silent=True) or {}
    cookie_value = data.get("cookie", "")[:2000]
    entry = CollectedSession(cookie_value=cookie_value, source_note=request.headers.get("User-Agent", "")[:200])
    db.session.add(entry)
    db.session.commit()
    return jsonify({"status": "received"})


@bp.route("/api/support/collector")
def collector_view():
    """Attacker checks their 'server' for exfiltrated sessions."""
    entries = CollectedSession.query.order_by(CollectedSession.created_at.desc()).all()
    return jsonify([{"id": e.id, "cookie_value": e.cookie_value, "created_at": e.created_at.isoformat()} for e in entries])


def register_reset():
    from app import db as _db
    SupportTicket.query.delete()
    CollectedSession.query.delete()
    _db.session.commit()
