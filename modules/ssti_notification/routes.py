"""
Module: ssti_notification
Difficulty: Hard
OWASP: A03:2021 Injection (Server-Side Template Injection)
CWE: CWE-1336

Business context: customers can set a display nickname used in
personalized notification previews. The preview handler builds the
Jinja2 template SOURCE by f-string-interpolating the nickname
directly, then renders it -- instead of passing the nickname as
template context data (the safe pattern used everywhere else in this
codebase, e.g. every other render_template() call in the app).

Player path: set nickname to a Jinja2 expression instead of a name.
`{{7*7}}` confirms injection (renders as 49). Full RCE is reachable
via standard Jinja2 SSTI technique, verified working against this
app's exact Jinja2 version (3.1.6) during development -- see docs.
"""
from flask import Blueprint, request, jsonify, session, abort, render_template_string

bp = Blueprint("ssti_notification", __name__)


@bp.route("/notifications/preview", methods=["POST"])
def preview_notification():
    if "user_id" not in session:
        abort(401)

    data = request.get_json(silent=True) or request.form
    nickname = data.get("nickname", "Customer")

    # VULNERABLE: nickname is embedded into the template SOURCE via
    # an f-string, then rendered -- instead of being passed as
    # context data to a static template string.
    template = f"<p>Hi {nickname}, you have new notifications waiting in your DarkVault inbox.</p>"
    rendered = render_template_string(template)

    return jsonify({"preview_html": rendered})
