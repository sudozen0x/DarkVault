"""
Module: insecure_deserialization_admin_import
Difficulty: Advanced
OWASP: A08:2021 Software and Data Integrity Failures
CWE: CWE-502 (Deserialization of Untrusted Data)

Business context: a legacy admin tool lets support staff "restore" a
customer-data backup by uploading a pickled Python object (an old
internal migration tool that never got replaced). The endpoint
requires an admin session, but that's realistic, not a mitigation:
in a real assessment this is reached either by social-engineering an
admin into importing an attacker-supplied "backup" file, or by
chaining in via mass_assignment_role's privilege escalation first.

Verified working during development: pickle.loads() on a crafted
object's __reduce__ output achieves real command execution, not just
theoretical -- see docs for the exact payload used.
"""
import base64
import pickle

from flask import Blueprint, request, jsonify, session, abort

bp = Blueprint("insecure_deserialization_admin_import", __name__)


def _require_admin():
    if session.get("role") != "admin":
        abort(403)


@bp.route("/admin/import-data", methods=["POST"])
def import_data():
    if "user_id" not in session:
        abort(401)
    _require_admin()

    data = request.get_json(silent=True) or {}
    encoded_payload = data.get("payload", "")
    if not encoded_payload:
        return jsonify({"error": "payload required"}), 400

    try:
        raw = base64.b64decode(encoded_payload)
        # VULNERABLE: pickle.loads() on data that ultimately traces
        # back to client input, even gated behind an admin check.
        # Deserialization itself executes arbitrary code via
        # __reduce__ -- the admin check doesn't prevent that, it just
        # narrows who could trigger it (a real admin tricked into
        # importing a bad file, or an attacker who chained in via
        # another privesc first).
        obj = pickle.loads(raw)
    except Exception as e:
        return jsonify({"error": f"failed to import: {e}"}), 400

    return jsonify({"message": "Data imported", "summary": str(obj)[:200]})
