"""
Module: ssrf_statement_fetch
Difficulty: Hard
OWASP: A10:2021 Server-Side Request Forgery
CWE: CWE-918

Business context: customers can import a statement from an external
partner institution by providing a URL (a real feature pattern --
"link your other bank" flows often fetch server-side). The endpoint
makes an unrestricted server-side HTTP request to whatever URL is
given, with no allowlist and no blocking of internal/private
address ranges.

This is the intended path into `internal_service` -- a Docker
service on the `backnet` network with no host port mapping (see
docker-compose.yml), unreachable directly from outside the Docker
network. This endpoint is the only way in.

Player path: POST a URL pointing at the internal service instead of
a real external statement provider.
"""
import requests
from flask import Blueprint, request, jsonify, session, abort, current_app

bp = Blueprint("ssrf_statement_fetch", __name__)


@bp.route("/statements/import-from-url", methods=["POST"])
def import_statement_from_url():
    if "user_id" not in session:
        abort(401)

    data = request.get_json(silent=True) or request.form
    url = data.get("url", "")

    if not url:
        return jsonify({"error": "url is required"}), 400

    # VULNERABLE: no allowlist of external domains, no check against
    # internal/private IP ranges or the internal-service hostname.
    try:
        resp = requests.get(url, timeout=5)
        preview = resp.text[:2000]
    except requests.RequestException as e:
        return jsonify({"error": f"could not fetch statement: {e}"}), 502

    return jsonify({"message": "Statement imported", "preview": preview}), 200
