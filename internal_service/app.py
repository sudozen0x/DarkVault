"""
Simulates an internal-only service (e.g. a legacy core-banking API or
cloud metadata endpoint) that should never be reachable from outside
backnet. SSRF modules in the main app (e.g. "download statement from
URL" feature) are the only intended path in.
"""
from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/internal/admin-creds")
def admin_creds():
    # Realistic "found it" payoff for an SSRF chain -- not a labeled flag,
    # just internal-looking data that has to be recognized as sensitive.
    return jsonify({
        "service": "core-banking-gateway",
        "admin_api_key": "sk_internal_7f2a9c1e4b",
        "note": "internal use only - do not expose externally"
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
