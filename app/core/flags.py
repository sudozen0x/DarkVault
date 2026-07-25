"""
Core flags/scoreboard system ("Operator Dashboard" in the NULLWAVE
framing). This is the ONLY place in the codebase where the theme
touches actual UI -- the bank app itself stays realistic.
"""
import hashlib
import os

from flask import Blueprint, jsonify, request, session, abort

from app import db
from app.core.contracts import CONTRACTS
from app.core.models import SolvedFlag

flags_bp = Blueprint("flags", __name__)

FLAGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "flags")

# modules whose flag is verified by reading a file at exploit-time
# (RCE / arbitrary file read) rather than a fixed hash -- the player
# submits whatever plaintext their exploit actually returned, and we
# check it against the file's live content.
FILE_BACKED_MODULES = {
    "xxe_kyc_xml": "xxe_flag.txt",
    "ssti_notification": "ssti_flag.txt",
    "insecure_deserialization_admin_import": "deserialization_flag.txt",
}


def _require_login():
    if "user_id" not in session:
        abort(401)


def _expected_flag_hash(module_name: str) -> str | None:
    """Returns the sha256 hash to check a submission against, or None
    if this module has no directly-submittable flag (e.g. capstone,
    which is derived from prerequisites instead)."""
    contract = CONTRACTS.get(module_name)
    if not contract:
        return None

    if module_name in FILE_BACKED_MODULES:
        path = os.path.join(FLAGS_DIR, FILE_BACKED_MODULES[module_name])
        try:
            with open(path) as f:
                return hashlib.sha256(f.read().strip().encode()).hexdigest()
        except FileNotFoundError:
            return None

    return contract.get("flag_hash")


@flags_bp.route("/contracts")
def list_contracts():
    """The 'mission board' -- every module's briefing, tier, and
    solved status for the current player. Never exposes flag hashes
    or plaintext."""
    _require_login()
    solved = {
        row.module_name
        for row in SolvedFlag.query.filter_by(user_id=session["user_id"]).all()
    }

    result = []
    for name, contract in CONTRACTS.items():
        entry = {
            "module": name,
            "tier": contract["tier"],
            "title": contract["title"],
            "briefing": contract["briefing"],
            "solved": name in solved,
        }
        if "requires" in contract:
            entry["requires"] = contract["requires"]
            entry["solved"] = all(r in solved for r in contract["requires"])
        result.append(entry)

    return jsonify(result)


@flags_bp.route("/flags/submit", methods=["POST"])
def submit_flag():
    _require_login()
    data = request.get_json(silent=True) or request.form
    module_name = data.get("module", "")
    submitted_flag = data.get("flag", "").strip()

    if module_name not in CONTRACTS:
        return jsonify({"error": "unknown contract"}), 404

    if "requires" in CONTRACTS[module_name]:
        return jsonify({"error": "this contract has no directly submittable flag -- complete its prerequisites instead"}), 400

    expected_hash = _expected_flag_hash(module_name)
    if expected_hash is None:
        return jsonify({"error": "flag not configured for this contract"}), 500

    submitted_hash = hashlib.sha256(submitted_flag.encode()).hexdigest()
    if submitted_hash != expected_hash:
        return jsonify({"correct": False}), 200

    existing = SolvedFlag.query.filter_by(user_id=session["user_id"], module_name=module_name).first()
    if not existing:
        db.session.add(SolvedFlag(user_id=session["user_id"], module_name=module_name))
        db.session.commit()

    return jsonify({"correct": True}), 200


@flags_bp.route("/progress")
def progress():
    _require_login()
    solved = {
        row.module_name
        for row in SolvedFlag.query.filter_by(user_id=session["user_id"]).all()
    }

    by_tier = {}
    for name, contract in CONTRACTS.items():
        tier = contract["tier"]
        by_tier.setdefault(tier, {"solved": 0, "total": 0})
        by_tier[tier]["total"] += 1

        is_solved = name in solved
        if "requires" in contract:
            is_solved = all(r in solved for r in contract["requires"])
        if is_solved:
            by_tier[tier]["solved"] += 1

    total_solved = sum(t["solved"] for t in by_tier.values())
    total = sum(t["total"] for t in by_tier.values())

    from app.core.models import User
    user = User.query.get(session["user_id"])

    return jsonify({
        "operator": user.username if user else "unknown",
        "targets_breached": total_solved,
        "total_contracts": total,
        "by_tier": by_tier,
    })
