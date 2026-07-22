"""
Module: idor_beneficiary
Difficulty: Beginner
OWASP: A01:2021 Broken Access Control / API1:2023 BOLA

Business context: authenticated customer views a saved beneficiary's
account details via GET /api/beneficiaries/<id>. No ownership check
is performed server-side, so any authenticated user can enumerate
<id> and read other customers' beneficiary PII/account numbers.

This module deliberately does NOT feel like a challenge -- it's just
the "beneficiaries" feature of the bank app. The player has to notice
the numeric ID in a normal API call during recon, not find a labeled
puzzle.
"""
from flask import Blueprint, jsonify, session, abort

from app import db
from .models import Beneficiary  # module-local model, migrated into shared schema

bp = Blueprint("idor_beneficiary", __name__, url_prefix="/api/beneficiaries")


@bp.route("/<int:beneficiary_id>")
def get_beneficiary(beneficiary_id):
    if "user_id" not in session:
        abort(401)

    # VULNERABLE: no `.filter_by(owner_id=session["user_id"])` check.
    beneficiary = Beneficiary.query.get_or_404(beneficiary_id)
    return jsonify(beneficiary.to_dict())


def register_reset():
    """Called by /admin reset tooling to restore this module's seed data."""
    from .seed import run_seed
    run_seed(db)
