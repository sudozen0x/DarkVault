"""
Core User model. Every chained module (IDOR, JWT attacks, broken
auth, priv-esc) reads/writes this table, so schema changes here
ripple everywhere -- treat this as a stable contract once modules
start depending on it.
"""
from datetime import datetime

from app import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    # "customer" | "support" | "admin" -- kept as a plain string, not
    # an enum, on purpose: a broken-access-control module can exploit
    # a mass-assignment / role-tampering bug more naturally against
    # a free-text field than a strict enum.
    role = db.Column(db.String(20), nullable=False, default="customer")
    balance = db.Column(db.Numeric(12, 2), default=5000.00)

    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(64), nullable=True)

    failed_login_count = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_public_dict(self):
        """Safe subset for API responses -- never include password_hash
        or mfa_secret here. Modules that DO leak these do so by
        deliberately calling __dict__ or a raw query instead of this
        helper, keeping the vuln explicit in the module's own code."""
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
        }
