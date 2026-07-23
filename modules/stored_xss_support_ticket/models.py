from datetime import datetime

from app import db


class SupportTicket(db.Model):
    __tablename__ = "support_tickets"

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    subject = db.Column(db.String(200))
    message = db.Column(db.Text)  # VULNERABLE FIELD: rendered with |safe in admin queue
    status = db.Column(db.String(20), default="open")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class CollectedSession(db.Model):
    """
    Stands in for an attacker-controlled external listener. In a real
    engagement this would be a server you host outside the target;
    here it's embedded so the full stored-XSS -> session-theft chain
    is completable inside one closed training environment.
    """
    __tablename__ = "collected_sessions"

    id = db.Column(db.Integer, primary_key=True)
    cookie_value = db.Column(db.Text)
    source_note = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
