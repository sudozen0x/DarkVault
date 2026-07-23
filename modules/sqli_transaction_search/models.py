from datetime import datetime

from app import db


class Transaction(db.Model):
    __tablename__ = "transactions"

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    description = db.Column(db.String(200))
    amount = db.Column(db.Numeric(10, 2))
    txn_date = db.Column(db.DateTime, default=datetime.utcnow)
    category = db.Column(db.String(50))  # not selected by the vulnerable query -- realism only
