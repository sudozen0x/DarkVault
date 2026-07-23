from datetime import datetime, timedelta

from app import db
from .models import Transaction


def run_seed(_db):
    Transaction.query.delete()
    now = datetime.utcnow()
    db.session.add_all([
        Transaction(customer_id=1, description="Grocery Store Purchase", amount=45.20,
                    txn_date=now - timedelta(days=1), category="shopping"),
        Transaction(customer_id=1, description="Salary Deposit", amount=2500.00,
                    txn_date=now - timedelta(days=3), category="income"),
        Transaction(customer_id=1, description="Electric Bill Payment", amount=112.50,
                    txn_date=now - timedelta(days=5), category="bills"),
        Transaction(customer_id=2, description="Rent Payment", amount=900.00,
                    txn_date=now - timedelta(days=2), category="bills"),
    ])
    db.session.commit()
