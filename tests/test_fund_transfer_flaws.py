import pytest


@pytest.fixture
def app():
    from app import create_app, db
    from app.core.models import User
    from modules.idor_beneficiary.models import Beneficiary
    from werkzeug.security import generate_password_hash

    application = create_app(config_object="config.TestConfig")
    application.config["TESTING"] = True

    with application.app_context():
        db.drop_all()
        db.create_all()
        db.session.add(User(id=1, username="attacker", email="a@test.local",
                             password_hash=generate_password_hash("Password123!"), role="customer", balance=5000.00))
        db.session.add(Beneficiary(id=101, owner_id=1, name="J. Perera", account_number="8001223344", bank_name="Commercial Bank"))
        db.session.commit()
        yield application


@pytest.fixture
def client(app):
    return app.test_client()


def _login(client):
    client.post("/login", data={"username": "attacker", "password": "Password123!"})


def test_normal_transfer_decreases_balance(client):
    _login(client)
    resp = client.post("/transfer", json={"beneficiary_id": 101, "amount": 500})
    assert resp.status_code == 200
    assert resp.get_json()["new_balance"] == "4500.00"


def test_negative_amount_increases_balance_instead_of_decreasing(client):
    """THE BUSINESS LOGIC VULNERABILITY."""
    _login(client)
    resp = client.post("/transfer", json={"beneficiary_id": 101, "amount": -1000})
    assert resp.status_code == 200
    new_balance = float(resp.get_json()["new_balance"])
    assert new_balance == 6000.00  # went UP, not down


def test_insufficient_funds_rejected_for_positive_amount(client):
    _login(client)
    resp = client.post("/transfer", json={"beneficiary_id": 101, "amount": 999999})
    assert resp.status_code == 400


def test_transfer_requires_login(client):
    resp = client.post("/transfer", json={"beneficiary_id": 101, "amount": 100})
    assert resp.status_code == 401


def test_session_cookie_samesite_is_none(app):
    """Confirms the paired config that makes the CSRF actually
    exploitable cross-site (see docs/csrf_poc.html)."""
    assert app.config["SESSION_COOKIE_SAMESITE"] == "None"
