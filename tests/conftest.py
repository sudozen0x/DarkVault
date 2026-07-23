import os
import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/darkvault_test.db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/1")


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
        db.session.add_all([
            User(id=1, username="attacker", email="attacker@test.local",
                 password_hash=generate_password_hash("Password123!"), role="customer"),
            User(id=2, username="victim", email="victim@test.local",
                 password_hash=generate_password_hash("Password123!"), role="customer"),
        ])
        db.session.add_all([
            Beneficiary(id=101, owner_id=1, name="J. Perera", account_number="8001223344", bank_name="Commercial Bank"),
            Beneficiary(id=102, owner_id=2, name="A. Fernando", account_number="FLAG-ACCT-9911223", bank_name="Sampath Bank"),
        ])
        db.session.commit()
        yield application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def attacker_client(client):
    client.post("/login", data={"username": "attacker", "password": "Password123!"})
    return client
