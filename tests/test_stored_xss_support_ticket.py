"""
Coverage for modules/stored_xss_support_ticket. Verifies:
- customer's own view escapes correctly (control case, should stay safe)
- admin queue does NOT escape (the intentional vuln -- locks it in)
- the collector endpoint mechanics work (stand-in for exfil listener)
- the missing-HttpOnly config that makes the chain completable
"""
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


PAYLOAD = "<script>alert(document.domain)</script>"


def _login(client, username, password):
    return client.post("/login", data={"username": username, "password": password})


def test_customer_view_escapes_payload(client):
    _login(client, "attacker", "Password123!")
    client.post("/support", data={"subject": "test", "message": PAYLOAD})

    resp = client.get("/support")
    # Jinja autoescape should turn this into &lt;script&gt;
    assert b"<script>alert" not in resp.data
    assert b"&lt;script&gt;" in resp.data


def test_admin_queue_does_not_escape_payload(client):
    """THE VULNERABILITY. Admin queue renders |safe -- raw <script> tag
    must appear unescaped in the response body."""
    _login(client, "attacker", "Password123!")
    client.post("/support", data={"subject": "test", "message": PAYLOAD})
    client.get("/logout")

    _login(client, "admin", "ChangeMe_Admin!2024")
    resp = client.get("/admin/support")
    assert resp.status_code == 200
    assert PAYLOAD.encode() in resp.data


def test_non_admin_cannot_view_admin_queue(client):
    _login(client, "attacker", "Password123!")
    resp = client.get("/admin/support")
    assert resp.status_code == 403


def test_collector_stores_and_returns_exfiltrated_cookie(client):
    """Simulates the injected script's fetch() call and the attacker
    retrieving it -- this is the mechanism the real payload relies on."""
    resp = client.post("/api/support/collector", json={"cookie": "session=abc123stolen"})
    assert resp.status_code == 200

    resp = client.get("/api/support/collector")
    data = resp.get_json()
    assert any("abc123stolen" in entry["cookie_value"] for entry in data)


def test_session_cookie_is_not_httponly(app):
    """
    Confirms the paired misconfiguration that makes this chain
    completable at all -- if this ever flips back to True, the XSS
    can deface pages but can no longer steal the session.
    """
    assert app.config["SESSION_COOKIE_HTTPONLY"] is False
