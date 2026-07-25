from unittest.mock import patch, Mock
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
        db.session.add(User(id=1, username="attacker", email="a@test.local",
                             password_hash=generate_password_hash("Password123!"), role="customer"))
        db.session.commit()
        yield application


@pytest.fixture
def client(app):
    return app.test_client()


def _login(client):
    client.post("/login", data={"username": "attacker", "password": "Password123!"})


def test_requires_login(client):
    resp = client.post("/statements/import-from-url", json={"url": "http://example.com"})
    assert resp.status_code == 401


def test_ssrf_fetches_arbitrary_url_no_allowlist(client):
    """THE VULNERABILITY. No domain allowlist -- server fetches
    whatever URL is given, including internal-only hosts (mocked
    here since internal-service isn't reachable from this test
    sandbox; real verification happens live under docker-compose)."""
    _login(client)

    fake_response = Mock()
    fake_response.text = '{"admin_api_key": "sk_internal_7f2a9c1e4b"}'

    with patch("modules.ssrf_statement_fetch.routes.requests.get", return_value=fake_response) as mock_get:
        resp = client.post("/statements/import-from-url", json={
            "url": "http://internal-service:9000/internal/admin-creds"
        })
        assert resp.status_code == 200
        assert "admin_api_key" in resp.get_json()["preview"]
        # confirms NO validation happened on the URL before fetching
        mock_get.assert_called_once_with("http://internal-service:9000/internal/admin-creds", timeout=5)


def test_missing_url_rejected(client):
    _login(client)
    resp = client.post("/statements/import-from-url", json={})
    assert resp.status_code == 400
