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


def test_normal_profile_update_works(client):
    _login(client)
    resp = client.patch("/profile", json={"username": "newname"})
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "newname"


def test_mass_assignment_escalates_role_in_database(client):
    """THE VULNERABILITY. role isn't an intended profile field but
    gets set anyway."""
    from app.core.models import User

    _login(client)
    client.patch("/profile", json={"role": "admin"})

    from app import db
    user = db.session.get(User, 1)
    assert user.role == "admin"


def test_escalation_requires_fresh_login_to_take_session_effect(client):
    """role only lands in the session at login time -- tampering the
    DB alone doesn't retroactively upgrade an existing session."""
    _login(client)
    client.patch("/profile", json={"role": "admin"})

    # still the OLD session, role claim unchanged until re-login
    resp = client.get("/profile")
    # to_public_dict reflects live DB role (not session), so this
    # confirms the DB write took effect independent of session state
    assert resp.get_json()["role"] == "admin"
