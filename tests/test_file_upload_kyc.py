import io
import shutil
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

    # clean up any files written during the test
    from modules.file_upload_kyc.routes import UPLOAD_DIR
    shutil.rmtree(UPLOAD_DIR, ignore_errors=True)


@pytest.fixture
def client(app):
    return app.test_client()


def _login(client):
    client.post("/login", data={"username": "attacker", "password": "Password123!"})


def test_upload_requires_login(client):
    resp = client.post("/kyc/upload", data={"document": (io.BytesIO(b"data"), "id.jpg")})
    assert resp.status_code == 401


def test_normal_image_upload_and_retrieval(client):
    _login(client)
    resp = client.post("/kyc/upload", data={"document": (io.BytesIO(b"fake image bytes"), "id.jpg")})
    assert resp.status_code == 200

    resp = client.get("/kyc/documents/id.jpg")
    assert resp.status_code == 200


def test_html_file_upload_served_as_html_not_downloaded():
    """THE VULNERABILITY. An uploaded .html file is served back with
    text/html content-type, rendering live instead of downloading."""
    from app import create_app
    app = create_app(config_object="config.TestConfig")
    with app.app_context():
        from app import db
        db.drop_all()
        db.create_all()
        from app.core.models import User
        from werkzeug.security import generate_password_hash
        db.session.add(User(id=1, username="attacker", email="a@test.local",
                             password_hash=generate_password_hash("Password123!"), role="customer"))
        db.session.commit()

    client = app.test_client()
    client.post("/login", data={"username": "attacker", "password": "Password123!"})

    payload = b"<html><body><script>alert(document.domain)</script></body></html>"
    client.post("/kyc/upload", data={"document": (io.BytesIO(payload), "phish.html")})

    resp = client.get("/kyc/documents/phish.html")
    assert resp.status_code == 200
    assert resp.content_type.startswith("text/html")
    assert b"<script>alert(document.domain)</script>" in resp.data

    from modules.file_upload_kyc.routes import UPLOAD_DIR
    shutil.rmtree(UPLOAD_DIR, ignore_errors=True)
