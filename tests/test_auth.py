"""
Regression coverage for core auth. These protect the SECURE parts of
the app (password hashing, generic failure messages, lockout) --
individual vuln modules get their own test files that assert the
INTENTIONAL vulnerability still behaves as designed.
"""


def test_login_succeeds_with_correct_password(client):
    resp = client.post("/login", data={"username": "attacker", "password": "Password123!"},
                        follow_redirects=True)
    assert resp.status_code == 200
    assert b"Welcome" in resp.data


def test_login_rejects_wrong_password(client):
    resp = client.post("/login", data={"username": "attacker", "password": "wrong"})
    assert b"Invalid username or password" in resp.data


def test_login_failure_message_identical_for_unknown_user(client):
    """
    Core auth must not leak whether a username exists -- this is the
    control that a dedicated username_enumeration module should
    later demonstrate breaking via a *different* endpoint (e.g.
    /register's duplicate-email check), not by weakening this one.
    """
    resp_unknown = client.post("/login", data={"username": "nobody", "password": "x"})
    resp_wrong_pw = client.post("/login", data={"username": "attacker", "password": "x"})
    assert resp_unknown.data == resp_wrong_pw.data


def test_account_locks_after_five_failed_attempts(client):
    for _ in range(5):
        client.post("/login", data={"username": "attacker", "password": "wrong"})

    resp = client.post("/login", data={"username": "attacker", "password": "Password123!"})
    assert b"Account locked" in resp.data


def test_dashboard_redirects_to_login_when_unauthenticated(client):
    resp = client.get("/dashboard")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]
