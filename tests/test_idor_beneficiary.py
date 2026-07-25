"""
Test coverage for modules/idor_beneficiary.

Unlike normal app tests, this one asserts the VULNERABLE behavior is
present -- if someone (including future you) adds an ownership check
to app/modules/idor_beneficiary/routes.py, this test starts failing,
which is the point: it stops the challenge from being silently
patched by an unrelated refactor.
"""


def test_unauthenticated_request_is_rejected(client):
    resp = client.get("/api/beneficiaries/101")
    assert resp.status_code == 401


def test_owner_can_view_own_beneficiary(attacker_client):
    resp = attacker_client.get("/api/beneficiaries/101")
    assert resp.status_code == 200
    assert resp.get_json()["name"] == "J. Perera"


def test_idor_allows_viewing_other_users_beneficiary(attacker_client):
    """
    THE VULNERABILITY. attacker is logged in, requests beneficiary 102
    which belongs to victim (owner_id=2) -- no ownership check exists,
    so this succeeds and leaks victim's account data. This is the
    behavior the challenge is built around; it should stay green.
    """
    resp = attacker_client.get("/api/beneficiaries/102")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["name"] == "A. Fernando"
    assert body["account_number"] == "DARKVAULT{1d0r_by_4ny_0th3r_n4m3}"


def test_nonexistent_beneficiary_returns_404(attacker_client):
    resp = attacker_client.get("/api/beneficiaries/9999")
    assert resp.status_code == 404
