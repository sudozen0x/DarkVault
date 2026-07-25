import pytest


@pytest.fixture
def app():
    from app import create_app, db
    from app.core.models import User
    from modules.idor_beneficiary.models import Beneficiary
    from werkzeug.security import generate_password_hash

    application = create_app(config_object="config.TestConfig")
    application.config["TESTING"] = True

    with application.app_context():
        db.drop_all()
        db.create_all()
        db.session.add(User(id=1, username="attacker", email="a@test.local",
                             password_hash=generate_password_hash("Password123!"), role="customer"))
        db.session.add(Beneficiary(id=102, owner_id=2, name="A. Fernando",
                                    account_number="DARKVAULT{1d0r_by_4ny_0th3r_n4m3}", bank_name="Sampath Bank"))
        db.session.commit()
        yield application


@pytest.fixture
def client(app):
    return app.test_client()


def _login(client):
    client.post("/login", data={"username": "attacker", "password": "Password123!"})


def test_contracts_list_requires_login(client):
    resp = client.get("/contracts")
    assert resp.status_code == 401


def test_contracts_list_shows_all_modules_unsolved_by_default(client):
    _login(client)
    resp = client.get("/contracts")
    data = resp.get_json()
    assert len(data) == 14  # 13 modules + capstone
    assert all(c["solved"] is False for c in data)


def test_correct_flag_submission_marks_solved(client):
    _login(client)
    resp = client.post("/flags/submit", json={
        "module": "idor_beneficiary", "flag": "DARKVAULT{1d0r_by_4ny_0th3r_n4m3}",
    })
    assert resp.status_code == 200
    assert resp.get_json()["correct"] is True

    contracts = client.get("/contracts").get_json()
    idor = next(c for c in contracts if c["module"] == "idor_beneficiary")
    assert idor["solved"] is True


def test_incorrect_flag_submission_not_marked_solved(client):
    _login(client)
    resp = client.post("/flags/submit", json={
        "module": "idor_beneficiary", "flag": "DARKVAULT{wrong_guess}",
    })
    assert resp.status_code == 200
    assert resp.get_json()["correct"] is False


def test_unknown_module_rejected(client):
    _login(client)
    resp = client.post("/flags/submit", json={"module": "not_a_real_module", "flag": "x"})
    assert resp.status_code == 404


def test_capstone_cannot_be_submitted_directly(client):
    _login(client)
    resp = client.post("/flags/submit", json={"module": "capstone_chain", "flag": "anything"})
    assert resp.status_code == 400


def test_capstone_solves_automatically_once_prerequisites_met(client):
    _login(client)
    # simulate solving the 3 prerequisite modules directly via DB
    from app import db
    from app.core.models import SolvedFlag
    for module_name in ["mass_assignment_role", "insecure_deserialization_admin_import", "fund_transfer_flaws"]:
        db.session.add(SolvedFlag(user_id=1, module_name=module_name))
    db.session.commit()

    contracts = client.get("/contracts").get_json()
    capstone = next(c for c in contracts if c["module"] == "capstone_chain")
    assert capstone["solved"] is True


def test_progress_tracks_solved_count_by_tier(client):
    _login(client)
    client.post("/flags/submit", json={
        "module": "idor_beneficiary", "flag": "DARKVAULT{1d0r_by_4ny_0th3r_n4m3}",
    })

    resp = client.get("/progress")
    data = resp.get_json()
    assert data["targets_breached"] == 1
    assert data["total_contracts"] == 14
    assert data["by_tier"]["Easy"]["solved"] == 1


def test_resubmitting_same_flag_does_not_duplicate_solve(client):
    _login(client)
    for _ in range(3):
        client.post("/flags/submit", json={
            "module": "idor_beneficiary", "flag": "DARKVAULT{1d0r_by_4ny_0th3r_n4m3}",
        })

    from app.core.models import SolvedFlag
    count = SolvedFlag.query.filter_by(user_id=1, module_name="idor_beneficiary").count()
    assert count == 1
