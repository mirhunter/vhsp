"""Tests for forcing an operator to replace a password somebody else set.

A generated password reaches its owner through a terminal, a flash
message, a chat window -- it is known to more than one party by the time
it is first used. The flag makes replacing it mandatory rather than
remembered.

The gate is the part worth testing hardest. It has to hold on *every*
route rather than the handful anyone thought to decorate, it must not
interfere with the 2FA challenge (which runs before session['username']
exists), and it must not strand an operator on a page demanding something
that isn't required.
"""

import pytest

from vhsp_ctl import auth


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "OPERATORS_PATH", tmp_path / "operators.json")
    monkeypatch.setattr(auth, "LEGACY_CREDENTIALS_PATH", tmp_path / "admin_credentials.json")
    monkeypatch.setattr(auth.audit, "AUDIT_LOG_PATH", tmp_path / "audit.log")


# --- the flag itself ---------------------------------------------------

def test_a_new_operator_must_change_its_generated_password(store):
    auth.create_operator("newop")
    assert auth.must_change_password("newop")


def test_choosing_your_own_password_clears_the_flag(store):
    auth.create_operator("newop")
    auth.set_password("newop", "a-password-they-chose")
    assert not auth.must_change_password("newop")


def test_a_reset_by_someone_else_re_arms_the_flag(store):
    auth.create_operator("newop")
    auth.set_password("newop", "self-chosen")
    assert not auth.must_change_password("newop")

    auth.set_password("newop", "reset-by-a-colleague", must_change=True)
    assert auth.must_change_password("newop")


def test_the_flag_does_not_affect_password_verification(store):
    """The forced change is a gate on what you can reach afterwards, not
    a reason to reject a correct password at login -- otherwise the
    operator could never get far enough to change it."""
    auth.create_operator("newop")
    auth.set_password("newop", "known-password", must_change=True)
    assert auth.check("newop", "known-password")


def test_operators_predating_this_feature_are_not_locked_out(store):
    """Absent key reads as False, so no migration is needed and shipping
    this doesn't retroactively demand a password cycle from everyone."""
    auth.create_operator("existing")
    operators = auth._load()
    del operators["existing"]["must_change_password"]
    auth._write(operators)

    assert not auth.must_change_password("existing")


def test_unknown_operator_is_not_reported_as_needing_a_change(store):
    assert not auth.must_change_password("no-such-operator")


# --- the gate in the web UI -------------------------------------------

@pytest.fixture
def client(store, monkeypatch):
    from vhsp_ctl import web
    web.app.config["TESTING"] = True
    monkeypatch.setattr(web.auth, "OPERATORS_PATH", auth.OPERATORS_PATH)
    monkeypatch.setattr(web.auth, "LEGACY_CREDENTIALS_PATH", auth.LEGACY_CREDENTIALS_PATH)
    return web.app.test_client()


def _logged_in(client, username="newop"):
    with client.session_transaction() as sess:
        sess["username"] = username
    return client


@pytest.mark.parametrize("path", ["/", "/operators", "/backups", "/dns", "/audit", "/account"])
def test_every_page_redirects_to_the_change_form_while_pending(client, path):
    auth.create_operator("newop")
    _logged_in(client)
    response = client.get(path)
    assert response.status_code == 302
    assert "/password-change-required" in response.headers["Location"]


def test_logout_stays_reachable_while_pending(client):
    """An operator who doesn't want to set a password right now must
    still be able to leave rather than being trapped."""
    auth.create_operator("newop")
    _logged_in(client)
    with client.session_transaction() as sess:
        sess["csrf_token"] = "t"
    response = client.post("/logout", data={"csrf_token": "t"})
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_the_change_page_itself_is_reachable_while_pending(client):
    auth.create_operator("newop")
    _logged_in(client)
    assert client.get("/password-change-required").status_code == 200


def test_setting_a_new_password_lifts_the_gate(client):
    auth.create_operator("newop")
    _logged_in(client)
    with client.session_transaction() as sess:
        sess["csrf_token"] = "t"

    response = client.post("/password-change-required", data={
        "csrf_token": "t",
        "new_password": "a-long-enough-password",
        "confirm_password": "a-long-enough-password",
    })
    assert response.status_code == 302
    assert not auth.must_change_password("newop")
    assert client.get("/").status_code == 200


def test_the_new_password_must_meet_the_minimum_length(client):
    from vhsp_ctl.web import MIN_PASSWORD_LENGTH
    auth.create_operator("newop")
    _logged_in(client)
    with client.session_transaction() as sess:
        sess["csrf_token"] = "t"

    short = "x" * (MIN_PASSWORD_LENGTH - 1)
    response = client.post("/password-change-required", data={
        "csrf_token": "t", "new_password": short, "confirm_password": short,
    })
    assert response.status_code == 200
    assert auth.must_change_password("newop"), "gate must stay up on a rejected password"


def test_mismatched_confirmation_is_rejected(client):
    auth.create_operator("newop")
    _logged_in(client)
    with client.session_transaction() as sess:
        sess["csrf_token"] = "t"

    response = client.post("/password-change-required", data={
        "csrf_token": "t", "new_password": "a-long-enough-password",
        "confirm_password": "a-different-password",
    })
    assert response.status_code == 200
    assert auth.must_change_password("newop")


def test_the_page_sends_you_home_when_no_change_is_pending(client):
    auth.create_operator("newop")
    auth.set_password("newop", "self-chosen")
    _logged_in(client)
    response = client.get("/password-change-required")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_the_gate_does_not_fire_during_the_2fa_challenge(client):
    """The challenge runs on pending_username, before session['username']
    exists. If the gate keyed on the pending value it would redirect an
    operator away from 2FA and into a page requiring the login it hasn't
    finished."""
    auth.create_operator("newop")
    with client.session_transaction() as sess:
        sess["pending_username"] = "newop"
    response = client.get("/login/2fa")
    assert response.status_code == 200


def test_anonymous_visitors_are_unaffected(client):
    response = client.get("/login")
    assert response.status_code == 200
