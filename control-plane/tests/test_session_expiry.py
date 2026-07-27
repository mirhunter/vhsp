"""Tests for the idle-session timeout on the operator admin UI.

The property that actually matters is that expiry is enforced
*server-side*, on the signed cookie's own timestamp, rather than being a
client-side `Expires` attribute a browser is trusted to honour. A cookie
captured before it expired must stop working afterwards even when
replayed by something that ignores cookie attributes entirely -- which is
the whole threat being defended against.
"""

from datetime import timedelta

import pytest

from vhsp_ctl import config, web


@pytest.fixture
def client():
    web.app.config["TESTING"] = True
    return web.app.test_client()


def test_a_session_lifetime_is_configured_at_all():
    """Flask's default is 31 days, so an unset lifetime is not "no expiry"
    -- it's a very long one. This asserts the deployment actually narrows
    it rather than inheriting that default."""
    lifetime = web.app.config["PERMANENT_SESSION_LIFETIME"]
    assert lifetime == timedelta(minutes=config.ADMIN_SESSION_LIFETIME_MINUTES)
    assert lifetime < timedelta(days=1), "session lifetime should be an idle timeout, not days"


def test_sessions_are_marked_permanent(client):
    """Without session.permanent, PERMANENT_SESSION_LIFETIME is ignored
    entirely and the cookie carries no expiry."""
    with client:
        client.get("/login")
        from flask import session
        assert session.permanent


def test_expiry_is_enforced_server_side_not_just_by_the_cookie(monkeypatch):
    """A cookie replayed after its lifetime must be rejected by the server
    on its own signed timestamp, regardless of what the client does with
    cookie attributes."""
    monkeypatch.setitem(web.app.config, "PERMANENT_SESSION_LIFETIME", timedelta(seconds=-1))

    established = web.app.test_client()
    with established.session_transaction() as sess:
        sess["username"] = "admin"
    cookie = established.get_cookie("session").value

    replay = web.app.test_client()
    replay.set_cookie("session", cookie, domain="localhost")
    # Any authenticated route will do; /account redirects to /login when
    # the session isn't accepted.
    response = replay.get("/account")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_a_live_session_is_accepted(client):
    """The other half of the assertion above -- proves the rejection test
    is detecting expiry rather than a session that never worked."""
    with client.session_transaction() as sess:
        sess["username"] = "admin"
    assert client.get("/account").status_code == 200


def test_the_pending_2fa_state_expires_too(monkeypatch):
    """`pending_username` is set after a correct password but before the
    second factor. It's a partial credential and must not outlive the
    session lifetime either."""
    monkeypatch.setitem(web.app.config, "PERMANENT_SESSION_LIFETIME", timedelta(seconds=-1))

    established = web.app.test_client()
    with established.session_transaction() as sess:
        sess["pending_username"] = "admin"
    cookie = established.get_cookie("session").value

    replay = web.app.test_client()
    replay.set_cookie("session", cookie, domain="localhost")
    response = replay.get("/login/2fa")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
