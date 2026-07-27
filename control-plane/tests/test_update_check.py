"""Tests for the GitHub release check behind the operator update banner.

Two things carry real weight here. The version comparison decides whether
operators get nagged forever or never told at all, and the response
validation is the boundary where a remote JSON document becomes an href
in a root-equivalent admin UI. Neither is exercised by the happy path
alone, so most of what follows is the unhappy paths.

No test here makes a network request -- `requests.get` is always stubbed.
"""

import json

import pytest

from vhsp_ctl import update_check
from vhsp_ctl.update_check import UpdateCheckError, is_newer, parse_version


@pytest.fixture
def state_path(tmp_path, monkeypatch):
    path = tmp_path / "update_check.json"
    monkeypatch.setattr(update_check, "STATE_PATH", path)
    return path


class _Response:
    def __init__(self, status_code=200, payload=None, raise_json=False):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self._raise_json = raise_json

    def json(self):
        if self._raise_json:
            raise ValueError("not json")
        return self._payload


def _stub_get(monkeypatch, response=None, exc=None):
    def fake_get(url, **kwargs):
        assert url == update_check.RELEASES_API_URL
        assert kwargs.get("timeout"), "requests must always carry a timeout"
        if exc:
            raise exc
        return response
    monkeypatch.setattr(update_check.requests, "get", fake_get)


# --- version comparison ------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("1.2.3", (1, 2, 3)),
    ("v1.2.3", (1, 2, 3)),
    ("v0.1.0", (0, 1, 0)),
    ("  v2.0.0  ", (2, 0, 0)),
    ("1.2.3-rc1", (1, 2, 3)),      # suffix ignored, not parsed
    ("1.2.3+build7", (1, 2, 3)),
    ("v10.20.30", (10, 20, 30)),   # multi-digit, not lexical
])
def test_parse_version_accepts(text, expected):
    assert parse_version(text) == expected


@pytest.mark.parametrize("text", ["", "v", "1.2", "latest", "release-1", "v1.2.x", "abc"])
def test_parse_version_rejects(text):
    assert parse_version(text) is None


@pytest.mark.parametrize("latest,current", [
    ("v0.2.0", "0.1.0"),
    ("v1.0.0", "0.9.9"),
    ("v0.1.1", "0.1.0"),
    ("v0.10.0", "0.9.0"),   # numeric, not string ordering
])
def test_is_newer_true(latest, current):
    assert is_newer(latest, current)


@pytest.mark.parametrize("latest,current", [
    ("v0.1.0", "0.1.0"),    # same version must not nag
    ("v0.1.0", "0.2.0"),    # older release than what's running
    ("v0.9.0", "0.10.0"),
    ("garbage", "0.1.0"),   # unparseable -> stay silent
    ("v0.2.0", "garbage"),
    ("", "0.1.0"),
])
def test_is_newer_false(latest, current):
    assert not is_newer(latest, current)


# --- response validation ----------------------------------------------

def test_fetch_accepts_a_well_formed_release(monkeypatch):
    _stub_get(monkeypatch, _Response(payload={
        "tag_name": "v0.2.0",
        "html_url": "https://github.com/mirhunter/vhsp/releases/tag/v0.2.0",
        "published_at": "2026-08-01T00:00:00Z",
    }))
    result = update_check.fetch_latest()
    assert result["tag"] == "v0.2.0"
    assert result["url"].startswith("https://github.com/mirhunter/vhsp/")


@pytest.mark.parametrize("bad_url", [
    "javascript:alert(1)",
    "http://github.com/mirhunter/vhsp/releases/tag/v1",   # not https
    "https://evil.example/mirhunter/vhsp",
    "https://github.com.evil.example/x",
    "",
])
def test_fetch_rejects_a_url_that_is_not_this_repo_on_github(monkeypatch, bad_url):
    """The URL becomes an href in the admin UI. Autoescaping does not
    save you here -- an attacker-chosen destination is still a valid
    attribute value."""
    _stub_get(monkeypatch, _Response(payload={"tag_name": "v0.2.0", "html_url": bad_url}))
    with pytest.raises(UpdateCheckError):
        update_check.fetch_latest()


@pytest.mark.parametrize("bad_tag", [
    "<script>alert(1)</script>",
    "v1.0.0 with spaces",
    "x" * 200,
    "",
])
def test_fetch_rejects_a_malformed_tag(monkeypatch, bad_tag):
    _stub_get(monkeypatch, _Response(payload={
        "tag_name": bad_tag,
        "html_url": "https://github.com/mirhunter/vhsp/releases/tag/v1",
    }))
    with pytest.raises(UpdateCheckError):
        update_check.fetch_latest()


@pytest.mark.parametrize("response,exc", [
    (_Response(status_code=404), None),
    (_Response(status_code=500), None),
    (_Response(status_code=403), None),          # rate limited
    (_Response(raise_json=True), None),
    (None, __import__("requests").RequestException("connection refused")),
])
def test_fetch_turns_every_failure_into_one_error_type(monkeypatch, response, exc):
    _stub_get(monkeypatch, response, exc)
    with pytest.raises(UpdateCheckError):
        update_check.fetch_latest()


# --- run_check / banner_state -----------------------------------------

def test_run_check_records_a_newer_release(monkeypatch, state_path):
    monkeypatch.setattr(update_check, "__version__", "0.1.0")
    _stub_get(monkeypatch, _Response(payload={
        "tag_name": "v0.2.0",
        "html_url": "https://github.com/mirhunter/vhsp/releases/tag/v0.2.0",
        "published_at": "2026-08-01T00:00:00Z",
    }))
    state = update_check.run_check()
    assert state["update_available"] is True
    assert json.loads(state_path.read_text())["latest_tag"] == "v0.2.0"


def test_run_check_records_the_error_rather_than_raising(monkeypatch, state_path):
    import requests as _requests
    _stub_get(monkeypatch, None, _requests.RequestException("offline"))
    state = update_check.run_check()
    assert "last_error" in state
    assert state["last_checked_at"]


def test_a_failed_check_does_not_erase_a_previous_good_result(monkeypatch, state_path):
    monkeypatch.setattr(update_check, "__version__", "0.1.0")
    _stub_get(monkeypatch, _Response(payload={
        "tag_name": "v0.2.0",
        "html_url": "https://github.com/mirhunter/vhsp/releases/tag/v0.2.0",
    }))
    update_check.run_check()

    import requests as _requests
    _stub_get(monkeypatch, None, _requests.RequestException("offline"))
    update_check.run_check()

    assert update_check.banner_state()["latest_tag"] == "v0.2.0"


def test_state_file_is_owner_read_write_only(monkeypatch, state_path):
    _stub_get(monkeypatch, _Response(payload={
        "tag_name": "v0.2.0",
        "html_url": "https://github.com/mirhunter/vhsp/releases/tag/v0.2.0",
    }))
    update_check.run_check()
    assert (state_path.stat().st_mode & 0o777) == 0o600


def test_no_banner_before_any_check_has_run(state_path):
    assert update_check.banner_state() is None


def test_banner_disappears_once_the_running_version_catches_up(monkeypatch, state_path):
    """The stored `update_available` was computed by whichever version was
    running at check time. After an upgrade that value is stale, and the
    banner must not keep nagging until the next timer run."""
    monkeypatch.setattr(update_check, "__version__", "0.1.0")
    _stub_get(monkeypatch, _Response(payload={
        "tag_name": "v0.2.0",
        "html_url": "https://github.com/mirhunter/vhsp/releases/tag/v0.2.0",
    }))
    update_check.run_check()
    assert update_check.banner_state() is not None

    monkeypatch.setattr(update_check, "__version__", "0.2.0")
    assert update_check.banner_state() is None


def test_banner_ignores_a_tampered_cache_file(state_path, monkeypatch):
    """The file is 0600 and host-local, but it's still parsed input and
    the URL is the field that becomes an href."""
    monkeypatch.setattr(update_check, "__version__", "0.1.0")
    state_path.write_text(json.dumps({
        "latest_tag": "v9.9.9",
        "latest_url": "javascript:alert(1)",
    }))
    assert update_check.banner_state() is None


def test_banner_survives_a_corrupt_cache_file(state_path):
    state_path.write_text("{not json")
    assert update_check.banner_state() is None
