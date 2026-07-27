"""Tests for the failed-login lockout shared by both admin surfaces.

Covers the window arithmetic specifically: the difference between "5
failures ever" and "5 failures within the window" is the difference
between a lockout that eventually traps every legitimate user and one
that only fires on a real burst.
"""

import pytest

from vhsp_ctl import login_throttle


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(login_throttle, "LOCKOUT_PATH", tmp_path / "login_attempts.json")


def test_unknown_account_is_not_locked(store):
    assert not login_throttle.is_locked("nobody")


def test_locks_only_after_reaching_the_threshold(store):
    for _ in range(login_throttle.MAX_FAILURES - 1):
        login_throttle.record_failure("admin")
    assert not login_throttle.is_locked("admin")

    login_throttle.record_failure("admin")
    assert login_throttle.is_locked("admin")


def test_lockout_is_per_account(store):
    for _ in range(login_throttle.MAX_FAILURES):
        login_throttle.record_failure("admin")
    assert login_throttle.is_locked("admin")
    assert not login_throttle.is_locked("someone-else")


def test_success_clears_accumulated_failures(store):
    for _ in range(login_throttle.MAX_FAILURES - 1):
        login_throttle.record_failure("admin")
    login_throttle.record_success("admin")

    for _ in range(login_throttle.MAX_FAILURES - 1):
        login_throttle.record_failure("admin")
    assert not login_throttle.is_locked("admin")


def test_failures_outside_the_window_do_not_accumulate(store, monkeypatch):
    """Four failures today plus one next week must not lock the account."""
    now = [1_000_000.0]
    monkeypatch.setattr(login_throttle.time, "time", lambda: now[0])

    for _ in range(login_throttle.MAX_FAILURES - 1):
        login_throttle.record_failure("admin")

    now[0] += login_throttle.WINDOW_SECONDS + 1
    login_throttle.record_failure("admin")
    assert not login_throttle.is_locked("admin")


def test_lockout_expires_on_its_own(store, monkeypatch):
    now = [1_000_000.0]
    monkeypatch.setattr(login_throttle.time, "time", lambda: now[0])

    for _ in range(login_throttle.MAX_FAILURES):
        login_throttle.record_failure("admin")
    assert login_throttle.is_locked("admin")

    now[0] += login_throttle.LOCKOUT_SECONDS + 1
    assert not login_throttle.is_locked("admin")


def test_state_file_is_owner_read_write_only(store):
    login_throttle.record_failure("admin")
    assert (login_throttle.LOCKOUT_PATH.stat().st_mode & 0o777) == 0o600
