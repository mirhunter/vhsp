"""Failed-login lockout, shared by both admin surfaces (web.py's operator
login and images/tenant-admin/app.py's tenant login) -- covers both the
password step and the TOTP-code step, since a 6-digit code is just as
guessable as a weak password without a limit on attempts.

File-based rather than flask-limiter/Redis-backed: vhsp-admin.service runs
`gunicorn --workers 2`, so in-memory rate-limiter state wouldn't be shared
across workers, and this deployment has no Redis. A STATE_DIR-backed JSON
file matches the existing pattern for exactly this kind of small shared
state (auth.py's operators.json, totp.py's totp_secrets.json) and needs no
new infrastructure.

Keyed by username, not by IP: this deployment sits behind at most one
reverse-proxy hop (see config.py's *_TRUST_PROXY docstrings) where a
spoofed X-Forwarded-For would be no more trustworthy than no IP at all,
and per-username throttling already covers the case that actually
matters here -- guessing one specific account's secret -- without that
extra trust assumption.
"""

import json
import os
import stat
import time

from vhsp_ctl.config import STATE_DIR

LOCKOUT_PATH = STATE_DIR / "login_attempts.json"
MAX_FAILURES = 5
WINDOW_SECONDS = 15 * 60
LOCKOUT_SECONDS = 15 * 60


def _load() -> dict:
    if not LOCKOUT_PATH.exists():
        return {}
    return json.loads(LOCKOUT_PATH.read_text())


def _save(entries: dict) -> None:
    LOCKOUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOCKOUT_PATH.write_text(json.dumps(entries))
    os.chmod(LOCKOUT_PATH, stat.S_IRUSR | stat.S_IWUSR)


def is_locked(username: str) -> bool:
    entry = _load().get(username)
    if not entry:
        return False
    locked_until = entry.get("locked_until")
    return bool(locked_until and time.time() < locked_until)


def record_failure(username: str) -> None:
    """Call only when is_locked() was already False -- an account that's
    currently locked shouldn't have its lockout silently extended just
    because someone kept submitting the login form; the caller is
    expected to short-circuit on is_locked() before ever checking the
    password/code, so this only ever sees "genuine, currently-permitted"
    attempts."""
    entries = _load()
    now = time.time()
    entry = entries.get(username, {"count": 0, "first_failure": now})
    if now - entry.get("first_failure", now) > WINDOW_SECONDS:
        entry = {"count": 0, "first_failure": now}
    entry["count"] += 1
    if entry["count"] >= MAX_FAILURES:
        entry["locked_until"] = now + LOCKOUT_SECONDS
    entries[username] = entry
    _save(entries)


def record_success(username: str) -> None:
    entries = _load()
    if username in entries:
        del entries[username]
        _save(entries)
