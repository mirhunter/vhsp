"""Operator auth for the admin web UI.

Per architecture.md's control-plane auth section, this is the
highest-blast-radius surface in the whole platform and deserves the
strongest auth of anywhere -- MFA/hardware-key, RBAC, the works. MFA
(WebAuthn, see webauthn.py) and per-operator identity (this module) are
both done; RBAC stays a separate, later gap (flat/equal-privilege
operators for now, confirmed by the user rather than assumed) -- see
README's "Known gaps".
"""

import json
import os
import secrets
import stat
from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from vhsp_ctl import audit
from vhsp_ctl.config import STATE_DIR

OPERATORS_PATH = STATE_DIR / "operators.json"
# Pre-multi-operator credential file -- no longer written, only read once
# by _migrate_legacy_single_admin() below. Left in place after migration
# rather than deleted, matching this codebase's general caution around
# destructive cleanup (e.g. registry.py's own note on stopgap files).
LEGACY_CREDENTIALS_PATH = STATE_DIR / "admin_credentials.json"
SECRET_KEY_PATH = STATE_DIR / "admin_flask_secret"


class AuthError(Exception):
    pass


def ensure_secret_key() -> str:
    """Flask session cookies are signed with this; generating it fresh on
    every process start (the original `secrets.token_hex(32)` at import
    time) would silently invalidate every logged-in session on every
    restart -- harmless under HTTP Basic Auth (no server-side session to
    invalidate) but not once login is session-based. Persisted once,
    reused across restarts, same pattern as OPERATORS_PATH below.
    """
    if not SECRET_KEY_PATH.exists():
        SECRET_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        SECRET_KEY_PATH.write_text(secrets.token_hex(32))
        os.chmod(SECRET_KEY_PATH, stat.S_IRUSR | stat.S_IWUSR)
    return SECRET_KEY_PATH.read_text()


def _migrate_legacy_single_admin() -> None:
    """One-time upgrade path: the pre-multi-operator single credential
    (username always "admin") becomes the first entry in operators.json,
    so upgrading a live deployment in place is a no-op from the
    operator's point of view -- same username, same password, still
    works. Lazy, idempotent (same "generate/migrate on first access"
    idiom as the old ensure_credentials), called at the top of every
    function below that reads OPERATORS_PATH so there's no separate
    migration step to remember to run."""
    if OPERATORS_PATH.exists() or not LEGACY_CREDENTIALS_PATH.exists():
        return
    legacy = json.loads(LEGACY_CREDENTIALS_PATH.read_text())
    _write({
        legacy["username"]: {
            "password_hash": legacy["password_hash"],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    })


def _load() -> dict:
    _migrate_legacy_single_admin()
    if not OPERATORS_PATH.exists():
        return {}
    return json.loads(OPERATORS_PATH.read_text())


def _write(operators: dict) -> None:
    OPERATORS_PATH.parent.mkdir(parents=True, exist_ok=True)
    OPERATORS_PATH.write_text(json.dumps(operators))
    os.chmod(OPERATORS_PATH, stat.S_IRUSR | stat.S_IWUSR)


def list_operators() -> list[dict]:
    """Metadata only (username, created_at) -- safe to render in a
    template, never includes password hashes."""
    return [
        {"username": username, "created_at": entry["created_at"]}
        for username, entry in sorted(_load().items())
    ]


def operator_exists(username: str) -> bool:
    return username in _load()


def create_operator(username: str, actor: str = "cli") -> str:
    """Generates+stores a random password for a brand-new operator.
    Returns the plaintext (the only time it's ever available -- shown
    once by the caller, same pattern as every other generated credential
    in this codebase).

    `actor` defaults to "cli" and audit-logs internally, matching
    provisioner.py's own convention for every tenant action (e.g.
    destroy_tenant) -- so both the CLI and the admin-UI web routes get an
    audit trail automatically, from one place, rather than each caller
    having to remember to log it themselves."""
    operators = _load()
    if username in operators:
        raise AuthError(f"operator {username!r} already exists")
    password = secrets.token_urlsafe(18)
    operators[username] = {
        "password_hash": generate_password_hash(password),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _write(operators)
    audit.log_action("admin.operator_create", username, actor)
    return password


def check(username: str, password: str) -> bool:
    operators = _load()
    entry = operators.get(username)
    return entry is not None and check_password_hash(entry["password_hash"], password)


def set_password(username: str, password: str, actor: str = "cli") -> None:
    """Overwrites one operator's password in place -- used both by the
    admin UI's "change my own password" page and by an operator
    resetting another's (e.g. lockout recovery). Caller decides which;
    this function doesn't distinguish "self" from "someone else", same
    as the rest of this flat/equal-privilege model. See create_operator's
    docstring for why audit logging lives here, not in each caller."""
    operators = _load()
    if username not in operators:
        raise AuthError(f"no such operator {username!r}")
    operators[username]["password_hash"] = generate_password_hash(password)
    _write(operators)
    audit.log_action("admin.operator_password_change", username, actor)


def remove_operator(username: str, actor: str = "cli") -> None:
    """Refuses to remove the last remaining operator -- there is no
    other way back into this admin UI once every operator is gone, no
    root-equivalent recovery path the way a locked-out tenant has (an
    operator can already clear a *tenant's* WebAuthn keys from here, but
    nothing clears an operator's own account from outside this UI).
    Enforced here, not just in the web/CLI callers, so every caller
    inherits the guarantee automatically. See create_operator's docstring
    for why audit logging lives here, not in each caller."""
    operators = _load()
    if username not in operators:
        raise AuthError(f"no such operator {username!r}")
    if len(operators) <= 1:
        raise AuthError("cannot remove the last remaining operator")
    del operators[username]
    _write(operators)
    audit.log_action("admin.operator_remove", username, actor)
