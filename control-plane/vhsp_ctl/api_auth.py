"""Operator API/MCP bearer-token store and validation.

Framework-agnostic on purpose -- shared by vhsp_ctl/api.py (a Flask
Blueprint) and vhsp_ctl/mcp_server.py (a separate fastmcp process, not
Flask at all), the same way both cli.py and web.py already call the
same provisioner.py functions rather than each having their own copy.
This module only knows about tokens; each of those two front-ends does
its own header/transport-specific extraction before calling
validate_token() here.

Same generate/hash/store/check idiom as vhsp_ctl/auth.py's operator
passwords (see that module's create_operator/check) -- secrets.token_urlsafe
to generate, only a generate_password_hash digest ever persisted, shown
in plaintext exactly once by the caller and never recoverable after
that. A token is deliberately mintable only from an already-2FA-
authenticated web session (see web.py's new /account token-management
section, gated @require_auth @require_2fa same as every other
high-blast-radius action there) -- this module has no opinion on how a
caller got authorized to mint one, it just stores/validates what it's
given.
"""

import json
import os
import stat
import secrets as _secrets
from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from vhsp_ctl import audit, auth
from vhsp_ctl.config import STATE_DIR

API_TOKENS_PATH = STATE_DIR / "api_tokens.json"


class ApiAuthError(Exception):
    pass


def _load() -> dict:
    if not API_TOKENS_PATH.exists():
        return {}
    return json.loads(API_TOKENS_PATH.read_text())


def _write(tokens: dict) -> None:
    API_TOKENS_PATH.parent.mkdir(parents=True, exist_ok=True)
    API_TOKENS_PATH.write_text(json.dumps(tokens))
    os.chmod(API_TOKENS_PATH, stat.S_IRUSR | stat.S_IWUSR)


def mint_token(operator_username: str, label: str, actor: str) -> str:
    """Returns the plaintext token -- the only time it's ever available,
    same "generated, shown once" contract as every other credential this
    codebase mints (auth.create_operator, provisioner's various
    reset_tenant_* functions). `actor` is required, not defaulted, since
    every call site here is a real operator action behind a real 2FA
    session, unlike some provisioner.py functions that default actor to
    "cli" for a non-interactive scheduler context that doesn't apply here."""
    tokens = _load()
    token = _secrets.token_urlsafe(32)
    token_id = _secrets.token_hex(8)
    tokens[token_id] = {
        "hash": generate_password_hash(token),
        "operator_username": operator_username,
        "label": label,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _write(tokens)
    audit.log_action("admin.api_token_create", label, actor)
    return token


def validate_token(token: str) -> str | None:
    """Returns the owning operator's username if `token` is a live,
    unrevoked token AND that operator account still exists; None
    otherwise. Checks against every stored hash -- unlike a
    username+password lookup, an opaque bearer token carries no
    identifier to look the right entry up by first, and password hashes
    are one-way by design, so there's no shortcut. Fine at the expected
    scale here (a handful of tokens per operator, not a
    per-request-latency-sensitive multi-tenant credential store).

    The operator-still-exists check matters: removing an operator
    (auth.remove_operator) doesn't cascade-delete their tokens from
    api_tokens.json -- these are two separate stores, same as
    operators.json and totp_secrets.json already are. Without this
    check, a removed operator's old token would keep granting full API/
    MCP access forever, silently outliving the account it was minted
    from."""
    for entry in _load().values():
        if check_password_hash(entry["hash"], token):
            username = entry["operator_username"]
            return username if auth.operator_exists(username) else None
    return None


def list_tokens() -> list[dict]:
    """Metadata only (token_id, operator_username, label, created_at) --
    never the hash, and there is no way to recover a plaintext token
    from anything this returns."""
    return [
        {"token_id": token_id, **{k: v for k, v in entry.items() if k != "hash"}}
        for token_id, entry in sorted(_load().items())
    ]


def revoke_token(token_id: str, actor: str) -> None:
    tokens = _load()
    if token_id not in tokens:
        raise ApiAuthError(f"no such token {token_id!r}")
    label = tokens[token_id]["label"]
    del tokens[token_id]
    _write(tokens)
    audit.log_action("admin.api_token_revoke", label, actor)
