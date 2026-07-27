"""WebAuthn (FIDO2/security key) support for the operator admin UI.

A second factor on top of the password login (see web.py's login()) --
register a key while already logged in, then get challenged for it on
future logins. Uses Yubico's own `fido2` library (matches the user's
stated YubiKey focus, though this works with any WebAuthn authenticator,
not just Yubico's).

RP ID is fixed to this deployment's real public hostname
(config.ADMIN_RP_ID, VHSP_ADMIN_RP_ID env var), not derived from the
request -- WebAuthn ties credentials to a specific origin, an IP address
can't be an RP ID at all, and this only works over HTTPS anyway (the whole
reason SSL got set up first). Registering/logging in via any path other
than the one public hostname this is configured for won't trigger WebAuthn
at all as a result. That's a deliberate consequence of the RP ID choice,
not a bug.

Every credential has an `owner` (the operator username it belongs to) --
added when multi-operator support landed. **Every lookup here is scoped
to one owner, including authenticate_begin/authenticate_complete.**
This isn't optional hygiene: with more than one operator, an unscoped
authenticate_complete() would accept ANY registered credential regardless
of who's logging in, which would let anyone who knows operator B's
password complete 2FA using operator A's own physical key and log in as
B. There is deliberately no "check against everyone's keys" code path
anywhere in this file.

Deliberately doesn't track each credential's signature counter across
uses (the mechanism WebAuthn provides for detecting a *cloned*
authenticator, not something fido2 tracks for the caller automatically).
A real consideration for a high-value target, more than this platform's
MVP needs -- noted here rather than silently skipped.

Credentials are stored as base64-encoded raw AttestedCredentialData bytes
-- fido2's own on-the-wire format, round-trips through
AttestedCredentialData(base64.b64decode(...)) directly, no need to pick
apart the public key/credential ID by hand (verified this round-trip
first, before building anything on top of it).
"""

import base64
import json
import os
import stat

from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestedCredentialData,
    AuthenticationResponse,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
)

from vhsp_ctl.config import ADMIN_RP_ID, STATE_DIR

CREDENTIALS_PATH = STATE_DIR / "webauthn_credentials.json"
RP_ID = ADMIN_RP_ID
RP_NAME = "VHSP Admin"

_server = Fido2Server(PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME))


def _load() -> list[dict]:
    """Entries from before multi-operator support have no "owner" field
    -- treated as belonging to the same legacy "admin" username
    auth.py's own migration preserves, and rewritten with that owner set
    so it's persisted rather than re-computed on every load."""
    if not CREDENTIALS_PATH.exists():
        return []
    entries = json.loads(CREDENTIALS_PATH.read_text())
    migrated = False
    for e in entries:
        if "owner" not in e:
            e["owner"] = "admin"
            migrated = True
    if migrated:
        _save(entries)
    return entries


def _save(entries: list[dict]) -> None:
    CREDENTIALS_PATH.parent.mkdir(parents=True, exist_ok=True)
    CREDENTIALS_PATH.write_text(json.dumps(entries))
    os.chmod(CREDENTIALS_PATH, stat.S_IRUSR | stat.S_IWUSR)


def list_credentials(owner: str) -> list[dict]:
    """Metadata only (name, added_at) -- safe to render in a template,
    never includes the actual credential data."""
    return [{"name": e["name"], "added_at": e["added_at"]} for e in _load() if e["owner"] == owner]


def has_credentials(owner: str) -> bool:
    return any(e["owner"] == owner for e in _load())


def _attested_credentials(owner: str) -> list[AttestedCredentialData]:
    return [AttestedCredentialData(base64.b64decode(e["credential_data"])) for e in _load() if e["owner"] == owner]


def name_taken(owner: str, name: str) -> bool:
    """Scoped per-owner, not global -- two different operators can each
    name a key "YubiKey 5C" without conflict."""
    return any(e["owner"] == owner and e["name"] == name for e in _load())


def add_credential(owner: str, name: str, credential_data: AttestedCredentialData, added_at: str) -> None:
    entries = _load()
    entries.append({
        "owner": owner,
        "name": name,
        "credential_data": base64.b64encode(bytes(credential_data)).decode(),
        "added_at": added_at,
    })
    _save(entries)


def remove_credential(owner: str, name: str) -> None:
    _save([e for e in _load() if not (e["owner"] == owner and e["name"] == name)])


def register_begin(username: str) -> tuple[dict, dict]:
    """Returns (options_json, state). state must be stashed server-side
    (the session) and passed back to register_complete unchanged --
    it's how the server remembers the challenge it issued without
    trusting the client to echo it back honestly."""
    user = PublicKeyCredentialUserEntity(id=username.encode(), name=username, display_name=username)
    options, state = _server.register_begin(
        user,
        credentials=_attested_credentials(username),  # excludes this operator's own already-registered keys
        user_verification="preferred",
    )
    return dict(options), state


def register_complete(state: dict, response_json: dict) -> AttestedCredentialData:
    response = RegistrationResponse.from_dict(response_json)
    auth_data = _server.register_complete(state, response)
    return auth_data.credential_data


def authenticate_begin(owner: str) -> tuple[dict, dict]:
    """owner is the pending-login username (session['pending_username']
    in web.py) -- only ever offers that operator's own credentials, see
    this module's docstring for why that's load-bearing, not incidental."""
    options, state = _server.authenticate_begin(credentials=_attested_credentials(owner))
    return dict(options), state


def authenticate_complete(owner: str, state: dict, response_json: dict) -> bool:
    """True if the response verifies against `owner`'s own registered
    credentials -- never anyone else's, see this module's docstring.
    Broad except is deliberate: fido2 raises several distinct exception
    types for the various ways a response can fail to verify, and every
    one of them should just mean "authentication failed" to the caller,
    never a 500 leaking internals of why."""
    try:
        response = AuthenticationResponse.from_dict(response_json)
        _server.authenticate_complete(state, _attested_credentials(owner), response)
        return True
    except Exception:
        return False
