"""TOTP (authenticator-app) support for the operator admin UI -- a second
factor alternative to WebAuthn (webauthn.py), for operators without (or in
addition to) a hardware security key. Same "second factor on top of the
password login" role as webauthn.py, offered as an *alternative*, not a
replacement -- an operator can register either, both, or neither; login
(web.py's login()/login_2fa()) accepts whichever they have.

Uses `pyotp` (RFC 6238 TOTP) and `qrcode` (SVG output via
qrcode.image.svg, no Pillow dependency -- verified this avoids pulling in
an image library just to draw a QR code) -- both pure-Python, no new
system packages needed in either the control-plane venv or the
tenant-admin container.

One secret per operator, not a list like webauthn.py's credentials --
there's no equivalent here to "multiple physical keys": scanning the same
QR/secret into a second device (a phone AND a tablet, say) already works
without needing two stored secrets.

Setup is two-step, deliberately never persisting an unconfirmed secret:
generate_setup() hands back a fresh secret (the caller stashes it in the
session, not here) plus its QR code; the secret only reaches disk via
confirm_and_enable(), once the operator proves they can produce a valid
code from it. Closing the tab mid-setup leaves nothing behind to clean up
-- there's no "pending" state on disk at all, only in that one session.
"""

import io
import json
import os
import stat

import pyotp
import qrcode
import qrcode.image.svg

from vhsp_ctl import secretbox
from vhsp_ctl.config import STATE_DIR

SECRETS_PATH = STATE_DIR / "totp_secrets.json"
ISSUER = "VHSP"


def _load() -> dict:
    if not SECRETS_PATH.exists():
        return {}
    entries = json.loads(SECRETS_PATH.read_text())
    # Only "secret" is sensitive (the base32 shared secret itself, which
    # is all an attacker needs to generate valid codes forever) --
    # "added_at" stays plaintext, nothing to protect there. Encrypted at
    # rest via secretbox.py for the same reason registry.py's tenant
    # credentials are: a leak of just this one file shouldn't hand over
    # every operator's second factor.
    for entry in entries.values():
        entry["secret"] = secretbox.decrypt(entry["secret"])
    return entries


def _save(entries: dict) -> None:
    SECRETS_PATH.parent.mkdir(parents=True, exist_ok=True)
    to_write = {
        owner: {**entry, "secret": secretbox.encrypt(entry["secret"])}
        for owner, entry in entries.items()
    }
    SECRETS_PATH.write_text(json.dumps(to_write))
    os.chmod(SECRETS_PATH, stat.S_IRUSR | stat.S_IWUSR)


def reencrypt_all() -> int:
    """One-time migration for `vhsp secrets migrate`: _load() already
    transparently decrypts old plaintext secrets (see secretbox.decrypt's
    own pass-through), and _save() always encrypts -- so a plain load+save
    round-trip is enough to bring every existing entry up to date once a
    master key exists. Returns the number of entries touched (0 if this
    file doesn't exist yet, i.e. no operator has set up TOTP)."""
    entries = _load()
    if entries:
        _save(entries)
    return len(entries)


def rotate_secrets(new_fernet) -> int:
    """Re-encrypts every operator's TOTP secret under a new master key,
    for `vhsp secrets rotate` (cli.py) -- see
    registry.rotate_credentials's docstring for the full ordering. No
    old_fernet parameter here (unlike that function) -- _load() is
    already safe to call as-is: it calls secretbox.decrypt(), which reads
    whatever key is *currently on disk* at MASTER_KEY_PATH, correct at
    this point in rotate_master_key()'s sequence since the old key is
    still the one on disk when this runs. Only the write side needs
    new_fernet explicitly, bypassing the normal _save() (which would also
    read the still-old on-disk key)."""
    entries = _load()
    if not entries:
        return 0
    SECRETS_PATH.parent.mkdir(parents=True, exist_ok=True)
    to_write = {
        owner: {**entry, "secret": secretbox.encrypt_with(new_fernet, entry["secret"])}
        for owner, entry in entries.items()
    }
    SECRETS_PATH.write_text(json.dumps(to_write))
    os.chmod(SECRETS_PATH, stat.S_IRUSR | stat.S_IWUSR)
    return len(entries)


def has_totp(owner: str) -> bool:
    return owner in _load()


def get_added_at(owner: str) -> str | None:
    entry = _load().get(owner)
    return entry["added_at"] if entry else None


def _qr_svg(owner: str, secret: str) -> str:
    uri = pyotp.TOTP(secret).provisioning_uri(name=owner, issuer_name=ISSUER)
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode()


def generate_setup(owner: str) -> tuple[str, str]:
    """Returns (secret, qr_svg_markup). NOT persisted -- the caller
    stashes `secret` in the session until confirm_and_enable verifies
    it. `owner` only affects the QR code's display label (which account
    an authenticator app shows this entry under), not anything checked
    later -- the actual binding to `owner` happens at confirm_and_enable
    time, when it's written into SECRETS_PATH keyed by that name."""
    secret = pyotp.random_base32()
    return secret, _qr_svg(owner, secret)


def qr_svg_for_secret(owner: str, secret: str) -> str:
    """Re-renders the QR for an already-generated, still-pending secret
    -- used to redisplay the setup page after a failed confirm attempt,
    where regenerating a *new* secret would silently invalidate whatever
    the user already scanned into their authenticator app."""
    return _qr_svg(owner, secret)


def confirm_and_enable(owner: str, secret: str, code: str, added_at: str) -> bool:
    """Verifies `code` against `secret` (the pending, session-held secret
    from generate_setup -- never anything already on disk) and, only if
    it verifies, persists it as this owner's active TOTP secret,
    overwriting any previous one. Returns whether it verified."""
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        return False
    entries = _load()
    entries[owner] = {"secret": secret, "added_at": added_at}
    _save(entries)
    return True


def verify(owner: str, code: str) -> bool:
    """True if `code` is currently valid for owner's already-confirmed
    secret. valid_window=1 tolerates +/-30s of clock drift between the
    authenticator app and this host, at the cost of not defending against
    a code being replayed within that window (no last-used-step
    tracking) -- a known, accepted gap of the same shape webauthn.py's own
    docstring already calls out for signature-counter tracking: a real
    consideration for a high-value target, more than this platform's MVP
    needs, noted here rather than silently skipped."""
    entry = _load().get(owner)
    if not entry:
        return False
    return pyotp.TOTP(entry["secret"]).verify(code, valid_window=1)


def remove(owner: str) -> None:
    entries = _load()
    entries.pop(owner, None)
    _save(entries)
