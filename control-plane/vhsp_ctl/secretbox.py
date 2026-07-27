"""Envelope encryption for secrets at rest.

Per architecture.md's control-plane-auth section: tenant DB/mail/panel
credentials (registry.py) and operator TOTP secrets (totp.py) have always
been plaintext on disk, protected only by 0600 file permissions -- a
single trust boundary, since whoever can read files as the owning user
reads everything at once. This wraps the specific fields that matter with
a single master key stored separately (MASTER_KEY_PATH, generated once
by `vhsp secrets init`), so a narrower leak -- a stray copy of the
SQLite file, a backup that goes somewhere it shouldn't, a directory-
traversal bug that reads exactly one file -- doesn't hand over plaintext
credentials on its own. Same reasoning backup.py already applies to
snapshot encryption (age); this closes the equivalent gap for secrets
that never leave this host at all.

Deliberately NOT a full secrets manager (Vault, cloud KMS): this is a
single-process, single-host deployment today, and the master key still
lives on the same host as everything it protects -- a full host/root
compromise still exposes everything, same limitation the Docker socket
proxy fix has for a different piece of the same problem. That tradeoff
was discussed with and confirmed by the user rather than assumed; see
the control-plane README's "Secrets management" section.

MASTER_KEY_PATH must never be swept up by any future "back up the
control plane's own state" tooling (no such feature exists today) --
that would defeat the entire "narrower leak" premise above by shipping
the key alongside what it protects.
"""

import os
import stat

from cryptography.fernet import Fernet, InvalidToken

from vhsp_ctl.config import STATE_DIR

MASTER_KEY_PATH = STATE_DIR / "master.key"

# Prefix marking a value as ciphertext produced by this module, distinct
# from any pre-existing plaintext (rows/files written before this feature
# existed, or a value read with no master key configured at all -- see
# decrypt()'s pass-through below). A version tag now avoids ambiguity if
# the scheme ever changes later.
_PREFIX = "enc1:"


class SecretBoxError(Exception):
    pass


def is_initialized() -> bool:
    return MASTER_KEY_PATH.exists()


def init_master_key(force: bool = False) -> None:
    """Generates the master key once. Refuses to silently overwrite an
    existing key (force=True required) -- every value already encrypted
    under the old key would become permanently undecryptable, the same
    "shown/generated once, guard against silent loss" posture `vhsp
    backup init` already uses for the backup keypairs."""
    if MASTER_KEY_PATH.exists() and not force:
        raise SecretBoxError(
            f"{MASTER_KEY_PATH} already exists -- refusing to overwrite "
            "(this would permanently orphan every secret encrypted under "
            "the current key)"
        )
    MASTER_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    MASTER_KEY_PATH.write_bytes(Fernet.generate_key())
    os.chmod(MASTER_KEY_PATH, stat.S_IRUSR | stat.S_IWUSR)


def _fernet() -> Fernet:
    if not MASTER_KEY_PATH.exists():
        raise SecretBoxError(f"no master key at {MASTER_KEY_PATH} -- run `vhsp secrets init` first")
    return Fernet(MASTER_KEY_PATH.read_bytes())


def is_encrypted(value: str) -> bool:
    return value.startswith(_PREFIX)


def encrypt_with(fernet: Fernet, plaintext: str) -> str:
    """Same as encrypt(), but against an explicit Fernet instance rather
    than whatever's currently on disk at MASTER_KEY_PATH -- used by
    rotate_master_key()'s callers (registry.rotate_credentials,
    totp.rotate_secrets) to encrypt under a brand-new key *before* it's
    been written to disk, while the old key is still current there."""
    return _PREFIX + fernet.encrypt(plaintext.encode()).decode()


def decrypt_with(fernet: Fernet, value: str) -> str:
    """Same pass-through/decrypt logic as decrypt(), against an explicit
    Fernet instance rather than the current on-disk key."""
    if not value.startswith(_PREFIX):
        return value
    try:
        return fernet.decrypt(value[len(_PREFIX):].encode()).decode()
    except InvalidToken as e:
        raise SecretBoxError("failed to decrypt -- wrong or missing master key") from e


def encrypt(plaintext: str) -> str:
    return encrypt_with(_fernet(), plaintext)


def decrypt(value: str) -> str:
    """Transparent pass-through for anything not carrying the `enc1:`
    prefix -- pre-existing plaintext rows/files from before this feature
    existed, or any value read back before `vhsp secrets init` has ever
    run (matches the "no master key -> behaves like the old plaintext
    code" fallback local dev relies on). Only real ciphertext takes the
    decrypt path, so this is safe to call unconditionally on every read
    without a separate "is this encrypted?" check at each call site."""
    return decrypt_with(_fernet(), value)
