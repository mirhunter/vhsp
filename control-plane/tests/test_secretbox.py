"""Tests for envelope encryption of secrets at rest.

The pass-through behaviour is the subtle part and the reason these exist:
decrypt() is called unconditionally on every read, including on values
written before this feature existed and on deployments with no master key
at all. If pass-through ever broke, every pre-existing plaintext
credential in the registry would start raising instead of being read.
"""

import pytest

from vhsp_ctl import secretbox
from vhsp_ctl.secretbox import SecretBoxError


@pytest.fixture
def master_key(tmp_path, monkeypatch):
    path = tmp_path / "master.key"
    monkeypatch.setattr(secretbox, "MASTER_KEY_PATH", path)
    secretbox.init_master_key()
    return path


def test_round_trip(master_key):
    assert secretbox.decrypt(secretbox.encrypt("hunter2")) == "hunter2"


def test_ciphertext_does_not_contain_the_plaintext(master_key):
    assert "hunter2" not in secretbox.encrypt("hunter2")


def test_same_plaintext_encrypts_differently_each_time(master_key):
    assert secretbox.encrypt("a") != secretbox.encrypt("a")


def test_encrypted_values_are_marked_with_a_version_prefix(master_key):
    assert secretbox.is_encrypted(secretbox.encrypt("a"))
    assert not secretbox.is_encrypted("plain")


def test_decrypt_passes_plaintext_through_untouched(master_key):
    """Values written before this feature existed carry no prefix."""
    assert secretbox.decrypt("legacy-plaintext-password") == "legacy-plaintext-password"


def test_round_trip_survives_unicode_and_empty(master_key):
    for value in ("", "pässwörd-✓", "a" * 4096):
        assert secretbox.decrypt(secretbox.encrypt(value)) == value


def test_init_refuses_to_silently_overwrite_an_existing_key(master_key):
    with pytest.raises(SecretBoxError):
        secretbox.init_master_key()


def test_force_overwrite_orphans_values_under_the_old_key(master_key):
    token = secretbox.encrypt("secret")
    secretbox.init_master_key(force=True)
    with pytest.raises(SecretBoxError):
        secretbox.decrypt(token)


def test_master_key_is_owner_read_write_only(master_key):
    assert (master_key.stat().st_mode & 0o777) == 0o600


def test_decrypt_reports_a_clear_error_when_no_key_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(secretbox, "MASTER_KEY_PATH", tmp_path / "absent.key")
    with pytest.raises(SecretBoxError, match="secrets init"):
        secretbox.decrypt("enc1:whatever")


def test_rotation_helpers_re_encrypt_under_a_new_key(master_key):
    """rotate_* callers encrypt under a brand-new key before it reaches
    disk, while the old key is still current there."""
    from cryptography.fernet import Fernet

    old_token = secretbox.encrypt("secret")
    new_fernet = Fernet(Fernet.generate_key())
    rotated = secretbox.encrypt_with(new_fernet, secretbox.decrypt(old_token))

    assert secretbox.decrypt_with(new_fernet, rotated) == "secret"
    with pytest.raises(SecretBoxError):
        secretbox.decrypt(rotated)  # old on-disk key must not open it
