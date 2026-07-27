"""Regression tests for the snapshot-name validation on the restore path.

Guards a real vulnerability, not a hypothetical: an unvalidated
snapshot_name reached `workdir / snapshot_name` and then scp, which made
it an arbitrary-file-write primitive reachable from a tenant's own panel
(tenant sets their backup destination, submits a restore, the host-side
reconciler fetches attacker-controlled bytes to an attacker-chosen path
as the control-plane user). See validate_snapshot_name's own docstring
for the two pathlib behaviours that made it exploitable.
"""

from pathlib import Path

import pytest

from vhsp_ctl.backup import BackupError, validate_snapshot_name


WORKDIR = Path("/srv/vhsp/backup/work/restore-123")

# Names that, joined onto the restore working directory, land somewhere
# outside it entirely -- the actual write primitive.
ESCAPES_WORKDIR = [
    "/home/vhsp/.ssh/authorized_keys",       # absolute REPLACES the base
    "/etc/cron.d/vhsp",
    "../../keys/operator_signing_ed25519",      # reaches the backup keys dir
    "../../keys/operator_encryption_age.key",
    "../snapshot.tar.age",
    "../../../../home/vhsp/.ssh/authorized_keys",
    "..",
]

# Rejected too, but for tidiness rather than danger: these stay inside the
# workdir (or resolve to it). Kept separate so the escape assertion below
# can't be weakened by lumping harmless cases in with real ones.
REJECTED_BUT_CONTAINED = [
    "sub/dir/snap.tar.age",   # a directory component scp would fail on anyway
    "./snap.tar.age",
    ".",
    "",
]


@pytest.mark.parametrize("name", ESCAPES_WORKDIR + REJECTED_BUT_CONTAINED)
def test_rejects_anything_that_is_not_a_bare_filename(name):
    with pytest.raises(BackupError):
        validate_snapshot_name(name)


@pytest.mark.parametrize("name", ESCAPES_WORKDIR)
def test_dangerous_names_really_do_escape_the_workdir(name):
    """The other half of the assertion above: confirms each of these is
    genuinely an escape rather than merely unusual, so the list can't
    quietly decay into testing nothing if the join ever moves."""
    joined = (WORKDIR / name).resolve()
    assert not joined.is_relative_to(WORKDIR), f"{name!r} was expected to escape {WORKDIR}"


@pytest.mark.parametrize("name", [
    "20260727-120000.tar.age",
    "20260727-120000.tar",
    "20260727-120000-tenant.tar.age",
    "snapshot.tar",
])
def test_accepts_the_names_create_backup_actually_produces(name):
    assert validate_snapshot_name(name) == name


def test_returns_the_name_so_it_can_be_used_inline():
    assert validate_snapshot_name("a.tar") == "a.tar"
