"""Keeps deployment artifacts free of any one host's identity.

The systemd units and the sudoers grant have to name a concrete OS user
-- `User=` takes no variables and sudoers has no indirection -- so they
carry placeholders in the repo and `deploy/vhsp-render` stamps them out
per host. These tests guard the two ways that arrangement quietly rots:
a personal username getting committed back into a template, and a
template growing a placeholder the renderer doesn't know how to fill.

The second one matters more than it looks. An unrendered placeholder in
a systemd unit is a service that won't start; in the sudoers file it's a
parse error, and a broken file in /etc/sudoers.d can lock sudo out of
the host entirely.
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
DEPLOY = REPO / "deploy"
RENDER = DEPLOY / "vhsp-render"

KNOWN_PLACEHOLDERS = {"__VHSP_USER__", "__VHSP_HOME__"}

# The delimited form, identical to what deploy/vhsp-render greps for.
PLACEHOLDER = re.compile(r"__VHSP_[A-Z_]*__")

# Files that legitimately discuss the templating scheme itself, or record
# history that named a real account before this existed.
EXEMPT = {"vhsp-render", "rendered"}


def _tracked_deploy_files():
    out = subprocess.run(
        ["git", "ls-files", "deploy"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout.split()
    return [REPO / p for p in out if (REPO / p).is_file()]


def test_there_are_deploy_files_to_check():
    assert len(_tracked_deploy_files()) > 10


@pytest.mark.parametrize("path", _tracked_deploy_files(), ids=lambda p: p.name)
def test_no_personal_username_in_committed_deploy_files(path):
    """A real account name here makes the repo installable as that person
    and nobody else, and puts a maintainer's username in front of every
    reader of the deployment docs."""
    if path.name in EXEMPT:
        pytest.skip("documents the templating scheme itself")
    text = path.read_text(errors="replace")
    assert "astjohn" not in text, (
        f"{path.name} names a specific OS user. Use __VHSP_USER__ / "
        f"__VHSP_HOME__ and let deploy/vhsp-render fill them in."
    )


@pytest.mark.parametrize("path", _tracked_deploy_files(), ids=lambda p: p.name)
def test_service_units_take_their_user_from_the_placeholder(path):
    """Structural version of the check above, and the stronger one: it
    catches *any* concrete account name, not just the one that happened
    to be committed before this existed."""
    if path.suffix != ".service":
        pytest.skip("not a systemd unit")
    for line in path.read_text().splitlines():
        if line.startswith(("User=", "Group=")):
            assert line.split("=", 1)[1] == "__VHSP_USER__", (
                f"{path.name} hardcodes {line!r}; use __VHSP_USER__."
            )


@pytest.mark.parametrize("path", _tracked_deploy_files(), ids=lambda p: p.name)
def test_no_hardcoded_home_directory(path):
    """Same idea for paths: /home/<name> or /opt/<name> baked into a unit
    or wrapper is another way one host's layout becomes everyone's."""
    if path.name in EXEMPT:
        pytest.skip("documents the templating scheme itself")
    stray = re.findall(r"/home/(?!<)[A-Za-z0-9_-]+", path.read_text(errors="replace"))
    assert not stray, (
        f"{path.name} hardcodes home path(s) {sorted(set(stray))}; use __VHSP_HOME__."
    )


@pytest.mark.parametrize("path", _tracked_deploy_files(), ids=lambda p: p.name)
def test_every_placeholder_is_one_the_renderer_knows(path):
    found = set(PLACEHOLDER.findall(path.read_text(errors="replace")))
    unknown = found - KNOWN_PLACEHOLDERS
    assert not unknown, (
        f"{path.name} uses placeholder(s) {sorted(unknown)} that "
        f"deploy/vhsp-render does not substitute -- it would ship "
        f"unrendered into an installed unit or sudoers file."
    )


@pytest.mark.skipif(not shutil.which("bash"), reason="needs bash")
def test_rendering_leaves_no_placeholders_behind(tmp_path):
    """End-to-end: render into a scratch copy and confirm nothing is left
    for systemd or sudo to choke on."""
    scratch = tmp_path / "deploy"
    shutil.copytree(DEPLOY, scratch)

    result = subprocess.run(
        ["bash", str(scratch / "vhsp-render"), "--user", "svcuser", "--home", "/opt/svcuser"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr

    rendered = list((scratch / "rendered").iterdir())
    assert rendered, "renderer produced no output"
    for f in rendered:
        text = f.read_text(errors="replace")
        # The full delimited pattern, matching what vhsp-render itself
        # greps for -- not a bare "__VHSP_" prefix. vhsp-mcp-toggle
        # legitimately contains that prefix as its own guard against
        # installing an unrendered unit, and flagging it here would make
        # the safety check look like the bug it exists to catch.
        assert not PLACEHOLDER.search(text), f"{f.name} still contains a placeholder"
        assert "astjohn" not in text

    unit = (scratch / "rendered" / "vhsp-admin.service").read_text()
    assert "User=svcuser" in unit
    assert "/opt/svcuser/vhsp-control-plane" in unit


@pytest.mark.skipif(not shutil.which("bash"), reason="needs bash")
@pytest.mark.parametrize("bad_user", ["root user", "a,b", "-leading", "UPPER", ""])
def test_renderer_rejects_names_that_would_corrupt_sudoers(tmp_path, bad_user):
    """The user name lands in a sudoers grant, so whitespace or a comma
    would change that file's meaning rather than merely look wrong."""
    scratch = tmp_path / "deploy"
    shutil.copytree(DEPLOY, scratch)
    result = subprocess.run(
        ["bash", str(scratch / "vhsp-render"), "--user", bad_user],
        capture_output=True, text=True,
    )
    assert result.returncode != 0, f"renderer accepted {bad_user!r}"


@pytest.mark.skipif(not shutil.which("bash"), reason="needs bash")
def test_mcp_toggle_installs_the_rendered_unit_not_the_template(tmp_path):
    """Enabling MCP from the admin UI is the one path where a repo file
    becomes an installed systemd unit with no operator install step, so
    it must read from rendered/ -- pointing at the template would install
    a unit naming a user that doesn't exist."""
    scratch = tmp_path / "deploy"
    shutil.copytree(DEPLOY, scratch)
    subprocess.run(
        ["bash", str(scratch / "vhsp-render"), "--user", "svcuser", "--home", "/opt/svcuser"],
        capture_output=True, text=True, check=True,
    )
    toggle = (scratch / "rendered" / "vhsp-mcp-toggle").read_text()
    assert "/deploy/rendered/vhsp-mcp.service" in toggle
    assert not PLACEHOLDER.search(toggle)
    # And it still refuses to install a unit that somehow has placeholders.
    assert "unrendered placeholders" in toggle
