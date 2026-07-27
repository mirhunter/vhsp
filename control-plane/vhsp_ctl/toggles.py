"""Shared read/write/validate logic for the tenant self-service knobs
(PHP functions, 404 fallback, password protection, error pages,
redirects, IP restrictions, email/mailboxes, logs) -- used by the
operator admin UI (web.py) to expose the exact same knobs
images/tenant-admin/ does, per-tenant, without a second implementation to
keep in sync with itself.

Operates on HOST-SIDE paths (t.phpconf_host_path, t.webroot_host_path,
t.logs_host_path) directly, since web.py runs on the Docker host itself
with full filesystem access already -- same trust level as the `vhsp` CLI
(see web.py's own docstring), and the exact same pattern
tenant_set_ssh_key already uses today (writing straight to
tenant.ssh_keys_host_path). images/tenant-admin/'s own container only
ever sees these paths through its volume mounts; this module reads/writes
the identical underlying files either way, so a change made here takes
effect through the identical poll-and-reload mechanism in the web/mail
containers' entrypoints, whichever UI made it.

images/tenant-admin/app.py keeps its OWN independent copy of this same
validation rather than importing this module -- it runs in a separate,
less-trusted, tenant-facing container with no access to the
control-plane's own package, and per the pattern the web/mail
entrypoints already use (re-validate at every trust boundary rather than
assume an earlier layer already did), that duplication is intentional.
"""

import ipaddress
import re
import secrets
from pathlib import Path

from passlib.hash import apr_md5_crypt, sha512_crypt

POSTMASTER = "postmaster"

# Must match images/web/entrypoint.sh's ALL_TOGGLEABLE exactly -- the
# fixed set of functions a tenant/operator is allowed to have an opinion
# about; the web container's watcher only understands these by name.
FUNCTIONS = [
    ("exec", "Run an external program, discarding most output."),
    ("shell_exec", "Run a shell command, returning its full output."),
    ("system", "Run an external program, streaming output directly."),
    ("passthru", "Run an external program, streaming raw output."),
    ("proc_open", "Open a process with full control over its I/O pipes."),
    ("popen", "Open a pipe to/from a process."),
    ("proc_close", "Close a process handle opened by proc_open."),
    ("proc_get_status", "Inspect a running process opened by proc_open."),
    ("proc_nice", "Change a process's scheduling priority."),
    ("proc_terminate", "Kill a process opened by proc_open."),
    ("pcntl_exec", "Replace the current process with a program."),
]

LOG_FILES = [
    ("web-access.log", "Web -- access"),
    ("web-error.log", "Web -- error"),
    ("php-error.log", "PHP-FPM -- error"),
    ("mail.log", "Mail (Postfix + Dovecot)"),
    ("sftp.log", "SFTP"),
]
TAIL_LINES = 200

PATH_RE = re.compile(r"^/[A-Za-z0-9/_.-]*$")
REDIRECT_TARGET_RE = re.compile(r"^(https?://[A-Za-z0-9/:?#\[\]@!*+,=._~%&-]+|/[A-Za-z0-9/_.\-?#=&%~]*)$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
NOEXEC_DIR_RE = re.compile(r"^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$")

# Seeded into every new tenant's noexec_dirs.txt at provisioning time (see
# provisioner.py's create_tenant) -- covers the writable-directory shape
# most PHP CMSes ship with (WordPress's wp-content/uploads, Drupal's
# sites/default/files) plus generic names a hand-rolled app is likely to
# use, so code execution in uploads is denied out of the box rather than
# only after a tenant discovers they need to add it themselves. Editable
# per tenant afterward -- this is a starting default, not a fixed list.
DEFAULT_NOEXEC_DIRS = ["wp-content/uploads", "sites/default/files", "uploads", "files", "media"]


# --- PHP functions ---

def read_enabled_functions(phpconf_dir: Path) -> set[str]:
    f = phpconf_dir / "enabled_functions.txt"
    if not f.exists():
        return set()
    return {ln.strip() for ln in f.read_text().splitlines() if ln.strip()}


def write_enabled_functions(phpconf_dir: Path, enabled: set[str]) -> None:
    valid = {fn for fn, _ in FUNCTIONS}
    phpconf_dir.mkdir(parents=True, exist_ok=True)
    (phpconf_dir / "enabled_functions.txt").write_text("\n".join(sorted(enabled & valid)) + "\n")


# --- 404 fallback ---

def fallback_marker(webroot_dir: Path) -> Path:
    return webroot_dir / ".vhsp-no-404-fallback"


def fallback_enabled(webroot_dir: Path) -> bool:
    return not fallback_marker(webroot_dir).exists()


def set_fallback_enabled(webroot_dir: Path, enabled: bool) -> None:
    marker = fallback_marker(webroot_dir)
    if enabled:
        marker.unlink(missing_ok=True)
    else:
        webroot_dir.mkdir(parents=True, exist_ok=True)
        marker.touch()


# --- Password protection (HTTP Basic Auth) ---

def read_basic_auth_user(phpconf_dir: Path) -> str:
    f = phpconf_dir / "basic_auth.txt"
    if not f.exists():
        return ""
    lines = f.read_text().splitlines()
    return lines[0].split(":", 1)[0] if lines and ":" in lines[0] else ""


def set_basic_auth(phpconf_dir: Path, username: str, password: str) -> str | None:
    if not username or not USERNAME_RE.match(username):
        return "Username must be non-empty and contain only letters, digits, '.', '_', '-'."
    if not password:
        return "Enter a password."
    phpconf_dir.mkdir(parents=True, exist_ok=True)
    (phpconf_dir / "basic_auth.txt").write_text(f"{username}:{apr_md5_crypt.hash(password)}\n")
    return None


def disable_basic_auth(phpconf_dir: Path) -> None:
    phpconf_dir.mkdir(parents=True, exist_ok=True)
    (phpconf_dir / "basic_auth.txt").write_text("")


# --- Custom error pages / redirects (line-based textarea files) ---

def read_lines_file(phpconf_dir: Path, name: str) -> str:
    f = phpconf_dir / name
    return f.read_text() if f.exists() else ""


def validate_error_page_line(parts: list[str]) -> str | None:
    if len(parts) != 2:
        return "each line must be 'CODE /path', e.g. '404 /custom-404.html'"
    code, path = parts
    if not re.fullmatch(r"[45][0-9]{2}", code):
        return f"{code!r} isn't a 3-digit HTTP error code (400-599)"
    if not PATH_RE.match(path) or ".." in path:
        return f"{path!r} must start with '/' and contain only safe path characters"
    return None


def validate_redirect_line(parts: list[str]) -> str | None:
    if len(parts) != 2:
        return "each line must be '/from-path target', e.g. '/old-page /new-page'"
    from_path, to = parts
    if not PATH_RE.match(from_path) or ".." in from_path:
        return f"{from_path!r} must start with '/' and contain only safe path characters"
    if not REDIRECT_TARGET_RE.match(to):
        return f"{to!r} must be an absolute path or http(s):// URL with safe characters"
    return None


def validate_noexec_dir_line(parts: list[str]) -> str | None:
    if len(parts) != 1:
        return "each line must be a single directory path relative to the webroot (no spaces), e.g. 'wp-content/uploads'"
    path = parts[0]
    if not NOEXEC_DIR_RE.match(path) or ".." in path:
        return f"{path!r} must be a relative path (no leading/trailing slash, no '..') using only letters, digits, '.', '_', '-', '/'"
    return None


def write_lines_file(phpconf_dir: Path, name: str, raw_text: str, validate_line) -> str | None:
    """Validates every non-blank line with validate_line; on success
    writes the cleaned file and returns None, otherwise writes nothing
    and returns an error string."""
    raw_lines = [ln.strip() for ln in raw_text.splitlines() if ln.strip()]
    cleaned = []
    for ln in raw_lines:
        parts = ln.split(None, 1)
        problem = validate_line(parts)
        if problem:
            return f"Line {ln!r}: {problem}"
        cleaned.append(" ".join(parts))
    phpconf_dir.mkdir(parents=True, exist_ok=True)
    (phpconf_dir / name).write_text("\n".join(cleaned) + ("\n" if cleaned else ""))
    return None


# --- IP allow/deny ---

def read_ip_acl(phpconf_dir: Path) -> tuple[str, str]:
    """Returns (mode, textarea_content)."""
    f = phpconf_dir / "ip_acl.txt"
    existing = f.read_text().splitlines() if f.exists() else []
    mode = existing[0] if existing and existing[0] in ("allow", "deny") else ""
    current = "\n".join(existing[1:]) if mode else "\n".join(existing)
    return mode, current


def write_ip_acl(phpconf_dir: Path, mode: str, raw_text: str) -> str | None:
    if mode not in ("", "allow", "deny"):
        return "Invalid mode."
    entries = [ln.strip() for ln in raw_text.splitlines() if ln.strip()]
    for ln in entries:
        try:
            ipaddress.ip_network(ln, strict=False)
        except ValueError:
            return f"Not a valid IP or CIDR: {ln!r}"
    if mode and not entries:
        return "Add at least one IP/CIDR, or choose Disabled."
    phpconf_dir.mkdir(parents=True, exist_ok=True)
    f = phpconf_dir / "ip_acl.txt"
    f.write_text(mode + "\n" + "\n".join(entries) + "\n" if mode else "")
    return None


# --- Email / mailboxes ---
#
# Each mailbox is {"hash": <SHA512-CRYPT>, "quota_bytes": int | None}.
# quota_bytes is None (no quota_bytes field, or an empty one) meaning
# unlimited -- a per-mailbox limit independent of and additional to the
# tenant-wide combined quota (config.DEFAULT_TENANT_QUOTA_BYTES): Dovecot
# enforces this one for real at delivery time (see images/mail/
# entrypoint.sh's quota plugin), unlike the tenant-wide one which is
# soft/monitor-only. Whatever a mailbox actually uses still counts toward
# the tenant-wide total either way -- that's measured by `du` over the
# whole mail directory, which doesn't care about per-mailbox limits.

def read_mailboxes(phpconf_dir: Path) -> dict[str, dict]:
    f = phpconf_dir / "mailboxes.txt"
    if not f.exists():
        return {}
    boxes = {}
    for line in f.read_text().splitlines():
        if ":" not in line:
            continue
        parts = line.split(":", 2)
        user, hash_ = parts[0], parts[1]
        quota_str = parts[2] if len(parts) > 2 else ""
        if user:
            boxes[user] = {"hash": hash_, "quota_bytes": int(quota_str) if quota_str.isdigit() and int(quota_str) > 0 else None}
    return boxes


def write_mailboxes(phpconf_dir: Path, boxes: dict[str, dict]) -> None:
    phpconf_dir.mkdir(parents=True, exist_ok=True)
    lines = []
    for u, b in boxes.items():
        quota_str = str(b["quota_bytes"]) if b.get("quota_bytes") else ""
        lines.append(f"{u}:{b['hash']}:{quota_str}\n")
    (phpconf_dir / "mailboxes.txt").write_text("".join(lines))


def add_mailbox(phpconf_dir: Path, user: str, password: str) -> str | None:
    if not user or not USERNAME_RE.match(user):
        return "Username must be non-empty and contain only letters, digits, '.', '_', '-'."
    boxes = read_mailboxes(phpconf_dir)
    if user in boxes:
        return f"{user} already exists."
    if not password:
        return "Enter a password."
    boxes[user] = {"hash": sha512_crypt.hash(password), "quota_bytes": None}
    write_mailboxes(phpconf_dir, boxes)
    return None


def reset_mailbox_password(phpconf_dir: Path, user: str, password: str) -> str | None:
    boxes = read_mailboxes(phpconf_dir)
    if user not in boxes:
        return f"No such mailbox: {user}."
    if not password:
        return "Enter a new password."
    boxes[user]["hash"] = sha512_crypt.hash(password)
    write_mailboxes(phpconf_dir, boxes)
    return None


def delete_mailbox(phpconf_dir: Path, user: str) -> str | None:
    if user == POSTMASTER:
        return "postmaster can't be deleted -- every domain must accept mail for it."
    boxes = read_mailboxes(phpconf_dir)
    if user not in boxes:
        return f"No such mailbox: {user}."
    del boxes[user]
    write_mailboxes(phpconf_dir, boxes)
    return None


def reset_all_mailbox_passwords(phpconf_dir: Path) -> dict[str, str]:
    """Regenerates every mailbox's password at once and returns
    {user: new_password} -- the operator's coarse incident-response
    lever (see provisioner.reset_tenant_mailbox_passwords), same
    "no way to tell which one's compromised, reset all of them"
    reasoning provisioner.clear_tenant_webauthn_keys already uses for
    the panel side. Unlike add_mailbox/reset_mailbox_password above
    (one user, a password the tenant or operator typed in), this
    generates every password itself -- there's no single party who'd
    type N replacement passwords into one action."""
    boxes = read_mailboxes(phpconf_dir)
    new_passwords = {}
    for user, box in boxes.items():
        password = secrets.token_urlsafe(18)
        box["hash"] = sha512_crypt.hash(password)
        new_passwords[user] = password
    write_mailboxes(phpconf_dir, boxes)
    return new_passwords


def set_mailbox_quota(phpconf_dir: Path, user: str, quota_bytes: int | None) -> str | None:
    boxes = read_mailboxes(phpconf_dir)
    if user not in boxes:
        return f"No such mailbox: {user}."
    if quota_bytes is not None and quota_bytes < 1:
        return "Quota must be at least 1 MB, or blank for unlimited."
    boxes[user]["quota_bytes"] = quota_bytes
    write_mailboxes(phpconf_dir, boxes)
    return None


# --- Logs ---

def tail_log(logs_dir: Path, fname: str, n: int = TAIL_LINES) -> str | None:
    f = logs_dir / fname
    if not f.exists():
        return None
    lines = f.read_text(errors="replace").splitlines()
    return "\n".join(lines[-n:]) if lines else None
