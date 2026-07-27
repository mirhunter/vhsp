"""Append-only audit log for privileged control-plane actions.

Per architecture.md's control-plane auth section: every tenant
create/destroy needs a trail that outlives the control plane itself. This
module is the local, append-only half of that. Off-host shipping (the other
half the doc calls for, so a host compromise can't retroactively erase the
trail) lives in backup.ship_audit_log, run every minute by
vhsp-audit-ship.timer -- see the control-plane README's "Backup / restore"
section for the shipping mechanism and remote layout.

**"Append-only" here means by convention and file permissions (0600,
opened in "a" mode), not a real filesystem guarantee** -- anyone with the
file's owner privileges (which, per the README's "Sudo scoping" section,
includes anyone who compromised the admin process and reached the two
allowed sudo scripts... though notably neither of those touches this
file) can still edit or truncate it. The hash chain below (`prev_hash`
on every entry, `verify_chain()`) doesn't make the file immutable either,
but it does make tampering *detectable* -- editing or deleting a past
line breaks the chain from that point forward, and `vhsp audit verify`
(cli.py) catches it. Off-host shipping is still the real defense (a
compromise can't retroactively edit what's already left the host); this
just closes the gap between "compromised" and "next successful ship."
"""

import hashlib
import json
import os
import stat
from datetime import datetime, timezone

from vhsp_ctl.config import STATE_DIR

AUDIT_LOG_PATH = STATE_DIR / "audit.log"


def _raw_lines() -> list[bytes]:
    if not AUDIT_LOG_PATH.exists():
        return []
    return [line for line in AUDIT_LOG_PATH.read_bytes().split(b"\n") if line]


def _last_entry_hash() -> str:
    """sha256 of the most recent line's exact JSON bytes (no trailing
    newline) -- "" for an empty log, the genesis value the first-ever
    entry's prev_hash is checked against. Reads the whole file each
    call rather than seeking from the end; fine at this scale, and
    ship_audit_log already keeps this file small by shipping it off-host
    every minute."""
    lines = _raw_lines()
    return hashlib.sha256(lines[-1]).hexdigest() if lines else ""


def log_action(action: str, domain: str, actor: str, ip: str | None = None) -> None:
    """ip is optional and only ever passed by web.py's login/login_failed/
    logout call sites (Flask's request.remote_addr, already correctly
    resolved through ProxyFix) -- deploy/fail2ban's vhsp-admin-login jail
    watches this file for exactly that field on admin.login_failed
    entries. Every other call site is unaffected: omitted from the
    entry entirely when not passed, not even an empty string, so old
    tooling reading this file sees no schema change for actions that
    never had an IP concept in the first place."""
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "domain": domain,
        "actor": actor,
        "prev_hash": _last_entry_hash(),
    }
    if ip is not None:
        entry["ip"] = ip
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    os.chmod(AUDIT_LOG_PATH, stat.S_IRUSR | stat.S_IWUSR)


def verify_chain() -> tuple[bool, int]:
    """Walks the log confirming each entry's prev_hash matches the actual
    hash of the line before it. Returns (chain_intact, entry_count) on
    success; on a break, (False, index_of_first_bad_entry) -- the index
    doubles as "how many entries are still trustworthy" (everything
    before it verified correctly). An empty log is trivially intact.

    Entries written before this field existed have no "prev_hash" key at
    all -- deliberately NOT treated as "prev_hash was empty string" (that
    would make verify_chain report a spurious break at the second old
    entry on every log that predates this feature, which is every log on
    first deploy). Instead, old-format entries are skipped without
    asserting anything, and the first entry that *does* have a
    "prev_hash" is trusted as a fresh starting point -- it was computed
    correctly at write time against whatever the real last line was, old-
    format or not, so there's nothing earlier to check it against. Strict
    verification applies from there on.
    """
    return _verify_lines(_raw_lines())


def _verify_lines(lines: list[bytes]) -> tuple[bool, int]:
    prev_hash = None  # None = "no chain established yet"
    for i, raw_line in enumerate(lines):
        try:
            entry = json.loads(raw_line)
        except json.JSONDecodeError:
            return False, i
        if "prev_hash" not in entry:
            prev_hash = None
            continue
        if prev_hash is not None and entry["prev_hash"] != prev_hash:
            return False, i
        prev_hash = hashlib.sha256(raw_line).hexdigest()
    return True, len(lines)


def verify_chain_at(path) -> tuple[bool, int]:
    """verify_chain() against an arbitrary log file, for the per-tenant
    audit logs images/tenant-admin/ writes onto each tenant's phpconf
    volume. Same format by construction (that container reimplements
    this module's write path, since it can't import it across the trust
    boundary), so the verification is genuinely shared rather than a
    third parallel copy that could drift from the other two.

    Reads the file directly off the host, which is the point for
    incident response: it works when the tenant's container is stopped,
    wedged, or actively compromised -- exactly when its own /audit page
    is least trustworthy or least reachable.
    """
    if not path.exists():
        return True, 0
    return _verify_lines([line for line in path.read_bytes().split(b"\n") if line])
