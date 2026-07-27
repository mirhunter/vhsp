"""Platform-wide fail2ban allowlist -- IPs/CIDRs an operator never wants
banned by any jail. Same read/write-a-flat-file shape as toggles.py's
read_ip_acl/write_ip_acl (that one's per-tenant and mode-based --
allow-list vs deny-list for site access; this one is simpler, just a
flat set of "never ban this" entries, platform-wide, for fail2ban's own
ignorecommand hook to check on every ban decision).

Deliberately a plain-text file, not JSON or a registry table:
deploy/vhsp-fail2ban-allowlist-check (a bash script, run by fail2ban's
own root-owned service on every check) reads this directly -- no JSON
parser needed. (Matching CIDR entries, not just exact IPs, needs real
containment math -- that script shells out to Python's ipaddress module
for it rather than a plain-text match like `grep -Fxq`, so keep this
file's format compatible with that, not with a simpler grep.)
"""

import ipaddress
import os
import stat

from vhsp_ctl.config import FAIL2BAN_OPERATOR_ALLOWLIST_PATH


def read_entries() -> list[str]:
    if not FAIL2BAN_OPERATOR_ALLOWLIST_PATH.exists():
        return []
    return [ln.strip() for ln in FAIL2BAN_OPERATOR_ALLOWLIST_PATH.read_text().splitlines() if ln.strip()]


def write_entries(entries: list[str]) -> str | None:
    """Returns an error message, or None on success -- same "validate,
    return a message instead of raising" convention as toggles.py's
    write_ip_acl, since both are called directly from a web form
    handler that wants to flash the error back to the user."""
    cleaned = [e.strip() for e in entries if e.strip()]
    for entry in cleaned:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return f"Not a valid IP or CIDR: {entry!r}"
    FAIL2BAN_OPERATOR_ALLOWLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    FAIL2BAN_OPERATOR_ALLOWLIST_PATH.write_text("\n".join(cleaned) + "\n" if cleaned else "")
    # World-readable, deliberately -- deploy/vhsp-fail2ban-allowlist-check
    # runs as fail2ban's own root service, which can already read
    # anything regardless, but this file has nothing sensitive in it (it's
    # a list of IPs an operator chose to exempt from banning, not a
    # secret) and a restrictive 0600 here would be misleading over-caution
    # relative to every other file in this module's own family.
    os.chmod(FAIL2BAN_OPERATOR_ALLOWLIST_PATH, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    return None
