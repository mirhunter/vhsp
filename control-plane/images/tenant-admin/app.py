"""Tenant self-service admin page.

Features:
  - Re-enabling specific PHP functions the web container disables by default.
  - Toggling the web container's 404 fallback (nginx's stand-in for the
    .htaccess-based front-controller rewrite WordPress/Laravel/etc. expect
    on Apache -- nginx has no per-directory config file, so this has to be
    a real self-service toggle instead of a file the tenant just drops in
    themselves).
  - Password protection (HTTP Basic Auth), custom error pages, an IP
    allow/deny list, and simple redirects -- together the rest of what
    .htaccess is actually used for in practice on Apache. Same reasoning
    as the 404 toggle: nginx has no per-directory config file at all, so
    each of these needs a real self-service surface rather than a file a
    tenant could just drop into their webroot themselves.
  - Mailbox management: add/remove mailboxes and reset passwords, beyond
    the one starter `postmaster@` mailbox provisioning creates (RFC 5321
    requires it to exist, so it can never be deleted here -- only its
    password can be reset). Same "write a plain data file to a shared
    volume, the mail container's own entrypoint watches it and reloads
    postfix/dovecot" split as the nginx toggles above; see
    images/mail/entrypoint.sh's write_mail_users.
  - Viewing web/mail/sftp logs.
  - A webroot file manager (upload/delete/move/edit) -- owner-only like
    the SQL console, and additionally gated behind having a second factor
    registered at all (see require_2fa below): a deliberate carrot for
    turning 2FA on, not a generic floor applied to every owner-only page.
    TOTP costs nothing and takes a couple minutes, so "you need *a*
    second factor, don't care which" is a real ask, not a hardware-key
    tax -- see forbidden()'s no_2fa branch for what an owner without one
    sees when they try.

Login: form-based (session cookie), not HTTP Basic -- the user's own
requirement, to leave room for a 2FA step between password verification
and session establishment (see login() below), the way Basic Auth's
native browser dialog has no clean way to support. Credential is
generated once by provisioner.py before this container ever starts
(admin_credentials.json on the same phpconf volume, same format
vhsp_ctl/auth.py already uses for the *operator* admin UI's own single
credential) and shown once via `vhsp tenant create`/`show`. This
container is also still reachable only from the management network (see
provisioner._create_tenant_admin_container's Traefik entrypoint binding),
not the tenant-facing gateway -- login is now a real second factor on
top of that network restriction, not a replacement for it.

WebAuthn (see the Security key page): the same 2FA seam, actually wired
up now, ported from vhsp_ctl/webauthn.py's already-verified
implementation (same Yubico `fido2` library) rather than sharing that
module directly -- this container has no access to the control-plane's
own package, and per the pattern the web/mail entrypoints already use
(re-validate at every trust boundary), a separate implementation here is
consistent, not an oversight. RP ID is `admin.<TENANT_DOMAIN>` -- the
exact public hostname this page is served on -- so it only works over
that real HTTPS path (see architecture.md/the KVM setup notes: this
container also has a second, public-facing Traefik router now, not just
the management-network one), never the raw management-network IP.

TOTP (also the Security key page): a second, independent 2FA option
alongside WebAuthn above -- either, both, or neither; login accepts
whichever a user has registered. Added specifically as a free (no
hardware) alternative, to lower the bar for turning a second factor on
at all -- see require_2fa below for which pages actually require one
(the file manager and SQL console, plus the config knobs with real
blast radius if a no-2FA account is compromised).

PHP toggle: writes only a plain list of currently-enabled function names
to a shared volume -- never touches the web container directly (no
docker.sock, no signal, no API call). The web container's own entrypoint
watches that file and reloads itself; see images/web/entrypoint.sh. This
split is deliberate: architecture.md is explicit that tenant self-service
should stay local to the tenant's own containers, not call back into a
shared control-plane API or require privileged access to another
container.

404 fallback toggle: same "just a file on a volume both containers
already share" split, but simpler -- nginx's `location @fallback` checks
for `.vhsp-no-404-fallback`'s existence directly on every request (see
images/web/nginx.conf), so writing/removing it here takes effect
immediately, no reload or watcher loop needed the way the PHP toggle
requires. Mounted from the *webroot* volume specifically (not `phpconf`),
since that's the volume nginx's $document_root actually points at.

nginx self-service config (auth/error-pages/redirects/IP-acl): each writes
a small, tightly-validated plain-text data file to the shared `phpconf`
volume -- this container NEVER writes nginx syntax itself. The web
container's own entrypoint.sh is the trusted layer that turns these into
real nginx directives, tests the result with `nginx -t`, and only reloads
if it's valid -- same "self-service stays local to the tenant's own
containers, not a shared API" split as the PHP toggle, plus a second,
independent round of validation there since that's the code that actually
decides what becomes live nginx config. Passwords are hashed here
(APR1/MD5-crypt, the format nginx's auth_basic explicitly documents
support for) before ever touching disk -- the plaintext never leaves this
request.

Logs: same reasoning applies to why this reads files rather than calling
`docker logs` -- that would need docker.sock, i.e. root on the host, for
every tenant-facing container. Instead the web/mail/sftp containers each
write their own logs to files on a shared `logs` volume (see each image's
entrypoint.sh for why that wasn't already true by default -- nginx logs to
local files unless redirected, postfix/dovecot default to syslog which
doesn't exist in these minimal containers, and atmoz/sftp's own stdout
had to be wrapped since it's a third-party image), and this container
just reads them read-only.
"""

import base64
import fcntl
import hashlib
import hmac
import ipaddress
import json
import io
import logging
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestedCredentialData,
    AuthenticationResponse,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
)
import pymysql
import pyotp
import qrcode
import qrcode.image.svg
from flask import Flask, abort, jsonify, redirect, render_template_string, request, send_file, session, url_for
from passlib.hash import apr_md5_crypt, sha512_crypt
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

logger = logging.getLogger(__name__)

app = Flask(__name__)
# Unconditional, unlike vhsp_ctl/web.py's own ADMIN_TRUST_PROXY (an
# opt-in flag there, since that app can legitimately run with zero
# reverse-proxy hops in front of it on a private mgmt network) -- every
# tenant-admin container is *always* reached through the same local
# Traefik instance, on both the entrypoints it's ever given a router on,
# so there's no legitimate zero-hop case here to guard against. Without
# this, request.remote_addr is just Traefik's own bridge-network IP for
# every request, which would make login_attempts.log (see
# _login_record_failure) record Traefik's own address instead of real
# attacker IPs for every tenant -- confirmed this was happening before
# adding this line (real external test request showed up as
# `172.18.0.2`, the traefik network's own view of the connection, not
# the real client).
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)
# Basic hygiene for the file manager's upload endpoint on a small droplet
# (some real deployments here run on ~1GB RAM, see DEPLOYMENT.md) -- an
# unbounded request body would let one upload exhaust memory well before
# it ever reaches disk-quota enforcement (itself only soft/advisory, see
# get_disk_usage's own docstring). Not a per-tenant storage policy, just a
# ceiling on a single request.
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024

# TENANT_ADMIN_MGMTWEB_EXISTS (set by provisioner.py at container-create
# time, mirroring config.py's own flag of the same name) -- whether the
# mgmtweb-entrypoint Traefik router this container is also always given
# is actually reachable over plain HTTP on this deployment (a real
# interface, the original dev-VM topology) or just an inert router object
# nothing ever matches (vhsp2's single-public-IP setup, HTTPS-only in
# practice). Secure can't be hardcoded True: it would silently break
# legitimate plain-HTTP mgmt-network logins on any deployment where that
# path is real.
_MGMTWEB_EXISTS = os.environ.get("TENANT_ADMIN_MGMTWEB_EXISTS", "1").strip().lower() in ("1", "true", "yes")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = not _MGMTWEB_EXISTS
# Same idle-timeout mechanism as vhsp_ctl/web.py's identical addition --
# see that one's own comment. Without this, a Flask session cookie carries
# no expiry at all, so a tenant panel login (or an in-progress 2FA
# challenge) stayed valid forever once issued.
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    minutes=int(os.environ.get("TENANT_ADMIN_SESSION_LIFETIME_MINUTES", "30"))
)


@app.before_request
def _make_session_permanent():
    session.permanent = True


@app.after_request
def _security_headers(response):
    """Same three headers as vhsp_ctl/web.py's identical hook -- see that
    one's own docstring for why a real Content-Security-Policy isn't
    here too (this app leans on inline <script> even more than the
    operator UI does -- WebAuthn ceremonies, the CodeMirror mount
    script, DNS copy-to-clipboard -- so CSP needs its own nonce-threading
    pass, not a one-line header)."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # See vhsp_ctl/web.py's identical addition -- found chasing a real
    # report of a live DNS check appearing stale in a real browser.
    response.headers["Cache-Control"] = "no-store"
    return response


ENABLED_FILE = Path("/data/enabled_functions.txt")
BASIC_AUTH_FILE = Path("/data/basic_auth.txt")
ERROR_PAGES_FILE = Path("/data/error_pages.txt")
REDIRECTS_FILE = Path("/data/redirects.txt")
NOEXEC_DIRS_FILE = Path("/data/noexec_dirs.txt")
IP_ACL_FILE = Path("/data/ip_acl.txt")
MAILBOXES_FILE = Path("/data/mailboxes.txt")
# Written only by the operator's vhsp_ctl/provisioner.py
# (set_tenant_maintenance_mode) -- deliberately no route anywhere in this
# file ever writes it. Read-only here purely so a tenant can see *that*
# it's on and stop wondering why visitors/IMAP/sending aren't working;
# they can't lift it themselves, by design (e.g. a billing hold).
MAINTENANCE_MARKER_FILE = Path("/data/.vhsp-maintenance")
# Two-layer tenant API/MCP permission model (architecture.md's "API and
# MCP access for operators and tenants") -- api_allowed/mcp_allowed are
# Layer 1, operator-set, read-only from here (written by
# vhsp_ctl/provisioner.py's set_tenant_api_allowed/set_tenant_mcp_allowed,
# same "operator writes, tenant container only reads" split as
# MAINTENANCE_MARKER_FILE above); api_enabled/mcp_enabled are Layer 2,
# this tenant's own toggle, read AND written here (see
# api_tokens_view() below) -- unlike maintenance mode, this file has a
# writer on both sides, one JSON blob, different keys.
PLATFORM_ACCESS_FILE = Path("/data/.vhsp-platform-access.json")
# This tenant's own API/MCP bearer tokens -- same generate/hash/store/
# check idiom as WEBAUTHN_CREDENTIALS_FILE etc. below, and the same
# shape vhsp_ctl/api_auth.py's operator token store uses, but scoped to
# this one tenant and validated by vhsp_ctl/tenant_api_auth.py reading
# this identical file by host path (see that module's own docstring).
API_TOKENS_FILE = Path("/data/api_tokens.json")
# Pre-multi-user credential file -- no longer written, only read once by
# _migrate_legacy_single_admin() below. Left in place after migration
# rather than deleted (same caution around destructive cleanup this
# codebase uses elsewhere).
ADMIN_CREDENTIALS_FILE = Path("/data/admin_credentials.json")
TENANT_USERS_FILE = Path("/data/tenant_users.json")
# Per-tenant audit log. Same hash-chained JSONL shape as the operator's
# own vhsp_ctl/audit.py -- reimplemented here rather than imported for
# the same trust-boundary reason every other cross-container duplication
# in this file exists (this container has no access to that package).
#
# Lives on the phpconf volume, which means the OPERATOR can read it from
# the host. That's deliberate for support ("what did they change before
# it broke?"), but it's also exactly why _audit_safe_form below redacts
# rather than allowlists: a tenant's SQL queries and file contents must
# never end up in a file their host can read, so the log records that an
# action happened, never the tenant data it carried.
AUDIT_LOG_FILE = Path("/data/audit.log")
# Temporary operator access. Written by the host (vhsp_ctl.provisioner's
# grant_operator_access), read here on every request -- so a revoke on
# the operator side takes effect on this side's very next request, with
# no restart and nothing to invalidate.
OPERATOR_ACCESS_FILE = Path("/data/.vhsp-operator-access.json")
OPERATOR_ACTOR_PREFIX = "operator:"
# Trimmed to the newest N on write. The chain still verifies afterwards:
# verify walks forward and never checks the FIRST retained entry against
# anything (there's nothing before it to check against), so dropping a
# prefix is detectable as "log starts later than it used to" but doesn't
# read as tampering.
AUDIT_MAX_ENTRIES = 5000
# This container has no docker.sock/registry access at all -- these two
# files are the same "write intent, something host-side watches and acts"
# split as every other self-service feature here, except the watcher is a
# new HOST-SIDE systemd timer (vhsp_ctl/backup.py's process_requests, run
# every ~2 minutes), not an in-container loop, since backup key
# generation/mariadb-dump/SFTP push all need host/Docker access no sibling
# container has either. BACKUP_REQUEST_FILE is write-only from here (this
# container's own intent); BACKUP_STATUS_FILE is read-only (the
# reconciler's report back -- current destination settings, the tenant's
# own public transport key, and a one-time-only age private key reveal
# right after it's first generated, never again after that).
BACKUP_REQUEST_FILE = Path("/data/backup_request.json")
BACKUP_STATUS_FILE = Path("/data/backup_status.json")
BACKUP_NOW_MARKER = Path("/data/.vhsp-backup-now")
# Written by the host (vhsp_ctl.provisioner._write_dns_records_status) on
# every mail-container create/recreate -- same read-only "host computes,
# container just reads" split as BACKUP_STATUS_FILE, this container has no
# docker/host access of its own to compute a DKIM value or know the
# platform's public IP either.
DNS_RECORDS_FILE = Path("/data/dns_records.json")
SECRET_KEY_FILE = Path("/data/flask_secret_key")
# This container always runs as root (no USER in the Dockerfile -- needed
# for the entrypoint's own setup work), so any 0600 file it creates on the
# phpconf bind mount is root-owned on the host. vhsp_ctl.provisioner reads
# a few of these files directly (webauthn/tenant_users, for the operator's
# tenant-detail page and the "reset admin password" action) running as
# whatever OS user runs vhsp-admin.service -- root ownership makes those
# reads fail with EACCES the moment this container (re)writes the file
# first. provisioner._create_tenant_admin_container passes its own
# os.getuid()/os.getgid() through as these two env vars so the files this
# container creates can be chowned back to that user, keeping them at 0600
# (nothing here should be world- or group-readable) while still letting
# the host-side code that legitimately needs them read/write them too --
# root inside this container can always read/write them regardless of
# ownership (DAC_OVERRIDE), so nothing here is lost by giving the host
# user ownership instead of root.
_HOST_UID = int(os.environ["VHSP_HOST_UID"]) if os.environ.get("VHSP_HOST_UID", "").isdigit() else None
_HOST_GID = int(os.environ["VHSP_HOST_GID"]) if os.environ.get("VHSP_HOST_GID", "").isdigit() else None


def _chown_to_host(path: Path) -> None:
    """No-op if the host UID/GID wasn't passed in (e.g. a container
    started by hand outside provisioner.py) -- the file just stays
    root-owned in that case, same as before this fix existed. Logs to
    stderr (visible in `docker logs`) rather than failing silently: a
    follow-up security review flagged that a future refactor dropping
    VHSP_HOST_UID/GID from _create_tenant_admin_container's environment
    would silently resurrect the exact host-side EACCES bug this
    mechanism exists to prevent, with nothing pointing at the cause."""
    if _HOST_UID is not None and _HOST_GID is not None:
        os.chown(path, _HOST_UID, _HOST_GID)
    else:
        print(f"WARNING: VHSP_HOST_UID/GID not set -- {path} stays root-owned, "
              f"host-side reads of it will fail", file=sys.stderr)


WEBAUTHN_CREDENTIALS_FILE = Path("/data/webauthn_credentials.json")
# TOTP (authenticator app) -- an alternative second factor to the WebAuthn
# keys above, same role, independently implemented (this file keeps its
# own copy of everything security-relevant rather than importing
# vhsp_ctl's, per this file's own top-of-file trust-boundary note). One
# secret per username, not a list like WEBAUTHN_CREDENTIALS_FILE -- no
# equivalent here to "multiple physical keys": scanning the same QR into
# a second device already works without a second stored secret.
TOTP_SECRETS_FILE = Path("/data/totp_secrets.json")
# Failed-login lockout -- same design as vhsp_ctl/login_throttle.py
# (independently implemented here for the same reason TOTP_SECRETS_FILE
# above is: this container keeps its own copy of everything
# security-relevant rather than importing across the trust boundary).
# File-based, not in-memory, so it survives a container restart and
# doesn't need this app to run single-process to stay correct.
LOGIN_ATTEMPTS_FILE = Path("/data/login_attempts.json")
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_LOCKOUT_SECONDS = 15 * 60
MIN_PASSWORD_LENGTH = 12
# Genuine append-only log (distinct from LOGIN_ATTEMPTS_FILE above,
# which is a rewritten-in-place *state* dict) -- fail2ban's
# [vhsp-tenant-admin-login] jail tails this across every tenant via a
# wildcard logpath. Only real, not-yet-allowlisted failures get a line
# here -- see _login_record_failure and FAIL2BAN_ALLOWLIST_FILE below.
# Touched at import time (every container start) rather than only on
# first failure -- fail2ban's own config test treats a wildcard logpath
# matching zero files as a hard error, not just "nothing to watch yet",
# so a brand-new tenant needs this file to exist from the moment its
# container starts, not from its first failed login.
LOGIN_ATTEMPTS_LOG_FILE = Path("/data/login_attempts.log")
LOGIN_ATTEMPTS_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
LOGIN_ATTEMPTS_LOG_FILE.touch(exist_ok=True)
# Per-tenant fail2ban allowlist -- same shape/location convention as
# IP_ACL_FILE below (host-visible at TENANTS_DIR/<slug>/phpconf/ once
# mounted), but a flat list, not a mode+list ACL: IPs here never
# contribute to THIS tenant's own failed-login count. Can't exempt an
# IP from a ban a *different* tenant's traffic triggers (bans on this
# jail are platform-wide -- see the control-plane README's fail2ban
# section for why), only from counting against this tenant specifically.
FAIL2BAN_ALLOWLIST_FILE = Path("/data/fail2ban_allowlist.txt")
POSTMASTER = "postmaster"
LOGS_DIR = Path("/logs")
WEBROOT_DIR = Path("/webroot")
FALLBACK_MARKER = WEBROOT_DIR / ".vhsp-no-404-fallback"
# Extensions the file manager's editor will open inline without sniffing
# content first -- covers everything a tenant plausibly hand-edits here
# (their own app code/config), not an exhaustive MIME registry. Anything
# not listed still gets a content-based sniff (see _is_text_file) rather
# than being refused outright, so an unlisted-but-genuinely-text file
# (e.g. a bare `.htaccess`-style dotfile) still opens.
FILES_TEXT_EXTENSIONS = {
    ".php", ".phtml", ".html", ".htm", ".css", ".js", ".mjs", ".json",
    ".txt", ".md", ".markdown", ".xml", ".yml", ".yaml", ".ini", ".conf",
    ".env", ".sql", ".csv", ".svg", ".sh", ".py", ".rb", ".twig", ".vue",
    ".jsx", ".tsx", ".ts", ".log", ".htpasswd", ".htaccess",
    ".gitignore", ".editorconfig",
}
# Above this, the inline textarea editor is more likely to hang a browser
# tab than be useful -- download/edit-via-SFTP instead. Uploads/deletes/
# moves have no such cap; only loading a full file into one HTTP response
# for in-browser editing does.
FILES_MAX_EDIT_BYTES = 2 * 1024 * 1024
TENANT_DOMAIN = os.environ.get("TENANT_DOMAIN", "(unknown)")
# Same charset-cleaning provisioner.slugify() uses -- duplicated rather
# than a new TENANT_SLUG env var, since it's fully derivable from
# TENANT_DOMAIN (already present) with no new container-recreation
# dependency. Used only as the public prefix on this tenant's own API
# tokens (see api_tokens_view() below) so vhsp_ctl/tenant_api_auth.py
# can resolve which tenant a token belongs to without scanning every
# tenant's own token file on every request.
TENANT_SLUG = re.sub(r"[^a-z0-9-]+", "-", TENANT_DOMAIN.lower()).strip("-")
# The shared host the tenant-scoped REST API/MCP surface actually lives
# on -- not this tenant's own subdomain. Falls back to TENANT_DOMAIN only
# so the page never shows a blank/broken example if this env var is ever
# missing (e.g. a container started by hand); on any real deployment
# provisioner.py always sets it.
PLATFORM_API_HOST = os.environ.get("PLATFORM_API_HOST", TENANT_DOMAIN)

# Same DB the tenant's own web container connects to, same non-root
# credential -- see provisioner.py's _create_tenant_admin_container
# docstring for why that's deliberate (the Database page's SQL console
# can't do anything the tenant's own app code couldn't already do).
DB_HOST = os.environ.get("DB_HOST", "")
DB_PORT = int(os.environ.get("DB_PORT", "3306"))
DB_NAME = os.environ.get("DB_NAME", "")
DB_USER = os.environ.get("DB_USER", "")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")

# For the Overview page's SFTP connect line -- this container has no
# registry access (see this file's own top-of-file trust-boundary note),
# so these have to arrive as env vars just like DB_* above, not be looked
# up live. See provisioner._create_tenant_admin_container.
SSH_PORT = os.environ.get("SSH_PORT", "")
SFTP_USER = os.environ.get("SFTP_USER", "")

MAIL_DIR = Path("/mail")
QUOTA_LIMIT_FILE = Path("/data/quota_limit_bytes.txt")
DEFAULT_QUOTA_BYTES = 200 * 1024 * 1024  # matches vhsp_ctl/config.py's DEFAULT_TENANT_QUOTA_BYTES


def _du_bytes(path: Path) -> int:
    if not path.exists():
        return 0
    result = subprocess.run(["du", "-sb", str(path)], capture_output=True, text=True)
    if result.returncode != 0:
        return 0
    return int(result.stdout.split()[0])


def get_disk_usage() -> dict:
    """Same three-part measurement as the operator admin UI's
    provisioner.get_tenant_disk_usage -- independently reimplemented here
    (same "separate trust boundary, no shared import" reasoning as
    everything else duplicated between the two apps) but computed from
    inside this container instead of from the host: `du` on the
    directly-mounted /webroot and /mail (read-only mounts added
    specifically for this), and the identical information_schema query
    against the same DB this container's own Database page already
    queries, over the connection it already has."""
    web_bytes = _du_bytes(WEBROOT_DIR)
    mail_bytes = _du_bytes(MAIL_DIR)
    db_bytes = 0
    try:
        conn = pymysql.connect(
            host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD,
            database=DB_NAME, connect_timeout=5,
        )
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COALESCE(SUM(data_length+index_length),0) FROM information_schema.tables "
                    "WHERE table_schema=%s", (DB_NAME,),
                )
                db_bytes = cur.fetchone()[0]
        finally:
            conn.close()
    except Exception:
        pass  # never let a DB hiccup break the whole page's rendering
    return {"web": web_bytes, "db": db_bytes, "mail": mail_bytes, "total": web_bytes + db_bytes + mail_bytes}


def get_quota_limit() -> int:
    if not QUOTA_LIMIT_FILE.exists():
        return DEFAULT_QUOTA_BYTES
    return int(QUOTA_LIMIT_FILE.read_text().strip())


def format_mb(n_bytes: int) -> str:
    return f"{n_bytes / (1024 * 1024):.1f} MB"


def _human_size(n_bytes: int) -> str:
    """Unlike format_mb (always MB, fine for a quota bar), a file listing
    needs small files to read as small -- "0.0 MB" for a 200-byte
    robots.txt is useless."""
    size = float(n_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


class FilesError(Exception):
    pass


def _safe_webroot_path(rel_path: str) -> Path:
    """The file manager's one load-bearing security check -- every route
    below resolves every tenant-supplied path through this before touching
    the filesystem. Rejects anything that would resolve outside
    WEBROOT_DIR (`..` segments, an absolute path, a symlink planted
    earlier that points out of the tree) rather than trying to sanitize
    the string itself, since resolving and checking the *real* final
    location is the only check that can't be tricked by encoding tricks a
    string-blocklist would miss.

    Doesn't require the path to exist -- callers that need it to (delete,
    move-source, edit, download) check that themselves; upload and
    move-destination legitimately name a path that doesn't exist yet.
    """
    rel_path = (rel_path or "").strip().strip("/")
    root = WEBROOT_DIR.resolve()
    candidate = (root / rel_path).resolve() if rel_path else root
    if candidate != root and root not in candidate.parents:
        raise FilesError("that path isn't inside the webroot")
    return candidate


def _is_vhsp_internal(path: Path) -> bool:
    """The one file in the webroot this container itself owns (the
    404-fallback toggle's marker, see FALLBACK_MARKER) -- hidden from the
    listing and refused by every mutating route so a tenant can't delete/
    move/edit their way into breaking that toggle's own state out from
    under it without realizing what the file was."""
    return path == FALLBACK_MARKER.resolve()


def _is_text_file(path: Path) -> bool:
    if path.suffix.lower() in FILES_TEXT_EXTENSIONS or path.name.lower() in FILES_TEXT_EXTENSIONS:
        return True
    try:
        chunk = path.open("rb").read(8192)
    except OSError:
        return False
    if b"\x00" in chunk:
        return False
    try:
        chunk.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def list_webroot_dir(rel_path: str) -> tuple[Path, list[dict]]:
    """Returns (resolved directory, entries) -- entries sorted
    directories-first then alphabetically, matching how most file
    managers order a listing. Raises FilesError if rel_path doesn't
    resolve to a real, existing directory inside the webroot."""
    directory = _safe_webroot_path(rel_path)
    if not directory.is_dir():
        raise FilesError("no such directory")
    entries = []
    for child in directory.iterdir():
        if _is_vhsp_internal(child.resolve()):
            continue
        stat_result = child.stat()
        child_rel = child.relative_to(WEBROOT_DIR.resolve())
        entries.append({
            "name": child.name,
            "rel_path": str(child_rel),
            "is_dir": child.is_dir(),
            "size": stat_result.st_size if child.is_file() else None,
            "size_human": _human_size(stat_result.st_size) if child.is_file() else "",
            "mtime": datetime.fromtimestamp(stat_result.st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M"),
            "is_text": child.is_file() and _is_text_file(child),
        })
    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    return directory, entries


# The exact public hostname this container is served on -- see
# provisioner.py's dual-router setup. Fixed at startup, not derived from
# the request, same reasoning as vhsp_ctl/webauthn.py's own fixed RP_ID.
WEBAUTHN_RP_ID = f"admin.{TENANT_DOMAIN}"
_webauthn_server = Fido2Server(PublicKeyCredentialRpEntity(id=WEBAUTHN_RP_ID, name=f"{TENANT_DOMAIN} tenant admin"))


def _load_webauthn_credentials() -> list[dict]:
    """Entries from before multi-user support have no "owner" field --
    treated as belonging to the same legacy "admin" username
    _migrate_legacy_single_admin() preserves, and rewritten with that
    owner set so it's persisted rather than re-computed on every load."""
    if not WEBAUTHN_CREDENTIALS_FILE.exists():
        return []
    entries = json.loads(WEBAUTHN_CREDENTIALS_FILE.read_text())
    migrated = False
    for e in entries:
        if "owner" not in e:
            e["owner"] = "admin"
            migrated = True
    if migrated:
        _save_webauthn_credentials(entries)
    return entries


def _save_webauthn_credentials(entries: list[dict]) -> None:
    WEBAUTHN_CREDENTIALS_FILE.parent.mkdir(parents=True, exist_ok=True)
    WEBAUTHN_CREDENTIALS_FILE.write_text(json.dumps(entries))
    os.chmod(WEBAUTHN_CREDENTIALS_FILE, stat.S_IRUSR | stat.S_IWUSR)
    _chown_to_host(WEBAUTHN_CREDENTIALS_FILE)


def _attested_credentials(owner: str) -> list[AttestedCredentialData]:
    return [AttestedCredentialData(base64.b64decode(e["credential_data"])) for e in _load_webauthn_credentials() if e["owner"] == owner]


def _has_credentials(owner: str) -> bool:
    return any(e["owner"] == owner for e in _load_webauthn_credentials())


def _name_taken(owner: str, name: str) -> bool:
    return any(e["owner"] == owner and e["name"] == name for e in _load_webauthn_credentials())


TOTP_ISSUER = f"{TENANT_DOMAIN} admin"


def _load_totp() -> dict:
    if not TOTP_SECRETS_FILE.exists():
        return {}
    return json.loads(TOTP_SECRETS_FILE.read_text())


def _save_totp(entries: dict) -> None:
    TOTP_SECRETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    TOTP_SECRETS_FILE.write_text(json.dumps(entries))
    os.chmod(TOTP_SECRETS_FILE, stat.S_IRUSR | stat.S_IWUSR)
    _chown_to_host(TOTP_SECRETS_FILE)


_PLATFORM_ACCESS_DEFAULTS = {
    "api_allowed": False, "mcp_allowed": False, "api_enabled": False, "mcp_enabled": False,
}


def _load_platform_access() -> dict:
    """Same shape as vhsp_ctl/provisioner.py's tenant_platform_access()
    -- reads the identical file this container shares with the operator
    process, defaulting missing keys/file to all-False."""
    if not PLATFORM_ACCESS_FILE.exists():
        return dict(_PLATFORM_ACCESS_DEFAULTS)
    try:
        data = json.loads(PLATFORM_ACCESS_FILE.read_text())
    except json.JSONDecodeError:
        data = {}
    return {key: bool(data.get(key, default)) for key, default in _PLATFORM_ACCESS_DEFAULTS.items()}


def _set_platform_access_enabled(*, api_enabled: bool | None = None, mcp_enabled: bool | None = None) -> None:
    """Layer 2 only -- this container never writes api_allowed/mcp_allowed
    (Layer 1), those are operator-only (see PLATFORM_ACCESS_FILE's own
    comment). Read-modify-write so a Layer-2 change here never clobbers
    Layer 1's current value, and vice versa when the operator writes
    their half independently."""
    current = _load_platform_access()
    if api_enabled is not None:
        current["api_enabled"] = api_enabled
    if mcp_enabled is not None:
        current["mcp_enabled"] = mcp_enabled
    PLATFORM_ACCESS_FILE.parent.mkdir(parents=True, exist_ok=True)
    PLATFORM_ACCESS_FILE.write_text(json.dumps(current))
    _chown_to_host(PLATFORM_ACCESS_FILE)


def _load_api_tokens() -> dict:
    if not API_TOKENS_FILE.exists():
        return {}
    return json.loads(API_TOKENS_FILE.read_text())


def _save_api_tokens(entries: dict) -> None:
    API_TOKENS_FILE.parent.mkdir(parents=True, exist_ok=True)
    API_TOKENS_FILE.write_text(json.dumps(entries))
    os.chmod(API_TOKENS_FILE, stat.S_IRUSR | stat.S_IWUSR)
    _chown_to_host(API_TOKENS_FILE)


def mint_api_token(label: str) -> str:
    """Returns the plaintext token -- shown once, same "generated, shown
    once, never recoverable" idiom as every other credential here.
    Prefixed with this tenant's own slug (see TENANT_SLUG's own comment)
    so vhsp_ctl/tenant_api_auth.py can resolve straight to this tenant's
    token file without scanning every tenant's own."""
    tokens = _load_api_tokens()
    token_id = secrets.token_hex(8)
    token = f"{TENANT_SLUG}.{secrets.token_urlsafe(32)}"
    tokens[token_id] = {
        "hash": generate_password_hash(token),
        "label": label,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_api_tokens(tokens)
    return token


def list_api_tokens() -> list[dict]:
    return [
        {"token_id": token_id, **{k: v for k, v in entry.items() if k != "hash"}}
        for token_id, entry in sorted(_load_api_tokens().items())
    ]


def revoke_api_token(token_id: str) -> str | None:
    tokens = _load_api_tokens()
    if token_id not in tokens:
        return f"no such token {token_id!r}"
    del tokens[token_id]
    _save_api_tokens(tokens)
    return None


def has_totp(owner: str) -> bool:
    return owner in _load_totp()


def totp_added_at(owner: str) -> str | None:
    entry = _load_totp().get(owner)
    return entry["added_at"] if entry else None


def _totp_qr_svg(owner: str, secret: str) -> str:
    uri = pyotp.TOTP(secret).provisioning_uri(name=owner, issuer_name=TOTP_ISSUER)
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode()


def totp_generate_setup(owner: str) -> tuple[str, str]:
    """Returns (secret, qr_svg). NOT persisted -- the caller stashes
    `secret` in the session until totp_confirm_and_enable verifies it,
    same "never write an unconfirmed secret to disk" reasoning as the
    operator admin UI's identical vhsp_ctl/totp.py."""
    secret = pyotp.random_base32()
    return secret, _totp_qr_svg(owner, secret)


def totp_qr_svg_for_secret(owner: str, secret: str) -> str:
    """Re-renders the QR for an already-generated, still-pending secret
    -- used to redisplay the setup page after a failed confirm attempt
    without silently invalidating whatever the user already scanned."""
    return _totp_qr_svg(owner, secret)


def totp_confirm_and_enable(owner: str, secret: str, code: str, added_at: str) -> bool:
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        return False
    entries = _load_totp()
    entries[owner] = {"secret": secret, "added_at": added_at}
    _save_totp(entries)
    return True


def totp_verify(owner: str, code: str) -> bool:
    """valid_window=1 tolerates +/-30s of clock drift, at the cost of not
    defending against a code being replayed within that window (no
    last-used-step tracking) -- same accepted-gap reasoning as this
    file's own WebAuthn code not tracking signature counters."""
    entry = _load_totp().get(owner)
    if not entry:
        return False
    return pyotp.TOTP(entry["secret"]).verify(code, valid_window=1)


def totp_remove(owner: str) -> None:
    entries = _load_totp()
    entries.pop(owner, None)
    _save_totp(entries)

# Persisted rather than regenerated on every process start (a container
# recreate, which this control plane does routinely to pick up image
# updates) -- otherwise every recreate would silently invalidate every
# logged-in session, same reasoning as vhsp_ctl/auth.py's
# ensure_secret_key for the operator admin UI. Flask *signs* (doesn't
# encrypt) session cookies with this, so anyone able to read this file
# can forge an arbitrary session -- a full login+2FA bypass, not just
# information disclosure. Same chmod+chown treatment as the other four
# sensitive files this container writes (webauthn/totp/tenant_users/
# login_attempts -- see _chown_to_host's own docstring); this one was
# missing both until a follow-up security review caught it.
if not SECRET_KEY_FILE.exists():
    SECRET_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    SECRET_KEY_FILE.write_text(secrets.token_hex(32))
    os.chmod(SECRET_KEY_FILE, stat.S_IRUSR | stat.S_IWUSR)
    _chown_to_host(SECRET_KEY_FILE)
app.secret_key = SECRET_KEY_FILE.read_text()


def csrf_token() -> str:
    """Same shape as vhsp_ctl/web.py's identical helper, independently
    implemented per this file's usual trust-boundary duplication -- one
    unpredictable per-session token, generated on first access and reused
    for the session's lifetime."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


# Authenticated by a single-use grant token in the body rather than by
# an existing session, so there's no ambient authority for a forged
# cross-site POST to borrow -- see operator_access_consume's docstring.
_CSRF_EXEMPT = {"operator_access_consume"}


@app.before_request
def _enforce_csrf():
    """Applies platform-wide to every state-changing request, before any
    view function runs -- see vhsp_ctl/web.py's identical hook for the
    full reasoning (real forms get the token via a small injector script
    in LAYOUT/AUTH_PAGE, the WebAuthn JS fetch() calls set it as a header
    instead)."""
    if request.endpoint in _CSRF_EXEMPT:
        return
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        expected = session.get("csrf_token")
        submitted = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not expected or not submitted or not hmac.compare_digest(expected, submitted):
            abort(403, description="csrf")


@app.before_request
def _expire_operator_session():
    """Ends an operator session the moment its grant stops being active --
    revoked, or simply run out of time.

    Enforced per-request against the grant file rather than trusting an
    expiry copied into the session cookie: the cookie is held by the
    operator, and the whole point of the tenant-visible banner is that
    what the tenant sees and what the operator can do are driven by the
    same piece of state. A session that outlived its banner would make
    the banner a lie.
    """
    username = session.get("username", "")
    if not username.startswith(OPERATOR_ACTOR_PREFIX):
        return
    if operator_session_is_valid(username):
        return
    audit_log("operator_access.session_ended", actor=username, ip=request.remote_addr,
              detail={"reason": "grant expired, revoked, or issued to a different operator"})
    session.clear()
    return redirect(url_for("login"))


# Logged explicitly by their own handlers with a real outcome (which
# password was right, which factor verified), so the generic hook skips
# them to avoid a duplicate, less informative entry for the same action.
_AUDIT_SELF_LOGGED = {
    "login", "login_2fa", "logout", "webauthn_authenticate_complete",
    # Writes its own operator_access.session_started / .denied entries
    # with the real outcome; the generic hook would add a second, vaguer
    # row for the same event.
    "operator_access_consume",
}


@app.after_request
def _audit_request(response):
    """One entry per state-changing request, whatever the outcome.

    after_request, not before_request: the status code is the cheapest
    honest record of whether the action actually took effect, and it's
    only known afterwards. Failures are logged too -- a rejected CSRF, a
    403 from a role check, or a 500 are all things somebody investigating
    an incident needs to see, and a log that only records successes hides
    exactly the attempts worth noticing.
    """
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return response
    if request.endpoint in _AUDIT_SELF_LOGGED:
        return response
    audit_log(
        f"panel.{request.endpoint or request.path}",
        detail=_audit_safe_form() or None,
        ip=request.remote_addr,
        status=response.status_code,
    )
    return response


# Endpoints still reachable while a forced password change is pending.
# Deliberately tiny: the change page itself, logging out, and static
# assets (without which that page renders unstyled).
_PASSWORD_CHANGE_EXEMPT = {"password_change_required", "logout", "static"}


@app.before_request
def _require_password_change():
    """Funnels a fully-authenticated user whose password was set by
    somebody else straight to the change page, and lets them reach
    nothing else until it's done.

    A before_request hook rather than a check bolted onto each login
    exit: there are three ways session['username'] gets set (plain
    login, TOTP via login_2fa, WebAuthn via its own complete endpoint),
    and any check placed on those paths would still leave every route
    reachable by direct URL afterwards. Gating on the session itself
    means the flag holds for the whole session, however it began, and
    however the user navigates.
    """
    if not session.get("username"):
        return None  # anonymous -- login flow handles it, nothing to force yet
    if request.endpoint in _PASSWORD_CHANGE_EXEMPT:
        return None
    if not must_change_password(session["username"]):
        return None
    return redirect(url_for("password_change_required"))


class AuthError(Exception):
    pass


def _migrate_legacy_single_admin() -> None:
    """One-time upgrade path, same idiom as vhsp_ctl/auth.py's own
    migration: the pre-multi-user single credential (username always
    "admin") becomes the first entry in tenant_users.json, so an
    already-provisioned tenant keeps working unchanged the next time this
    container restarts -- no manual per-tenant step. Owner, since it's the
    same undifferentiated full access that single credential already had."""
    if TENANT_USERS_FILE.exists() or not ADMIN_CREDENTIALS_FILE.exists():
        return
    legacy = json.loads(ADMIN_CREDENTIALS_FILE.read_text())
    _save_users({
        legacy["username"]: {
            "password_hash": legacy["password_hash"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "role": "owner",
        }
    })


ROLES = ("owner", "member")


def _load_users() -> dict:
    """Entries from before RBAC have no "role" field -- treated as
    "owner" (the same undifferentiated full access they already had) and
    rewritten with that role set, same lazy-migration pattern
    _load_webauthn_credentials uses for its own "owner" field."""
    _migrate_legacy_single_admin()
    if not TENANT_USERS_FILE.exists():
        return {}
    users = json.loads(TENANT_USERS_FILE.read_text())
    migrated = False
    for entry in users.values():
        if "role" not in entry:
            entry["role"] = "owner"
            migrated = True
    if migrated:
        _save_users(users)
    return users


def _save_users(users: dict) -> None:
    TENANT_USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    TENANT_USERS_FILE.write_text(json.dumps(users))
    os.chmod(TENANT_USERS_FILE, stat.S_IRUSR | stat.S_IWUSR)
    _chown_to_host(TENANT_USERS_FILE)


def list_users() -> list[dict]:
    """Metadata only (username, created_at, role) -- safe to render,
    never includes password hashes."""
    return [
        {"username": username, "created_at": entry["created_at"], "role": entry["role"]}
        for username, entry in sorted(_load_users().items())
    ]


def user_exists(username: str) -> bool:
    return username in _load_users()


def user_role(username: str) -> str | None:
    """Operator sessions have no tenant_users.json entry by design -- an
    operator must never become a persistent login on a tenant's panel.
    They're treated as owner for the life of the grant so support work
    isn't blocked by role checks, but that authority comes from the
    grant file, which expires; there is nothing to clean up afterwards
    and nothing for the tenant to discover later in their Team page."""
    if username.startswith(OPERATOR_ACTOR_PREFIX):
        return "owner" if operator_session_is_valid(username) else None
    entry = _load_users().get(username)
    return entry["role"] if entry else None


def operator_session_is_valid(username: str) -> bool:
    """An operator session is valid only while a grant is active AND
    names that same operator.

    The name check is not redundant with the active check: without it,
    any session claiming `operator:<anyone>` would inherit owner rights
    from a grant issued to somebody else entirely -- including a grant
    that was replaced mid-session by one for a different operator. It
    also means a stale cookie from a previous operator's window stops
    working the moment a new grant supersedes it, rather than riding
    along on it.
    """
    state = operator_access_state()
    if not state.get("active"):
        return False
    return username == f"{OPERATOR_ACTOR_PREFIX}{state.get('operator')}"


def create_user(username: str, role: str = "member") -> str:
    """Generates+stores a random password for a brand-new team member.
    Returns the plaintext -- the only time it's ever available, shown
    once by the caller. Defaults to "member", not "owner" -- adding
    someone to the team shouldn't silently hand them owner-only reach
    (team management, backup destination/restore, the SQL console)
    unless that's asked for explicitly."""
    if role not in ROLES:
        raise AuthError(f"invalid role {role!r}")
    users = _load_users()
    if username in users:
        raise AuthError(f"user {username!r} already exists")
    password = secrets.token_urlsafe(18)
    users[username] = {
        "password_hash": generate_password_hash(password),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "role": role,
        # The owner who created this account reads the password off the
        # screen to pass it on, so it's somebody else's choice until the
        # new member replaces it -- same must-change rule as every other
        # "one person set another person's password" path here.
        "must_change_password": True,
    }
    _save_users(users)
    return password


def set_user_role(username: str, role: str) -> None:
    """Guards against ending up with zero owners -- that's a harder lockout
    than zero users at all (see remove_user's own identical concern):
    every owner-only surface (team management itself, backup destination/
    restore, the SQL console) becomes unreachable from inside this panel,
    recoverable only through the operator's coarse tools."""
    if role not in ROLES:
        raise AuthError(f"invalid role {role!r}")
    users = _load_users()
    if username not in users:
        raise AuthError(f"no such user {username!r}")
    if users[username]["role"] == "owner" and role != "owner":
        if sum(1 for u in users.values() if u["role"] == "owner") <= 1:
            raise AuthError("cannot demote the last owner")
    users[username]["role"] = role
    _save_users(users)


"""Audit log ------------------------------------------------------------

Records every state-changing action taken in this panel. Coverage comes
from a single after_request hook (see _audit_request) rather than a
log_action() call bolted onto each of the ~27 state-changing routes:
per-route instrumentation silently misses whatever route somebody adds
next, which is the one failure mode an audit log cannot have. Auth
outcomes are additionally logged explicitly, because a generic hook can
see that POST /login happened but not whether the password was right.
"""

# Redacted wholesale, never truncated-and-logged. Passwords and TOTP
# codes are credentials; `sql` and `content` are tenant DATA (a query's
# text or a file's body) which must not be copied into a log the host
# can read; own_age_private_key is the tenant's backup encryption key.
_AUDIT_REDACT_FIELDS = frozenset({
    "password", "new_password", "current_password", "confirm_password",
    "code", "sql", "content", "own_age_private_key",
    # Operator-access grant token. Caught in real testing: the generic
    # hook logged it verbatim, putting a live credential into a log that
    # is then mirrored to the operator log AND shipped off-host. Kept in
    # this set even though operator_access_consume is now self-logged
    # (below) and no longer reaches the generic hook -- defence in depth,
    # so any future form carrying a field named `token` is safe by
    # default rather than by someone remembering.
    "token",
})
# Dropped entirely rather than redacted: csrf_token is on every single
# form post, so keeping a "<redacted>" placeholder for it would put a
# line of pure noise in the details column of every row in the log.
_AUDIT_DROP_FIELDS = frozenset({"csrf_token"})

# Backstop under the explicit list above: any field whose NAME contains
# one of these is redacted even if nobody remembered to list it. The
# explicit set stays as the primary mechanism (it documents intent and
# doesn't depend on someone naming a field well) -- this only catches
# what that set misses.
#
# Added because the grant-token leak was exactly this failure: the field
# was called `token`, the redact set didn't have it, and the value went
# into a log that is mirrored to the operator and shipped off-host. A
# name check would have caught it with nobody having to think about it.
# Substring match. These have no realistic false positive in a field
# name -- nothing benign contains "password" or "credential" by accident.
_AUDIT_REDACT_NAME_PARTS = ("token", "password", "passwd", "secret", "credential")

# Whole-word match only. "key" is too short for substring matching --
# it would redact `keyword` and `monkey`. Matched against the field
# name split on separators AND camelCase, so `api_key`, `private-key`
# and `apiKey` all hit while `keyword` doesn't.
_AUDIT_REDACT_NAME_WORDS = frozenset({"key", "keys", "privatekey", "seed"})
_AUDIT_NAME_WORD_RE = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")

# Exact field names that match a pattern above but are deliberately NOT
# secrets, and whose value is the whole point of the audit entry.
# `token_id` identifies WHICH API token was revoked -- redacting it would
# turn "revoked token abc123" into "revoked a token", losing exactly the
# detail an incident reviewer needs. Exact names only, never substrings:
# a future `api_token_id` gets redacted by default rather than silently
# inheriting this exemption.
_AUDIT_NAME_PATTERN_EXEMPT = frozenset({"token_id"})
_AUDIT_VALUE_MAXLEN = 200


def _audit_field_is_secret(field_name: str) -> bool:
    if field_name in _AUDIT_REDACT_FIELDS:
        return True
    if field_name in _AUDIT_NAME_PATTERN_EXEMPT:
        return False
    lowered = field_name.lower()
    if any(part in lowered for part in _AUDIT_REDACT_NAME_PARTS):
        return True
    words = {w.lower() for w in _AUDIT_NAME_WORD_RE.findall(field_name)}
    return bool(words & _AUDIT_REDACT_NAME_WORDS)


def _audit_safe_form() -> dict:
    """The submitted form, with credential/data fields replaced by a
    marker and everything else length-capped.

    Denylist rather than allowlist so a newly added benign field still
    shows up in the trail -- but with a name-pattern backstop under it
    (_audit_field_is_secret), so "sensitive but nobody listed it" fails
    closed instead of open. That combination is deliberate: an allowlist
    would silently drop useful detail every time a form gains a field,
    while a bare denylist silently leaks every time one gains a secret,
    and only the second failure is unrecoverable once the log has been
    mirrored and shipped off-host."""
    out = {}
    for key, value in request.form.items():
        if key in _AUDIT_DROP_FIELDS:
            continue
        if _audit_field_is_secret(key):
            # No length. An earlier version recorded "<redacted:N chars>",
            # which for a token is harmless (fixed, publicly-known length)
            # but for a password hands whoever reads this log -- the
            # operator, and whoever holds the off-host shipped copy -- the
            # exact length of a tenant user's password. That narrows a
            # guess for free and buys nothing operationally: "was the
            # field filled in at all" is the only thing anyone needs from
            # a redacted value, and <empty> already answers it.
            out[key] = "<redacted>" if value else "<empty>"
        elif len(value) > _AUDIT_VALUE_MAXLEN:
            out[key] = value[:_AUDIT_VALUE_MAXLEN] + f"...<truncated:{len(value)} chars>"
        else:
            out[key] = value
    return out


def operator_access_state() -> dict:
    """Current grant state, re-read from disk every call. {'active': bool,
    'operator': str, 'expires_at': str}.

    Deliberately not cached and not held in the session: the banner this
    drives has to disappear the moment the grant is revoked or expires,
    including for a tenant sitting on the page, and has to appear for the
    TENANT's session even though the grant was created for somebody
    else's."""
    if not OPERATOR_ACCESS_FILE.exists():
        return {"active": False}
    try:
        data = json.loads(OPERATOR_ACCESS_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {"active": False}
    if data.get("revoked_at"):
        return {"active": False, **data}
    try:
        expired = datetime.fromisoformat(data["expires_at"]) <= datetime.now(timezone.utc)
    except (KeyError, ValueError, TypeError):
        expired = True
    return {**data, "active": not expired}


def _audit_raw_lines() -> list[bytes]:
    if not AUDIT_LOG_FILE.exists():
        return []
    return [line for line in AUDIT_LOG_FILE.read_bytes().split(b"\n") if line]


def _audit_last_hash(lines: list[bytes] | None = None) -> str:
    lines = _audit_raw_lines() if lines is None else lines
    return hashlib.sha256(lines[-1]).hexdigest() if lines else ""


def audit_log(action: str, detail: dict | None = None, actor: str | None = None,
              ip: str | None = None, status: int | None = None) -> None:
    """Appends one entry. Never raises: an audit write failing must not
    turn a working action into a 500 for the tenant -- the action already
    happened by the time the after_request hook runs, so aborting here
    would report failure for work that succeeded. Failures go to stderr
    (visible in `docker logs`) instead of vanishing."""
    try:
        AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        resolved_actor = actor if actor is not None else (session.get("username") or "-")
        # flock around the whole read-hash-append. The host writes this
        # same bind-mounted file too (vhsp_ctl.provisioner's
        # append_tenant_audit, for operator-access grants), and without
        # the lock two concurrent appends would each hash the same
        # "last" line -- producing a chain break that reads as tampering
        # when it was only a race. Same lock, same inode, both sides.
        with open(AUDIT_LOG_FILE, "a+") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.seek(0)
                lines = [line for line in f.read().encode().split(b"\n") if line]
                entry = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "action": action,
                    "actor": resolved_actor,
                    "prev_hash": hashlib.sha256(lines[-1]).hexdigest() if lines else "",
                }
                if ip is not None:
                    entry["ip"] = ip
                if status is not None:
                    entry["status"] = status
                if detail:
                    entry["detail"] = detail
                if len(lines) + 1 > AUDIT_MAX_ENTRIES:
                    kept = lines[-(AUDIT_MAX_ENTRIES - 1):] if AUDIT_MAX_ENTRIES > 1 else []
                    f.truncate(0)
                    f.seek(0)
                    f.write("".join(l.decode() + "\n" for l in kept))
                    entry["prev_hash"] = (
                        hashlib.sha256(kept[-1]).hexdigest() if kept else ""
                    )
                f.seek(0, os.SEEK_END)
                f.write(json.dumps(entry) + "\n")
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        os.chmod(AUDIT_LOG_FILE, stat.S_IRUSR | stat.S_IWUSR)
        _chown_to_host(AUDIT_LOG_FILE)
    except Exception as e:  # noqa: BLE001 -- see docstring
        print(f"WARNING: audit log write failed ({action}): {e!r}", file=sys.stderr)


def audit_entries(limit: int = 200, action_filter: str = "", actor_filter: str = "") -> list[dict]:
    """Newest first. Malformed lines are skipped rather than raising --
    a corrupted line shouldn't make the whole page unviewable, and
    audit_verify() is what actually reports integrity."""
    out = []
    for raw in _audit_raw_lines():
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if action_filter and action_filter not in entry.get("action", ""):
            continue
        if actor_filter and actor_filter not in entry.get("actor", ""):
            continue
        out.append(entry)
    out.reverse()
    return out[:limit]


def audit_verify() -> tuple[bool, int]:
    """(chain_intact, entries_checked) -- or (False, index_of_first_break).
    Same walk as the operator's vhsp_ctl.audit.verify_chain, including
    never checking the first retained entry against anything."""
    lines = _audit_raw_lines()
    prev_hash = None
    for i, raw in enumerate(lines):
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            return False, i
        if "prev_hash" not in entry:
            prev_hash = None
            continue
        if prev_hash is not None and entry["prev_hash"] != prev_hash:
            return False, i
        prev_hash = hashlib.sha256(raw).hexdigest()
    return True, len(lines)


def check_login(username: str, password: str) -> bool:
    users = _load_users()
    entry = users.get(username)
    return entry is not None and check_password_hash(entry["password_hash"], password)


def set_user_password(username: str, password: str, must_change: bool = False) -> None:
    """Used both by a user's own "change my password" (any role, via
    /security-key) and by an owner resetting a colleague's (lockout
    recovery, via /team, which the route handler already restricts to
    owners) -- this function itself doesn't care which, the route calling
    it does.

    Clears must_change_password unless the caller explicitly re-sets it:
    every path through here is somebody deliberately choosing a new
    password, which is exactly the condition the flag exists to force.
    An owner resetting a colleague passes must_change=True for the same
    reason the operator's own reset does -- the person who typed it
    shouldn't keep knowing it.
    """
    users = _load_users()
    if username not in users:
        raise AuthError(f"no such user {username!r}")
    users[username]["password_hash"] = generate_password_hash(password)
    if must_change:
        users[username]["must_change_password"] = True
    else:
        users[username].pop("must_change_password", None)
    _save_users(users)


def must_change_password(username: str) -> bool:
    """Whether this login is holding a password somebody else chose for
    it (the operator's reset, or an owner resetting a team member) and
    hasn't replaced yet. Absent key == False, so every pre-existing
    tenant_users.json entry reads as "no change needed" without a
    migration."""
    entry = _load_users().get(username)
    return bool(entry and entry.get("must_change_password"))


def remove_user(username: str) -> None:
    """Refuses to remove the last remaining user -- there is no
    recovery path back into this panel once every team-member account is
    gone except through the operator's own coarse tools (reset the
    original admin account, clear all WebAuthn keys). Enforced here, not
    just in the route handler, so the guarantee can't be bypassed.

    Also refuses to remove the last remaining owner, even when other
    (member-role) users would still be left -- same reasoning as
    set_user_role's identical guard: a team of members-only can't manage
    its own team, change backup destinations, restore a backup, or use
    the SQL console, and has no way back into any of that short of the
    operator's own tools."""
    users = _load_users()
    if username not in users:
        raise AuthError(f"no such user {username!r}")
    if len(users) <= 1:
        raise AuthError("cannot remove the last remaining user")
    if users[username]["role"] == "owner" and sum(1 for u in users.values() if u["role"] == "owner") <= 1:
        raise AuthError("cannot remove the last owner")
    del users[username]
    _save_users(users)


def require_login(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def require_role(role: str):
    """Stronger than require_login, not a stack-with-it companion: still
    redirects an anonymous visitor to /login (same as require_login), but
    also 403s a logged-in user whose role doesn't match, rather than
    silently letting the page render for a member and just hiding a
    button -- team management, backup destination/restore, and the SQL
    console are the owner-only surfaces (see each route's own comment
    for why that specific one is gated)."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("username"):
                return redirect(url_for("login", next=request.path))
            if user_role(session["username"]) != role:
                abort(403, description="not_owner")
            return view(*args, **kwargs)
        return wrapped
    return decorator


def _has_2fa(username: str) -> bool:
    # An operator session counts as second-factored. It has no enrolment
    # in THIS tenant's stores and must never acquire one (that would be a
    # persistent credential on someone else's panel) -- but the grant
    # behind it can only be issued from the operator admin UI's own
    # @require_2fa route, so a second factor was already checked, just on
    # the other side of the boundary. Without this the operator lands in
    # the panel with owner rights and is then 403'd out of every page
    # worth having access for: files, database, backups, redirects.
    if username.startswith(OPERATOR_ACTOR_PREFIX):
        return operator_session_is_valid(username)
    return _has_credentials(username) or has_totp(username)


def _login_throttle_load() -> dict:
    if not LOGIN_ATTEMPTS_FILE.exists():
        return {}
    return json.loads(LOGIN_ATTEMPTS_FILE.read_text())


def _login_throttle_save(entries: dict) -> None:
    LOGIN_ATTEMPTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOGIN_ATTEMPTS_FILE.write_text(json.dumps(entries))
    os.chmod(LOGIN_ATTEMPTS_FILE, stat.S_IRUSR | stat.S_IWUSR)
    _chown_to_host(LOGIN_ATTEMPTS_FILE)


def _login_is_locked(username: str) -> bool:
    entry = _login_throttle_load().get(username)
    if not entry:
        return False
    locked_until = entry.get("locked_until")
    return bool(locked_until and time.time() < locked_until)


def _fail2ban_ip_allowlisted(ip: str) -> bool:
    """Checked before ever writing to LOGIN_ATTEMPTS_LOG_FILE -- an
    allowlisted IP's failures still lock the account out locally
    (LOGIN_ATTEMPTS_FILE's own throttle above is unaffected, still
    applies to everyone), they just never get reported to fail2ban.
    Real CIDR containment (ipaddress module), not string matching --
    same reasoning as deploy/vhsp-fail2ban-allowlist-check's own use of
    Python for this rather than hand-rolled bash arithmetic."""
    if not FAIL2BAN_ALLOWLIST_FILE.exists():
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for line in FAIL2BAN_ALLOWLIST_FILE.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            if addr in ipaddress.ip_network(line, strict=False):
                return True
        except ValueError:
            continue
    return False


def _login_record_failure(username: str) -> None:
    entries = _login_throttle_load()
    now = time.time()
    entry = entries.get(username, {"count": 0, "first_failure": now})
    if now - entry.get("first_failure", now) > LOGIN_WINDOW_SECONDS:
        entry = {"count": 0, "first_failure": now}
    entry["count"] += 1
    if entry["count"] >= LOGIN_MAX_FAILURES:
        entry["locked_until"] = now + LOGIN_LOCKOUT_SECONDS
    entries[username] = entry
    _login_throttle_save(entries)

    ip = request.remote_addr
    if ip and not _fail2ban_ip_allowlisted(ip):
        LOGIN_ATTEMPTS_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(LOGIN_ATTEMPTS_LOG_FILE, "a") as f:
            f.write(json.dumps({
                "ts": datetime.now(timezone.utc).isoformat(),
                "domain": TENANT_DOMAIN,
                "username": username,
                "ip": ip,
            }) + "\n")
        os.chmod(LOGIN_ATTEMPTS_LOG_FILE, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)


def _login_record_success(username: str) -> None:
    entries = _login_throttle_load()
    if username in entries:
        del entries[username]
        _login_throttle_save(entries)


def require_2fa(view):
    """Stacks with require_login/require_role rather than replacing
    either -- see e.g. /database's or /files' own decorators. Deliberate
    product choice, not a generic security floor applied everywhere: a
    carrot for turning a second factor on at all (TOTP being free and a
    couple minutes of setup, see this file's own module docstring),
    applied to the surfaces with real blast radius if a no-2FA account
    gets compromised -- the file manager and SQL console (full site/DB
    takeover), the config knobs that change what the live site serves or
    how it's reached (PHP functions, redirects, no-exec dirs, IP
    restrictions) or where backups go/what gets restored, and mailbox
    management (a follow-up security review reclassified this one: email
    is the recovery path into most of what a tenant owns *outside* this
    platform too -- registrar, billing, other SaaS accounts -- so a
    compromised no-2FA account resetting postmaster@'s password or
    adding a mailbox to intercept mail is a bigger prize than it first
    looks, not a "routine" page). Genuinely low-impact pages (404
    handling, error pages, password protection, logs) stay ungated. No
    exception for an owner who simply hasn't gotten around to it yet;
    the 403 page (see forbidden() below) says exactly what to do about
    it and links straight to the Security key page."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login", next=request.path))
        if not _has_2fa(session["username"]):
            abort(403, description="no_2fa")
        return view(*args, **kwargs)
    return wrapped


# `prefers-color-scheme` rather than a manual toggle -- "dark mode aware"
# means follow the browser/OS setting, not a stateful preference to build
# UI for. Verbatim-duplicated (not shared/imported) from vhsp_ctl/web.py's
# own identical constant -- separate trust boundary/container, same
# reasoning as every other cross-app duplication in this codebase; kept
# byte-for-byte identical so light/dark look the same on both admin UIs.
# Defined here, before every template that references it via string
# concatenation -- those concatenations run at module-import time (plain
# top-level statements, not inside a function), unlike this project's
# route handlers which only run when actually called, so definition
# order genuinely matters here (verified: got NameError on the first
# deploy attempt from getting this backwards).
# Verbatim copy of vhsp_ctl/web.py's own BASE_CSS -- separate trust
# boundary/container, same "duplicated, not imported" reasoning as
# DARK_AWARE_CSS always had here, just covering the fuller design system
# now. Keep the two in sync by hand if either changes.
DARK_AWARE_CSS = """
:root {
  /* See vhsp_ctl/web.py's identical comment -- without this, Chromium/
     Firefox fall back to light-mode native rendering for residual
     form-control chrome even under appearance:none (observed on the
     lone "Log out" button, the only submit control in its own bare
     <form>). `light dark` tracks the same prefers-color-scheme media
     query already driving every custom property below. */
  color-scheme: light dark;
  --bg: #f6f7f9; --surface: #fff; --surface-2: #fafbfc;
  --fg: #1a1d23; --muted: #6b7280; --border: #e5e7eb;
  --link: #4f46e5; --link-hover: #4338ca;
  --accent: #4f46e5; --accent-fg: #fff; --accent-hover: #4338ca;
  --danger: #dc2626; --danger-fg: #fff; --danger-hover: #b91c1c;
  --danger-bg: #fef2f2; --danger-border: #fecaca; --danger-text: #991b1b;
  --ok-bg: #f0fdf4; --ok-border: #bbf7d0; --ok-text: #166534;
  --warn-bg: #fffbeb; --warn-border: #fde68a; --warn-text: #92400e;
  --code-bg: #f1f2f5; --code-border: #e5e7eb;
  --input-bg: #fff; --input-border: #d1d5db; --input-focus: #4f46e5;
  --row-hover: #f9fafb; --thead-bg: #fafbfc;
  --shadow: 0 1px 2px rgba(16,24,40,.04), 0 1px 3px rgba(16,24,40,.06);
  --radius: 10px; --radius-sm: 6px;
  --quota-track: #eef0f3; --quota-ok: #22c55e; --quota-warn: #eab308; --quota-danger: #ef4444;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #101114; --surface: #17181c; --surface-2: #1c1e23;
    --fg: #e8e9ec; --muted: #9199a8; --border: #2a2d34;
    --link: #a5b4fc; --link-hover: #c7d2fe;
    --accent: #6366f1; --accent-fg: #fff; --accent-hover: #7c7ff2;
    --danger: #f87171; --danger-fg: #1a1114; --danger-hover: #fca5a5;
    --danger-bg: #2a1618; --danger-border: #4c2226; --danger-text: #fca5a5;
    --ok-bg: #12241a; --ok-border: #1f3d2a; --ok-text: #86efac;
    --warn-bg: #2a2113; --warn-border: #4a3820; --warn-text: #fcd34d;
    --code-bg: #1e2025; --code-border: #2a2d34;
    --input-bg: #1a1c21; --input-border: #33363e; --input-focus: #818cf8;
    --row-hover: #1c1e23; --thead-bg: #1a1c21;
    --shadow: 0 1px 2px rgba(0,0,0,.3), 0 2px 6px rgba(0,0,0,.25);
    --quota-track: #262930; --quota-ok: #22c55e; --quota-warn: #eab308; --quota-danger: #ef4444;
  }
}
"""

BASE_CSS = DARK_AWARE_CSS + """
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    margin: 0; background: var(--bg); color: var(--fg); line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }
  a { color: var(--link); text-decoration: none; }
  a:hover { color: var(--link-hover); text-decoration: underline; }
  h1, h2, h3 { font-weight: 650; letter-spacing: -0.01em; line-height: 1.25; }
  h2 { font-size: 1.3rem; margin: 0 0 0.9rem; }
  h3 { font-size: 1.05rem; margin: 1.6rem 0 0.6rem; }
  .shell { max-width: 1040px; margin: 0 auto; padding: 0 1.5rem 4rem; }

  .topbar { background: var(--surface); border-bottom: 1px solid var(--border); margin-bottom: 1.25rem; }
  .topbar-inner { max-width: 1040px; margin: 0 auto; padding: 1rem 1.5rem; }
  .brand-row { display: flex; align-items: center; justify-content: space-between; gap: 1rem; margin-bottom: 0.8rem; }
  .brand { font-weight: 700; font-size: 1.05rem; letter-spacing: -0.01em; color: var(--fg); }
  .quota-line { font-size: 0.82rem; color: var(--muted); margin: 0 0 0.35rem; }

  .subnav { display: flex; flex-wrap: wrap; gap: 0.35rem; }
  .subnav a {
    font-size: 0.85rem; font-weight: 500; color: var(--muted); padding: 0.4rem 0.75rem;
    border-radius: 999px; border: 1px solid var(--border); background: var(--surface);
  }
  .subnav a:hover { color: var(--fg); border-color: var(--muted); text-decoration: none; }
  .subnav a.active { color: var(--accent-fg); background: var(--accent); border-color: var(--accent); }

  .card {
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
    box-shadow: var(--shadow); padding: 1.5rem; margin: 0 0 1.5rem;
  }
  .card > h2:first-child, .card > h3:first-child { margin-top: 0; }

  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: 0.65rem 0.75rem; border-bottom: 1px solid var(--border); vertical-align: top; }
  thead th { background: var(--thead-bg); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); font-weight: 600; }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover { background: var(--row-hover); }
  .card table { margin: -1.5rem; width: calc(100% + 3rem); overflow-x: auto; }
  .card table th:first-child, .card table td:first-child { padding-left: 1.5rem; }
  .card table th:last-child, .card table td:last-child { padding-right: 1.5rem; }

  code, pre { background: var(--code-bg); border: 1px solid var(--code-border); border-radius: 4px; }
  code { padding: 0.1rem 0.4rem; font-size: 0.87em; }
  pre { padding: 0.9rem 1rem; overflow-x: auto; max-height: 400px; overflow-y: auto; font-size: 0.8rem; }

  form.inline { display: inline; }
  .muted { color: var(--muted); font-size: 0.9em; }
  .badge {
    display: inline-block; padding: 0.15rem 0.55rem; border-radius: 999px;
    font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.02em;
    white-space: nowrap;
  }
  .badge-ok { background: var(--ok-bg); color: var(--ok-text); border: 1px solid var(--ok-border); }
  .badge-warn { background: var(--warn-bg); color: var(--warn-text); border: 1px solid var(--warn-border); }
  .dns-row-ok td { background: var(--ok-bg); border-color: var(--ok-border); }
  /* QR codes stay black-on-white in BOTH themes. The SVG qrcode emits
     has a transparent background and a path with no fill attribute (so
     it renders black), which against the dark theme's surface is black
     on near-black -- invisible, and unscannable. The white is padded
     out past the code itself because scanners need that light quiet
     zone to find the symbol at all. Fill is pinned explicitly rather
     than left to the SVG default so a future global `svg { fill:
     currentColor }` rule can't silently break it again. */
  /* Deliberately the loudest thing on the page and not dismissible --
     a tenant must not be able to lose track of the fact that somebody
     else is currently inside their panel. */
  .operator-banner {
    background: var(--warn-bg); color: var(--warn-text);
    border: 2px solid var(--warn-border); border-radius: var(--radius);
    padding: 0.9rem 1.1rem; margin-bottom: 1.5rem; line-height: 1.5;
  }
  .operator-banner code { background: color-mix(in srgb, var(--warn-text) 12%, transparent); border-color: var(--warn-border); }
  .operator-banner a { color: inherit; text-decoration: underline; }
  .table-filter { display: flex; gap: 0.6rem; align-items: center; flex-wrap: wrap; margin-bottom: 0.9rem; }
  .table-filter input[type=search] { max-width: 240px; }
  .qr-code { background: #fff; padding: 0.75rem; border-radius: var(--radius-sm); }
  .qr-code svg { display: block; width: 100%; height: auto; }
  .qr-code svg path { fill: #000; }
  code.copyable { cursor: pointer; }
  code.copyable:hover { border-color: var(--accent); }
  code.copyable:focus-visible { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 30%, transparent); }
  code.copyable.copied { background: var(--ok-bg); border-color: var(--ok-border); color: var(--ok-text); }

  .flash, .warn {
    border-radius: var(--radius-sm); padding: 0.7rem 1rem; margin: 0 0 1.25rem;
    border: 1px solid var(--ok-border); border-left-width: 3px;
    background: var(--ok-bg); color: var(--ok-text); font-size: 0.9rem;
  }
  .flash.error { background: var(--danger-bg); border-color: var(--danger-border); color: var(--danger-text); }
  .warn { background: var(--warn-bg); border-color: var(--warn-border); color: var(--warn-text); }

  label { display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.3rem; }
  .sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }
  textarea, input[type=text], input[type=password], input[type=email], input[type=number], input[type=search], select {
    width: 100%; font-family: inherit; font-size: 0.92rem; background: var(--input-bg); color: var(--fg);
    border: 1px solid var(--input-border); border-radius: var(--radius-sm); padding: 0.5rem 0.65rem;
    transition: border-color .12s ease, box-shadow .12s ease;
  }
  textarea:focus, input:focus, select:focus {
    outline: none; border-color: var(--input-focus); box-shadow: 0 0 0 3px color-mix(in srgb, var(--input-focus) 22%, transparent);
  }
  textarea { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.85rem; }
  input::placeholder, textarea::placeholder { color: var(--muted); opacity: 0.7; }
  input:-webkit-autofill, input:-webkit-autofill:hover, input:-webkit-autofill:focus {
    -webkit-text-fill-color: var(--fg); -webkit-box-shadow: 0 0 0 1000px var(--input-bg) inset; caret-color: var(--fg);
    transition: background-color 5000s ease-in-out 0s;
  }

  button {
    appearance: none; -webkit-appearance: none;
    background: var(--accent); color: var(--accent-fg); border: 1px solid transparent;
    border-radius: var(--radius-sm); padding: 0.5rem 0.9rem; font-size: 0.88rem; font-weight: 600;
    cursor: pointer; transition: background-color .12s ease, box-shadow .12s ease;
  }
  button:hover { background: var(--accent-hover); }
  button:focus-visible { outline: none; box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 30%, transparent); }
  button.danger { background: transparent; color: var(--danger); border-color: var(--danger-border); }
  button.danger:hover { background: var(--danger-bg); }
  button.btn-ghost { background: var(--surface); color: var(--fg); border-color: var(--border); }
  button.btn-ghost:hover { background: var(--surface-2); }
  .danger { color: var(--danger); }

  .quota-bar { background: var(--quota-track); border-radius: 999px; height: 0.5rem; overflow: hidden; margin: 0.35rem 0; max-width: 320px; }
  .quota-bar-fill { height: 100%; border-radius: 999px; }
  .quota-bar-fill.ok { background: var(--quota-ok); }
  .quota-bar-fill.warn { background: var(--quota-warn); }
  .quota-bar-fill.danger { background: var(--quota-danger); }

  .field { margin-bottom: 1rem; }
  .field:last-child { margin-bottom: 0; }
  .actions { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }

  .docs { max-width: 720px; }
  .docs h3 { scroll-margin-top: 1.25rem; padding-top: 1.75rem; border-top: 1px solid var(--border); }
  .docs h3:first-of-type { padding-top: 0; border-top: none; }
  .docs h4 { scroll-margin-top: 1.25rem; }
  .docs p, .docs li { color: var(--fg); }
  .docs .toc { columns: 2; column-gap: 2rem; }
  .docs .toc li { break-inside: avoid; margin-bottom: 0.3rem; font-size: 0.9rem; }
  .docs .eyebrow { text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.75rem; font-weight: 700; color: var(--muted); margin: 0 0 0.25rem; }
"""

# Shared shell for the two pre-session pages (login, WebAuthn challenge) --
# same brand/card language as LAYOUT but centered and narrow, since there's
# no nav/session to show yet.
AUTH_PAGE = """
<!doctype html><meta name="viewport" content="width=device-width, initial-scale=1"><title>{{ domain }} -- {{ heading }}</title>
<style>""" + BASE_CSS + """
  body { display: flex; align-items: center; justify-content: center; min-height: 100vh; }
  .auth-card { width: 100%; max-width: 340px; padding: 0 1.5rem; }
  .auth-brand { text-align: center; font-weight: 700; font-size: 1.15rem; margin-bottom: 1.5rem; letter-spacing: -0.01em; }
</style>
<div class="auth-card">
  <div class="auth-brand">{{ domain }}</div>
  <div class="card">
    <h2>{{ heading }}</h2>
    {% if error %}<div class="flash error">{{ error }}</div>{% endif %}
    {{ body|safe }}
  </div>
</div>
<script>
  document.querySelectorAll('form').forEach(function (f) {
    var isGet = f.method.toLowerCase() === 'get';
    if (!isGet) {
      var i = document.createElement('input');
      i.type = 'hidden'; i.name = 'csrf_token'; i.value = '{{ csrf_token() }}';
      f.appendChild(i);
    }
    f.addEventListener('submit', function (e) {
      if (e.defaultPrevented || isGet) return;
      var btn = e.submitter;
      if (btn && btn.tagName === 'BUTTON' && !btn.disabled) {
        btn.disabled = true;
        btn.textContent = 'Working…';
      }
    });
  });
</script>
"""

LOGIN_PAGE_BODY = """
<form method="post" autocomplete="off">
  <div class="field"><label>Username</label><input name="username" placeholder="username" autocomplete="username" required></div>
  <div class="field"><label>Password</label><input type="password" name="password" placeholder="password" autocomplete="current-password" required></div>
  <button type="submit" style="width:100%">Log in</button>
</form>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if _login_is_locked(username):
            audit_log("panel.login_locked", actor=username or "-", ip=request.remote_addr)
            error = "Too many failed attempts for this account. Try again in a few minutes."
        elif check_login(username, password):
            _login_record_success(username)
            if _has_credentials(username) or has_totp(username):
                # Ported from the operator admin UI's own login() --
                # verified working there first. Password alone doesn't
                # complete login when a second factor is registered:
                # stash the username as *pending* and hand off to the
                # 2FA challenge page, the only thing that can still set
                # session['username'] from here. Whichever of WebAuthn/
                # TOTP (or both) this user has registered, that page
                # offers.
                session["pending_username"] = username
                audit_log("panel.login_password_ok_2fa_pending",
                          actor=username, ip=request.remote_addr)
                return redirect(url_for("login_2fa", next=request.args.get("next")))
            session["username"] = username
            audit_log("panel.login", actor=username, ip=request.remote_addr)
            return redirect(request.args.get("next") or url_for("index"))
        else:
            _login_record_failure(username)
            # Records the attempted username, never the password. Same
            # field shape as the operator log's admin.login_failed, which
            # deploy/fail2ban watches -- a tenant-side jail could key off
            # this the same way.
            audit_log("panel.login_failed", actor=username or "-", ip=request.remote_addr)
            error = "Invalid username or password."
    return render_template_string(AUTH_PAGE, error=error, heading="Log in", body=LOGIN_PAGE_BODY, domain=TENANT_DOMAIN)


@app.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    pending = session.get("pending_username")
    if not pending:
        return redirect(url_for("login"))
    has_key = _has_credentials(pending)
    user_has_totp = has_totp(pending)
    error = None
    if request.method == "POST":
        if _login_is_locked(pending):
            error = "Too many failed attempts for this account. Try again in a few minutes."
        else:
            code = request.form.get("code", "").strip().replace(" ", "")
            if totp_verify(pending, code):
                _login_record_success(pending)
                session.pop("pending_username", None)
                session["username"] = pending
                audit_log("panel.login_2fa_totp", actor=pending, ip=request.remote_addr)
                return redirect(request.args.get("next") or url_for("index"))
            _login_record_failure(pending)
            audit_log("panel.login_2fa_failed", actor=pending, ip=request.remote_addr,
                      detail={"factor": "totp"})
            error = "That code didn't verify -- check the time on your phone/authenticator and try again."
    # Same as vhsp_ctl/web.py's identical login_2fa: this whole body is a
    # plain Python string, not a Jinja template (AUTH_PAGE only ever
    # substitutes it via {{ body|safe }}, a single-pass render), so the
    # fetch() calls below embed `token` as an f-string value rather than
    # `{{ csrf_token() }}`, which would be inert text here.
    token = csrf_token()
    body = ""
    if has_key:
        body += f"""
<p class="muted" style="margin-top:0">Insert/tap your security key.</p>
<div id="error" class="flash error" style="display:none"></div>
<button id="go" type="button" style="width:100%">Use security key</button>
<script>
  async function go() {{
    const errEl = document.getElementById('error');
    errEl.style.display = 'none';
    try {{
      const beginResp = await fetch('/webauthn/authenticate/begin', {{method: 'POST', headers: {{'X-CSRF-Token': '{token}'}}}});
      if (!beginResp.ok) throw new Error((await beginResp.json()).error || 'Could not start authentication.');
      const options = (await beginResp.json()).publicKey;
      const credential = await navigator.credentials.get({{
        publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options)
      }});
      const completeResp = await fetch('/webauthn/authenticate/complete', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json', 'X-CSRF-Token': '{token}'}},
        body: JSON.stringify(credential.toJSON())
      }});
      const result = await completeResp.json();
      if (!completeResp.ok || !result.ok) throw new Error(result.error || 'Verification failed.');
      window.location = result.next || '/';
    }} catch (e) {{
      errEl.textContent = e.message || String(e);
      errEl.style.display = 'block';
    }}
  }}
  document.getElementById('go').addEventListener('click', go);
</script>
"""
    if has_key and user_has_totp:
        body += """<p class="muted" style="text-align:center;margin:1.25rem 0">or</p>"""
    if user_has_totp:
        body += """
<form method="post" autocomplete="off">
  <div class="field"><label>Code from your authenticator app</label>
    <input name="code" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" placeholder="123456" autofocus required></div>
  <button type="submit" style="width:100%">Verify code</button>
</form>
"""
    return render_template_string(AUTH_PAGE, error=error, heading="Second factor", body=body, domain=TENANT_DOMAIN)


@app.route("/webauthn/authenticate/begin", methods=["POST"])
def webauthn_authenticate_begin():
    if not session.get("pending_username"):
        return jsonify(error="Not in a pending login."), 400
    options, state = _webauthn_server.authenticate_begin(credentials=_attested_credentials(session["pending_username"]))
    session["webauthn_state"] = state
    return jsonify(dict(options))


@app.route("/webauthn/authenticate/complete", methods=["POST"])
def webauthn_authenticate_complete():
    pending = session.get("pending_username")
    state = session.get("webauthn_state")
    if not pending or not state:
        return jsonify(ok=False, error="Not in a pending login."), 400
    try:
        response = AuthenticationResponse.from_dict(request.get_json(force=True))
        # Only ever checked against `pending`'s OWN credentials -- see
        # this file's _attested_credentials/owner-scoping: with more than
        # one team member, checking against everyone's keys would let
        # anyone who knows another user's password complete 2FA with a
        # DIFFERENT person's physical key and log in as them.
        _webauthn_server.authenticate_complete(state, _attested_credentials(pending), response)
    except Exception:
        audit_log("panel.login_2fa_failed", actor=pending, ip=request.remote_addr,
                  detail={"factor": "webauthn"})
        return jsonify(ok=False, error="Security key verification failed."), 400
    session.pop("webauthn_state", None)
    session["username"] = session.pop("pending_username")
    audit_log("panel.login_2fa_webauthn", actor=session["username"], ip=request.remote_addr)
    return jsonify(ok=True, next=request.args.get("next") or url_for("index"))


@app.route("/operator-access", methods=["POST"])
def operator_access_consume():
    """Consumes a single-use grant token and opens an operator session.

    POST with the token in the body, not GET with it in the query string:
    the operator admin UI submits a cross-origin form here, so the token
    never lands in browser history, a Referer header, or Traefik's access
    log the way a click-through link would.

    CSRF-exempt (see _enforce_csrf's exempt set) because the token IS the
    authentication -- there is no ambient session authority here for a
    forged cross-site request to borrow, which is the only thing CSRF
    protection defends. A forged request would need the token, and
    anyone holding the token can just use it directly.
    """
    state = operator_access_state()
    token = request.form.get("token", "")
    if not state.get("active") or not state.get("token_hash"):
        audit_log("operator_access.denied", ip=request.remote_addr,
                  actor="-", detail={"reason": "no active grant"})
        return render_template_string(
            AUTH_PAGE, error="No active operator access grant for this site.",
            heading="Operator access", body="", domain=TENANT_DOMAIN), 403
    if state.get("token_used_at"):
        audit_log("operator_access.denied", ip=request.remote_addr,
                  actor=f"{OPERATOR_ACTOR_PREFIX}{state.get('operator', '?')}",
                  detail={"reason": "token already used"})
        return render_template_string(
            AUTH_PAGE, error="That access link has already been used. Ask for a new one.",
            heading="Operator access", body="", domain=TENANT_DOMAIN), 403
    if not check_password_hash(state["token_hash"], token):
        audit_log("operator_access.denied", ip=request.remote_addr,
                  actor=f"{OPERATOR_ACTOR_PREFIX}{state.get('operator', '?')}",
                  detail={"reason": "bad token"})
        return render_template_string(
            AUTH_PAGE, error="That access link isn't valid.",
            heading="Operator access", body="", domain=TENANT_DOMAIN), 403

    # Single-use: burn the token immediately. The GRANT stays active for
    # its full window (so the session keeps working, and the tenant's
    # banner keeps showing) -- it's only the link that's spent, so a
    # copy of it leaking later is worthless.
    try:
        data = json.loads(OPERATOR_ACCESS_FILE.read_text())
        data["token_used_at"] = datetime.now(timezone.utc).isoformat()
        OPERATOR_ACCESS_FILE.write_text(json.dumps(data))
        _chown_to_host(OPERATOR_ACCESS_FILE)
    except (OSError, json.JSONDecodeError) as e:
        print(f"WARNING: could not mark operator token used: {e!r}", file=sys.stderr)

    session.clear()
    session["username"] = f"{OPERATOR_ACTOR_PREFIX}{state['operator']}"
    session["csrf_token"] = secrets.token_urlsafe(32)
    audit_log("operator_access.session_started", ip=request.remote_addr,
              detail={"expires_at": state.get("expires_at", "?")})
    return redirect(url_for("index"))


@app.route("/logout", methods=["POST"])
def logout():
    # Before session.clear(), or the actor is already gone by the time
    # audit_log() falls back to reading it from the session.
    audit_log("panel.logout", actor=session.get("username") or "-", ip=request.remote_addr)
    session.clear()
    return redirect(url_for("login"))


PASSWORD_CHANGE_REQUIRED_BODY = """
<p class="muted" style="margin-top:0">
  The password you just used was generated by your host and is single-use.
  Choose your own now -- they can't see what you set here, and the one they
  gave you stops working as soon as you finish.
</p>
<form method="post" autocomplete="off">
  <div class="field"><label for="new_password">New password</label>
    <input type="password" id="new_password" name="new_password" autocomplete="new-password" autofocus required></div>
  <div class="field"><label for="confirm_password">Confirm new password</label>
    <input type="password" id="confirm_password" name="confirm_password" autocomplete="new-password" required></div>
  <button type="submit" style="width:100%">Set my password</button>
</form>
<form method="post" action="/logout" style="margin-top:1rem">
  <button type="submit" class="btn-ghost" style="width:100%">Log out instead</button>
</form>
"""
# Literal "/logout", not url_for: AUTH_PAGE substitutes this via
# {{ body|safe }} in a single render pass, so Jinja tags inside the body
# are inert text by the time they land -- same constraint login_2fa's own
# body already works around.


@app.route("/password-change-required", methods=["GET", "POST"])
@require_login
def password_change_required():
    """Forced change after an operator (or an owner, via /team) set this
    account's password. Deliberately does NOT ask for the current
    password, unlike the voluntary change on /security-key: the user just
    proved they hold it by logging in, and re-typing a long generated
    string they pasted from an email is friction with no security value.

    Anyone reaching here with no pending change gets sent home, so a
    stale bookmark can't present a password form out of context.
    """
    if not must_change_password(session["username"]):
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if not new:
            error = "Enter a new password."
        elif len(new) < MIN_PASSWORD_LENGTH:
            error = f"New password must be at least {MIN_PASSWORD_LENGTH} characters."
        elif new != confirm:
            error = "New password and confirmation don't match."
        elif check_login(session["username"], new):
            # Reusing the handed-over value would leave the operator
            # knowing the live password -- the one thing this flow exists
            # to prevent.
            error = "Choose a different password from the one you were given."
        else:
            set_user_password(session["username"], new)
            return redirect(url_for("index"))
    return render_template_string(
        AUTH_PAGE, error=error, heading="Choose a new password",
        body=PASSWORD_CHANGE_REQUIRED_BODY, domain=TENANT_DOMAIN,
    )


@app.errorhandler(403)
def forbidden(e):
    if not session.get("username"):
        return redirect(url_for("login"))
    if e.description == "csrf":
        return render("<h2>Your session expired</h2><p class=\"muted\">That form was "
                      "from an old page load. Go back and try again -- reloading the "
                      "page first will pick up a fresh token.</p>"), 403
    if e.description == "no_2fa":
        return render("<h2>Two-factor authentication required</h2>"
                      "<p class=\"muted\">The file manager needs a second factor "
                      "registered on your account first -- a security key or an "
                      "authenticator app, either one. Set one up on the "
                      "<a href=\"/security-key\">Security key</a> page (an "
                      "authenticator app like Google Authenticator or Authy takes "
                      "about two minutes, no hardware needed), then come back.</p>"), 403
    return render("<h2>Not available</h2><p class=\"muted\">Your account is a "
                  "member, not an owner -- that page or action is owner-only. "
                  "Ask a team owner on the <a href=\"/team\">Team</a> page if "
                  "you need it.</p>"), 403


@app.route("/security-key", methods=["GET", "POST"])
@require_login
def security_key():
    error = None
    saved = False
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if not check_login(session["username"], current):
            error = "Current password is incorrect."
        elif not new:
            error = "Enter a new password."
        elif len(new) < MIN_PASSWORD_LENGTH:
            error = f"New password must be at least {MIN_PASSWORD_LENGTH} characters."
        elif new != confirm:
            error = "New password and confirmation don't match."
        else:
            set_user_password(session["username"], new)
            saved = True
    keys = [{"name": e["name"], "added_at": e["added_at"]} for e in _load_webauthn_credentials() if e["owner"] == session["username"]]
    return render(SECURITY_KEY_PAGE, keys=keys, rp_id=WEBAUTHN_RP_ID, error=error, saved=saved, username=session["username"],
                  totp_enabled=has_totp(session["username"]), totp_added_at=totp_added_at(session["username"]))


@app.route("/webauthn/register/begin", methods=["POST"])
@require_login
def webauthn_register_begin():
    user = PublicKeyCredentialUserEntity(
        id=session["username"].encode(), name=session["username"], display_name=session["username"]
    )
    options, state = _webauthn_server.register_begin(
        user, credentials=_attested_credentials(session["username"]), user_verification="preferred"
    )
    session["webauthn_state"] = state
    return jsonify(dict(options))


@app.route("/webauthn/register/complete", methods=["POST"])
@require_login
def webauthn_register_complete():
    state = session.get("webauthn_state")
    if not state:
        return jsonify(ok=False, error="No registration in progress."), 400
    body = request.get_json(force=True)
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify(ok=False, error="Name required."), 400
    if _name_taken(session["username"], name):
        return jsonify(ok=False, error=f"A key named {name!r} already exists."), 400
    try:
        response = RegistrationResponse.from_dict(body["credential"])
        auth_data = _webauthn_server.register_complete(state, response)
    except Exception as e:
        return jsonify(ok=False, error=f"Registration failed: {e}"), 400
    session.pop("webauthn_state", None)
    entries = _load_webauthn_credentials()
    entries.append({
        "owner": session["username"],
        "name": name,
        "credential_data": base64.b64encode(bytes(auth_data.credential_data)).decode(),
        "added_at": datetime.now(timezone.utc).isoformat(),
    })
    _save_webauthn_credentials(entries)
    return jsonify(ok=True)


@app.route("/webauthn/remove", methods=["POST"])
@require_login
def webauthn_remove():
    name = request.form.get("name", "")
    _save_webauthn_credentials([
        e for e in _load_webauthn_credentials() if not (e["owner"] == session["username"] and e["name"] == name)
    ])
    return redirect(url_for("security_key"))


@app.route("/totp/setup", methods=["GET", "POST"])
@require_login
def totp_setup():
    error = None
    if request.method == "POST":
        pending_secret = session.get("pending_totp_secret")
        code = request.form.get("code", "").strip().replace(" ", "")
        if not pending_secret:
            return redirect(url_for("totp_setup"))
        if totp_confirm_and_enable(session["username"], pending_secret, code, datetime.now(timezone.utc).isoformat()):
            session.pop("pending_totp_secret", None)
            return redirect(url_for("security_key"))
        error = "That code didn't verify -- check the time on your phone/authenticator and try again."
        secret = pending_secret
        qr_svg = totp_qr_svg_for_secret(session["username"], secret)
    else:
        secret, qr_svg = totp_generate_setup(session["username"])
        session["pending_totp_secret"] = secret
    return render(TOTP_SETUP_PAGE, error=error, secret=secret, qr_svg=qr_svg)


@app.route("/totp/remove", methods=["POST"])
@require_login
def totp_remove_route():
    totp_remove(session["username"])
    return redirect(url_for("security_key"))


@app.route("/api-tokens", methods=["GET", "POST"])
@require_role("owner")
@require_2fa
def api_tokens_view():
    """Layer 2 of the tenant API/MCP two-layer permission model
    (architecture.md's "API and MCP access for operators and tenants";
    see vhsp_ctl/provisioner.py's set_tenant_api_allowed's own docstring
    for Layer 1). Owner + 2FA, same tier as Files/Database -- a token
    minted here can do everything this account can, up to what
    vhsp_ctl/api.py's /self/* routes and mcp_server.py's tenant-scoped
    tools actually expose.

    enable_api/enable_mcp re-check Layer 1 server-side before honoring
    anything -- never trust that the form simply hid the button; a
    tenant POSTing this action directly when their operator hasn't
    allowed it is rejected with a clear error, not silently ignored."""
    error = None
    new_token = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "create":
            label = request.form.get("label", "").strip()
            if not label:
                error = "Name this token (e.g. \"laptop script\", \"ops agent\")."
            else:
                new_token = mint_api_token(label)
        elif action == "revoke":
            error = revoke_api_token(request.form.get("token_id", ""))
        elif action == "enable_api":
            if _load_platform_access()["api_allowed"]:
                _set_platform_access_enabled(api_enabled=True)
            else:
                error = "Your host hasn't allowed REST API access for this site."
        elif action == "disable_api":
            _set_platform_access_enabled(api_enabled=False)
        elif action == "enable_mcp":
            if _load_platform_access()["mcp_allowed"]:
                _set_platform_access_enabled(mcp_enabled=True)
            else:
                error = "Your host hasn't allowed MCP access for this site."
        elif action == "disable_mcp":
            _set_platform_access_enabled(mcp_enabled=False)
    return render(API_TOKENS_PAGE, error=error, new_token=new_token, tokens=list_api_tokens(),
                  access=_load_platform_access(), platform_api_host=PLATFORM_API_HOST)


@app.route("/audit")
@require_role("owner")
def audit_view():
    """Owner-only: the log names every user's actions, so it's oversight
    of the team rather than a personal history -- same tier as /team,
    which is the other place one user can see another's business. GET
    only; nothing here mutates, and the log is deliberately not
    clearable from the UI at all (a wipe button would defeat the point
    of keeping it).
    """
    action_filter = request.args.get("action", "").strip()
    actor_filter = request.args.get("actor", "").strip()
    chain_ok, chain_count = audit_verify()
    return render(
        AUDIT_PAGE,
        entries=audit_entries(limit=300, action_filter=action_filter, actor_filter=actor_filter),
        action_filter=action_filter, actor_filter=actor_filter,
        chain_ok=chain_ok, chain_count=chain_count,
    )


@app.route("/team", methods=["GET", "POST"])
@require_login
def team():
    # Readable by any logged-in user (so a member can see who the owners
    # are, e.g. to ask one for something owner-only) -- every action below
    # is a mutation, though, and those stay owner-only.
    if request.method == "POST" and user_role(session["username"]) != "owner":
        abort(403)
    error = None
    generated_username = None
    generated_password = None
    if request.method == "POST":
        action = request.form.get("action")
        target = request.form.get("target", "").strip()
        if action == "add":
            role = request.form.get("role", "member")
            try:
                generated_password = create_user(target, role=role)
                generated_username = target
            except AuthError as e:
                error = str(e)
        elif action == "reset-password":
            password = secrets.token_urlsafe(18)
            try:
                # must_change: same reasoning as the operator's own reset
                # of this panel's admin login -- whoever read this value
                # shouldn't still know the colleague's password afterwards.
                set_user_password(target, password, must_change=True)
                generated_username = target
                generated_password = password
            except AuthError as e:
                error = str(e)
        elif action == "remove":
            try:
                remove_user(target)
            except AuthError as e:
                error = str(e)
        elif action == "set-role":
            try:
                set_user_role(target, request.form.get("role", ""))
            except AuthError as e:
                error = str(e)
    users = list_users()
    key_counts = {
        u["username"]: sum(1 for e in _load_webauthn_credentials() if e["owner"] == u["username"])
        for u in users
    }
    totp_status = {u["username"]: has_totp(u["username"]) for u in users}
    return render(TEAM_PAGE, users=users, key_counts=key_counts, totp_status=totp_status, username=session["username"],
                  error=error, generated_username=generated_username, generated_password=generated_password,
                  is_owner=user_role(session["username"]) == "owner")


# Matches images/web/entrypoint.sh's own (independent) validation exactly --
# this is just the friendlier first pass; that script is the real trust
# boundary and re-checks everything itself before it ever becomes nginx
# syntax.
PATH_RE = re.compile(r"^/[A-Za-z0-9/_.-]*$")
REDIRECT_TARGET_RE = re.compile(r"^(https?://[A-Za-z0-9/:?#\[\]@!*+,=._~%&-]+|/[A-Za-z0-9/_.\-?#=&%~]*)$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
NOEXEC_DIR_RE = re.compile(r"^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$")

# name -> (file, human label)
LOG_FILES = [
    ("web-access.log", "Web -- access"),
    ("web-error.log", "Web -- error"),
    ("php-error.log", "PHP-FPM -- error"),
    ("mail.log", "Mail (Postfix + Dovecot)"),
    ("sftp.log", "SFTP"),
]
TAIL_LINES = 200

# Must match images/web/entrypoint.sh's ALL_TOGGLEABLE exactly -- this is
# the fixed set of functions a tenant is allowed to have an opinion about;
# the web container's watcher only understands these by name.
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

LAYOUT = """
<!doctype html><meta name="viewport" content="width=device-width, initial-scale=1"><title>{{ domain }} -- tenant admin</title>
<style>""" + BASE_CSS + """</style>
<div class="topbar"><div class="topbar-inner">
  <div class="brand-row">
    <span class="brand">{{ domain }}</span>
    <div style="display:flex;align-items:center;gap:0.9rem">
      <span class="muted">{{ username }}{% if has_2fa %} <span title="Two-factor authentication enabled" aria-label="Two-factor authentication enabled" style="display:inline-flex;vertical-align:middle"><svg width="18" height="15" viewBox="0 0 26 22" aria-hidden="true"><g fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 8V5a4 4 0 0 1 8 0v3"></path><rect x="11" y="8" width="14" height="9" rx="1.6"></rect></g><g stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path fill="none" d="M5 10V7a4 4 0 0 1 8 0v3"></path><rect fill="var(--surface)" x="3" y="10" width="14" height="9" rx="1.6"></rect></g></svg></span>{% endif %}</span>
      <form method="post" action="/logout"><button type="submit" class="btn-ghost">Log out</button></form>
    </div>
  </div>
  <p class="quota-line">Disk usage (web + database + mail, soft quota): {{ usage_total_mb }} / {{ quota_limit_mb }} ({{ quota_percent }}%)</p>
  <div class="quota-bar"><div class="quota-bar-fill {{ quota_status }}" style="width:{{ quota_percent }}%"></div></div>
  <div class="subnav">
    {% for href, label, owner_only, needs_2fa in [
      ('/', 'Overview', False, False), ('/php-functions', 'PHP functions', False, True), ('/fallback', '404 handling', False, False),
      ('/auth', 'Password protection', False, False), ('/error-pages', 'Error pages', False, False),
      ('/redirects', 'Redirects', False, True), ('/noexec-dirs', 'No-exec dirs', False, True),
      ('/ip-acl', 'IP restrictions', False, True), ('/fail2ban-allowlist', 'Login allowlist', False, True),
      ('/email', 'Email', False, False),
      ('/files', 'Files', True, True),
      ('/database', 'Database', True, True), ('/backups', 'Backups', False, True),
      ('/security-key', 'My account', False, False), ('/team', 'Team', True, False), ('/logs', 'Logs', False, False),
      ('/audit', 'Audit log', True, False),
      ('/api-tokens', 'API & MCP access', True, True),
      ('/manual', 'Manual', False, False),
    ] %}
    {% if not owner_only or is_owner %}
    <a href="{{ href }}" class="{{ 'active' if request.path == href }}">{{ label }}{% if needs_2fa and not has_2fa %} <span class="muted">(2FA required)</span>{% endif %}</a>
    {% endif %}
    {% endfor %}
  </div>
</div></div>
<div class="shell">
{% if operator_access.active %}
<div class="operator-banner">
  <strong>Your host currently has temporary admin access to this panel.</strong>
  {% if viewing_as_operator %}
  You are signed in as <code>{{ username }}</code> — an operator, not this tenant.
  Everything you do here is recorded in this tenant's own audit log under your name,
  and in the operator audit log.
  {% else %}
  <code>{{ operator_access.operator }}</code> can act here as an owner until
  <strong>{{ operator_access.expires_at|humanize_ts }}</strong>, then access ends
  automatically. Everything they do is recorded in your
  <a href="/audit">audit log</a> under their name. You did not lose any access —
  your own login still works normally.
  {% endif %}
</div>
{% endif %}
{% if maintenance_enabled %}
<div class="warn">
  <strong>Maintenance mode is on.</strong> Visitors see a "temporarily undergoing
  maintenance" page instead of your site, and mail clients can't log in (IMAP or
  sending). Incoming email is still being delivered normally. This was turned on
  by your host, not something in this panel -- contact them to have it lifted.
</div>
{% endif %}
{{ body|safe }}
</div>
<script>
  document.querySelectorAll('form').forEach(function (f) {
    var isGet = f.method.toLowerCase() === 'get';
    if (!isGet) {
      var i = document.createElement('input');
      i.type = 'hidden'; i.name = 'csrf_token'; i.value = '{{ csrf_token() }}';
      f.appendChild(i);
    }
    f.addEventListener('submit', function (e) {
      if (e.defaultPrevented || isGet) return;
      var btn = e.submitter;
      if (btn && btn.tagName === 'BUTTON' && !btn.disabled) {
        btn.disabled = true;
        btn.textContent = 'Working…';
      }
    });
  });
</script>
"""

OVERVIEW_PAGE = """
<h2>Overview</h2>
<p class="muted">Everything you need to connect to this site's services.</p>
<div class="card">
  <table>
    <tr><td>Website</td><td><a href="https://{{ domain }}/" target="_blank" rel="noopener noreferrer">https://{{ domain }}/</a></td></tr>
    <tr><td>Webmail</td><td><a href="https://webmail.{{ domain }}/" target="_blank" rel="noopener noreferrer">https://webmail.{{ domain }}/</a></td></tr>
    <tr><td>Mail server</td><td><code>mail.{{ domain }}</code> &middot;
      IMAP: port 993 (implicit TLS) &middot;
      SMTP (submission): port 465 (implicit TLS)<br>
      <span class="muted">Manage mailboxes and see recommended DNS records on the <a href="/email">Email</a> page.</span>
    </td></tr>
    <tr><td>SFTP connect</td><td>
      {% if ssh_port %}<code>sftp -P {{ ssh_port }} {{ sftp_user }}@{{ domain }}</code>{% else %}<span class="muted">not available yet</span>{% endif %}
      <br><span class="muted">Uploads land in ~/www, served live. Contact your host if you haven't been given an SSH key yet.</span>
    </td></tr>
    <tr><td>Database</td><td>
      host <code>{{ db_host }}</code> &middot; name <code>{{ db_name }}</code> &middot; user <code>{{ db_user }}</code><br>
      {% if db_password %}password: <code>{{ db_password }}</code>{% else %}<span class="muted">password visible to owners only -- see <a href="/database">Database</a></span>{% endif %}
      <br><span class="muted">Same credentials your own application already uses -- see the <a href="/database">Database</a> page for a SQL console.</span>
    </td></tr>
  </table>
</div>

<h3>Disk usage / quota</h3>
<div class="card">
  <table>
    <tr><td>Web</td><td>{{ web_mb }}</td></tr>
    <tr><td>Database</td><td>{{ db_mb }}</td></tr>
    <tr><td>Mail</td><td>{{ mail_mb }}</td></tr>
    <tr><td>Total</td><td>{{ usage_total_mb }} / {{ quota_limit_mb }} ({{ quota_percent }}%)</td></tr>
  </table>
</div>
"""

PAGE = """
<h2>PHP functions</h2>
<p>Disabled by default. Re-enabling any of these gives PHP
code running on your site the ability to run arbitrary programs on the
server -- only enable what your application genuinely needs.</p>
<div class="warn">Changes take effect within a few seconds (the web
container reloads PHP-FPM automatically). Existing requests in flight are
not interrupted.</div>
{% if saved %}<div class="flash">Saved.</div>{% endif %}
<form method="post">
  <div class="card">
    <table>
      <thead><tr><th style="width:2.5rem"></th><th>Function</th><th>What it does</th></tr></thead>
      <tbody>
      {% for fn, desc in functions %}
      <tr>
        <td><input type="checkbox" name="fn" value="{{ fn }}" {% if fn in enabled %}checked{% endif %}></td>
        <td><code>{{ fn }}</code></td>
        <td class="muted">{{ desc }}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  <button type="submit">Save</button>
</form>
"""

FALLBACK_PAGE = """
<h2>404 handling</h2>
<p>By default, a request that doesn't match a real file falls back to
your site's front controller -- <code>index.php</code> if you have one
(this is what makes WordPress/Laravel/etc.-style pretty permalinks work,
the same job <code>.htaccess</code> does on Apache), otherwise
<code>index.html</code>. Turn this off if you want plain 404 responses
for missing pages instead.</p>
<div class="warn">Takes effect immediately -- no reload, no downtime.</div>
{% if saved %}<div class="flash">Saved.</div>{% endif %}
<div class="card">
  <form method="post">
    <label style="display:flex;align-items:center;gap:0.5rem;font-weight:400">
      <input type="checkbox" name="enabled" style="width:auto" {% if enabled %}checked{% endif %}>
      Fall back to index.php / index.html on 404 (recommended)
    </label>
    <div style="margin-top:1rem"><button type="submit">Save</button></div>
  </form>
</div>
"""

BASIC_AUTH_PAGE = """
<h2>Password protection</h2>
<p>Lock your entire site behind a single username/password (HTTP Basic
Auth) -- the same job Apache's <code>.htaccess</code> + <code>AuthUserFile</code>
does. Applies to every page, including PHP.</p>
<div class="warn">Takes effect within a few seconds (the web container
reloads nginx automatically).</div>
{% if error %}<div class="flash error">{{ error }}</div>{% endif %}
{% if saved %}<div class="flash">Saved.</div>{% endif %}
<div class="card">
  {% if currently_enabled %}<p style="margin-top:0">Currently <span class="badge badge-ok">enabled</span> for user <code>{{ current_user }}</code>.</p>
  {% else %}<p class="muted" style="margin-top:0">Currently disabled -- your site is public.</p>{% endif %}
  <form method="post" autocomplete="off">
    <div class="field"><label>Username</label><input type="text" name="username" value="{{ current_user }}" autocomplete="off"></div>
    <div class="field"><label>New password</label><input type="password" name="password" placeholder="leave blank to keep disabled/unchanged" autocomplete="new-password"></div>
    <div class="actions">
      <button type="submit" name="action" value="save">Save</button>
      {% if currently_enabled %}<button type="submit" name="action" value="disable" class="btn-ghost">Disable protection</button>{% endif %}
    </div>
  </form>
</div>
"""

ERROR_PAGES_PAGE = """
<h2>Custom error pages</h2>
<p>Map an HTTP error code to a page in your own webroot, e.g. a custom
404. One per line: <code>CODE /path/to/page.html</code>.</p>
<div class="warn">Takes effect within a few seconds. Paths must start with
<code>/</code> and refer to a file in your webroot; anything else is
rejected.</div>
{% if error %}<div class="flash error">{{ error }}</div>{% endif %}
{% if saved %}<div class="flash">Saved.</div>{% endif %}
<div class="card">
  <form method="post">
    <div class="field"><textarea name="lines" rows="6" placeholder="404 /custom-404.html">{{ current }}</textarea></div>
    <button type="submit">Save</button>
  </form>
</div>
"""

REDIRECTS_PAGE = """
<h2>Redirects</h2>
<p>Permanent (301) redirects for exact paths. One per line:
<code>/old-path https://example.com/new-path</code> (the target can also
be an absolute path on your own site, e.g. <code>/new-path</code>).</p>
<div class="warn">Takes effect within a few seconds. Only exact-path
matches are supported (no wildcards).</div>
{% if error %}<div class="flash error">{{ error }}</div>{% endif %}
{% if saved %}<div class="flash">Saved.</div>{% endif %}
<div class="card">
  <form method="post">
    <div class="field"><textarea name="lines" rows="6" placeholder="/old-page https://example.com/new-page">{{ current }}</textarea></div>
    <button type="submit">Save</button>
  </form>
</div>
"""

NOEXEC_DIRS_PAGE = """
<h2>No-execute directories</h2>
<p>Denies PHP execution under these directories (relative to your
webroot), regardless of what ends up in them -- one directory per line, no
leading/trailing slash, e.g. <code>wp-content/uploads</code>. Your web
process runs as the same user your SFTP account does, so a dropped
executable file anywhere writable is a full compromise, not a contained
one -- keep this on for any directory your site or its visitors can write
to.</p>
<div class="warn">Takes effect within a few seconds.</div>
{% if error %}<div class="flash error">{{ error }}</div>{% endif %}
{% if saved %}<div class="flash">Saved.</div>{% endif %}
<div class="card">
  <form method="post">
    <div class="field"><textarea name="lines" rows="6" placeholder="wp-content/uploads">{{ current }}</textarea></div>
    <button type="submit">Save</button>
  </form>
</div>
"""

IP_ACL_PAGE = """
<h2>IP restrictions</h2>
<p>Restrict your whole site to specific IPs/CIDRs, or block specific
ones -- everyone else is treated the opposite way. Same job as
<code>.htaccess</code>'s <code>Allow</code>/<code>Deny from</code>.</p>
<div class="warn">Takes effect within a few seconds. "Only allow" mode with the
wrong IPs/CIDRs silently makes your live site unreachable to everyone,
including your own real visitors -- there's no confirmation step and no
automatic recovery. Your own current IP is <code>{{ your_ip }}</code> --
worth including if you want to keep being able to reach your own site
while testing this.</div>
{% if error %}<div class="flash error">{{ error }}</div>{% endif %}
{% if saved %}<div class="flash">Saved.</div>{% endif %}
<div class="card">
  <form method="post">
    <div class="field" style="display:flex;flex-direction:column;gap:0.4rem">
      <label style="display:flex;align-items:center;gap:0.5rem;font-weight:400"><input type="radio" name="mode" value="allow" style="width:auto" {% if mode == "allow" %}checked{% endif %}> Only allow these IPs (block everyone else)</label>
      <label style="display:flex;align-items:center;gap:0.5rem;font-weight:400"><input type="radio" name="mode" value="deny" style="width:auto" {% if mode == "deny" %}checked{% endif %}> Block these IPs (allow everyone else)</label>
      <label style="display:flex;align-items:center;gap:0.5rem;font-weight:400"><input type="radio" name="mode" value="" style="width:auto" {% if not mode %}checked{% endif %}> Disabled -- no restriction</label>
    </div>
    <div class="field"><textarea name="lines" rows="6" placeholder="203.0.113.0/24&#10;198.51.100.7">{{ current }}</textarea></div>
    <button type="submit">Save</button>
  </form>
</div>
"""

FAIL2BAN_ALLOWLIST_PAGE = """
<h2>Login allowlist</h2>
<p><strong>In short:</strong> add your own office/home IP here so a
mistyped password on this login page never contributes to a platform-wide
ban.</p>
<p class="muted">A few things worth knowing about how that actually
works: it only covers failed logins on <strong>your own</strong> site's
admin panel -- it can't exempt your IP from a ban a <em>different</em>
tenant's failed logins trigger, since every tenant's admin panel shares
the same login page platform-wide, and a ban there applies everywhere at
once. And your account's own short lockout (a few minutes, after
repeated failures) still happens regardless of this list -- this only
changes what gets reported to the platform-wide system, not your own
account's local behavior.</p>
{% if error %}<div class="flash error">{{ error }}</div>{% endif %}
{% if saved %}<div class="flash">Saved.</div>{% endif %}
<div class="card">
  <form method="post">
    <div class="field"><textarea name="lines" rows="6" placeholder="203.0.113.4&#10;198.51.100.0/24">{{ current }}</textarea></div>
    <button type="submit">Save</button>
  </form>
</div>
"""

EMAIL_PAGE = """
<h2>Email</h2>
<p class="muted">
  Server: <code>mail.{{ domain }}</code> &middot;
  IMAP: port 993 (implicit TLS) &middot;
  SMTP (submission): port 465 (implicit TLS) &middot;
  Webmail: <a href="https://webmail.{{ domain }}/" target="_blank" rel="noopener noreferrer">https://webmail.{{ domain }}/</a>
</p>
<div class="warn">Changes take effect within a few seconds (postfix/dovecot
reload automatically). Per-mailbox quotas are independent of the tenant's
combined disk quota above, but usage still counts toward it either way.</div>
{% if error %}<div class="flash error">{{ error }}</div>{% endif %}
{% if saved %}<div class="flash">Saved.</div>{% endif %}
{% if not is_owner %}<p class="muted">You're a member -- resetting a mailbox's
password or deleting one is owner-only (email is the recovery path into most of
what you own outside this platform too, so this stays a bigger deal than
day-to-day provisioning). Adding a mailbox and setting quotas below are still
available to you.</p>{% endif %}
<div class="card">
  <table>
    <thead><tr><th>Mailbox</th><th>Quota</th>{% if is_owner %}<th>Reset password</th><th></th>{% endif %}</tr></thead>
    <tbody>
    {% for user in mailboxes %}
    <tr>
      <td><code>{{ user }}@{{ domain }}</code>{% if user == postmaster %} <span class="muted">(required)</span>{% endif %}</td>
      <td>
        <form class="actions" method="post" autocomplete="off">
          <input type="hidden" name="action" value="quota">
          <input type="hidden" name="user" value="{{ user }}">
          <input type="number" name="quota_mb" min="1" placeholder="unlimited" value="{{ boxes[user].quota_bytes // 1048576 if boxes[user].quota_bytes else '' }}" style="width:8em">
          <span class="muted">MB</span> <button type="submit">Set</button>
        </form>
      </td>
      {% if is_owner %}
      <td>
        <form class="actions" method="post" autocomplete="off">
          <input type="hidden" name="action" value="reset">
          <input type="hidden" name="user" value="{{ user }}">
          <input type="password" name="password" placeholder="new password" required autocomplete="new-password" style="width:11em">
          <button type="submit">Reset</button>
        </form>
      </td>
      <td>
        {% if user != postmaster %}
        <form method="post"
              onsubmit="return confirm('Delete ' + '{{ user }}' + '@{{ domain }}? This cannot be undone.');">
          <input type="hidden" name="action" value="delete">
          <input type="hidden" name="user" value="{{ user }}">
          <button type="submit" class="danger">Delete</button>
        </form>
        {% endif %}
      </td>
      {% endif %}
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
<h3>Add a mailbox</h3>
<div class="card">
  <form method="post" autocomplete="off">
    <input type="hidden" name="action" value="add">
    <div class="actions">
      <label class="sr-only" for="new-mailbox-user">Mailbox name</label>
      <input id="new-mailbox-user" type="text" name="user" placeholder="sales" autocomplete="off" style="max-width:160px">
      <span class="muted">@{{ domain }}</span>
      <label class="sr-only" for="new-mailbox-password">Password</label>
      <input id="new-mailbox-password" type="password" name="password" placeholder="password" autocomplete="new-password" style="max-width:200px">
      <button type="submit">Add</button>
    </div>
  </form>
</div>

<h3>Recommended DNS records</h3>
<p class="muted">
  Add these at whatever host actually manages this domain's DNS -- nothing
  here changes DNS for you. Includes SPF/DKIM (mail sent from this tenant
  is already signed) and DMARC; the MX/mail-A entries only matter once
  you're ready to point this domain's inbound mail at this host.
</p>
{% if dns_records %}
<form method="get" style="margin-bottom:1rem">
  <button type="submit" name="check" value="1">Check records</button>
  {% if dns_checked %}<span class="muted" style="margin-left:0.5rem">Checked against live DNS just now.</span>{% endif %}
</form>
<div class="card" style="overflow-x:auto">
  <table>
    <thead><tr><th>Type</th><th>Name</th><th>Value</th></tr></thead>
    <tbody>
    {% for r in dns_records %}
    <tr class="{{ 'dns-row-ok' if r.ok }}">
      <td>{{ r.kind }}
        {% if r.ok %} <span class="badge badge-ok">live</span>
        {% elif r.ok is defined %} <span class="badge badge-warn">not live yet</span>
        {% endif %}
      </td>
      <td><code class="copyable" title="Click to copy" tabindex="0" role="button" onclick="vhspCopyDns(this)" onkeydown="vhspCopyDnsKey(event, this)">{{ r.name }}</code></td>
      <td style="word-break:break-all"><code class="copyable" title="Click to copy" tabindex="0" role="button" onclick="vhspCopyDns(this)" onkeydown="vhspCopyDnsKey(event, this)">{{ r.value }}</code>
        {% if r.note %}<div class="muted" style="margin-top:0.25rem">{{ r.note }}</div>{% endif %}
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
<script>
  function vhspCopyDns(el) {
    const text = el.dataset.full || el.textContent;
    navigator.clipboard.writeText(text).then(() => {
      el.dataset.full = text;
      el.textContent = "Copied!";
      el.classList.add("copied");
      setTimeout(() => {
        el.textContent = el.dataset.full;
        el.classList.remove("copied");
      }, 1200);
    });
  }
  function vhspCopyDnsKey(event, el) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      vhspCopyDns(el);
    }
  }
</script>
{% else %}
<div class="card muted">Not available yet -- the mail server generates its signing key on
first start, which can take a few seconds after this tenant was created.</div>
{% endif %}
"""

FILES_PAGE = """
<h2>Files</h2>
<p class="muted">Direct read/write access to your webroot -- the same directory your
SFTP login and website itself serve from. Owner-only: this is equivalent to full
control over what your site serves, the same tier as the SQL console. Also requires
a second factor (security key or authenticator app) on your account -- you're
seeing this page because you already have one.</p>
{% if error %}<div class="flash error">{{ error }}</div>{% endif %}

<div class="card">
  <p style="margin-top:0">
    <a href="/files">webroot</a>
    {% for c in crumbs %} / <a href="/files?path={{ c.rel_path }}">{{ c.name }}</a>{% endfor %}
  </p>
  <table>
    <thead><tr><th>Name</th><th>Size</th><th>Modified</th><th></th></tr></thead>
    <tbody>
    {% for e in entries %}
    <tr>
      <td>
        {% if e.is_dir %}<a href="/files?path={{ e.rel_path }}">{{ e.name }}/</a>
        {% else %}{{ e.name }}{% endif %}
      </td>
      <td class="muted">{{ e.size_human }}</td>
      <td class="muted">{{ e.mtime }}</td>
      <td style="text-align:right">
        {% if not e.is_dir %}
        {% if e.is_text %}<a href="/files/edit?path={{ e.rel_path }}">Edit</a>{% endif %}
        <a href="/files/download?path={{ e.rel_path }}">Download</a>
        {% endif %}
        <button type="button" class="btn-ghost" onclick="vhspFilesMove('{{ e.rel_path }}')">Move</button>
        <form class="inline" method="post"
              onsubmit="return confirm('Delete {{ e.name }}{{ '/' if e.is_dir }}?{% if e.is_dir %} This deletes everything inside it.{% endif %} This cannot be undone.');">
          <input type="hidden" name="action" value="delete">
          <input type="hidden" name="path" value="{{ current_rel }}">
          <input type="hidden" name="target" value="{{ e.rel_path }}">
          <button class="danger" type="submit">Delete</button>
        </form>
      </td>
    </tr>
    {% else %}
    <tr><td colspan="4" class="muted">Empty directory.</td></tr>
    {% endfor %}
    </tbody>
  </table>
</div>

<div class="card">
  <h3 style="margin-top:0">Upload here</h3>
  <form method="post" enctype="multipart/form-data">
    <input type="hidden" name="action" value="upload">
    <input type="hidden" name="path" value="{{ current_rel }}">
    <div class="actions">
      <input type="file" name="uploads" multiple required>
      <button type="submit">Upload</button>
    </div>
  </form>
</div>

<form id="vhsp-files-move-form" method="post" style="display:none">
  <input type="hidden" name="action" value="move">
  <input type="hidden" name="path" value="{{ current_rel }}">
  <input type="hidden" name="target" id="vhsp-files-move-target">
  <input type="hidden" name="dest" id="vhsp-files-move-dest">
</form>
<script>
  function vhspFilesMove(relPath) {
    const dest = prompt('Move/rename to (path relative to the webroot):', relPath);
    if (dest === null || dest === relPath) return;
    document.getElementById('vhsp-files-move-target').value = relPath;
    document.getElementById('vhsp-files-move-dest').value = dest;
    document.getElementById('vhsp-files-move-form').submit();
  }
</script>
"""

FILES_EDIT_PAGE = """
<h2>Edit {{ rel_path }}</h2>
{% if error %}<div class="flash error">{{ error }}</div>{% endif %}
{% if saved %}<div class="flash">Saved.</div>{% endif %}
<style>
  /* CM6 injects its own rules for .cm-editor at low specificity, so a
     plain descendant selector here is enough to override font/size/
     border to match this page's other inputs -- no !important needed.
     Fixed height (rather than CM6's own auto-grow default) so a huge
     file scrolls inside the editor instead of pushing the Save button
     off-screen, same reasoning FILES_MAX_EDIT_BYTES already applies
     server-side. */
  .vhsp-cm-editor .cm-editor {
    border: 1px solid var(--input-border); border-radius: var(--radius-sm);
    height: 32rem;
  }
  .vhsp-cm-editor .cm-editor.cm-focused {
    outline: none; border-color: var(--input-focus);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--input-focus) 22%, transparent);
  }
  .vhsp-cm-editor .cm-content, .vhsp-cm-editor .cm-gutters {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.85rem;
  }
</style>
<div class="card">
  <form method="post">
    <input type="hidden" name="path" value="{{ rel_path }}">
    <textarea name="content" rows="28" spellcheck="false"
      style="font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace">{{ content }}</textarea>
    <div class="actions" style="margin-top:0.75rem">
      <button type="submit">Save</button>
      <a href="/files?path={{ rel_path.rsplit('/', 1)[0] if '/' in rel_path else '' }}" class="btn-ghost"
         style="display:inline-block;padding:0.5rem 0.9rem">Back to files</a>
    </div>
  </form>
</div>
<script src="{{ url_for('static', filename='vhsp-editor.bundle.js') }}"></script>
<script>
  vhspMountEditor(document.querySelector('textarea[name=content]'), {{ rel_path|tojson }});
</script>
"""

FILES_EDIT_ERROR_PAGE = """
<h2>Can't edit {{ rel_path }}</h2>
<div class="flash error">{{ error }}</div>
<p><a href="/files">Back to files</a></p>
"""

DATABASE_PAGE = """
<h2>Database</h2>
<p class="muted">Connected as <code>{{ db_user }}</code> to
<code>{{ db_name }}</code> on <code>{{ db_host }}</code> -- the same
database and credentials your own application already uses. This
console can't do anything your app's own code couldn't already do;
there's no extra restriction here beyond MariaDB's own permissions for
this user on this database.</p>
{% if error %}<div class="flash error"><pre style="white-space:pre-wrap;margin:0;background:none;border:none;padding:0">{{ error }}</pre></div>{% endif %}
<div class="card">
  <form method="post">
    <div class="field"><textarea name="sql" rows="6" placeholder="SELECT * FROM your_table LIMIT 100">{{ sql }}</textarea></div>
    <button type="submit">Run query</button>
  </form>
</div>
{% if columns is not none %}
  <p class="muted">{{ rows|length }} row{{ 's' if rows|length != 1 }}</p>
  <div class="card" style="overflow-x:auto">
  <table>
    <thead><tr>{% for c in columns %}<th>{{ c }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for row in rows %}
    <tr>{% for v in row %}<td>{{ v }}</td>{% endfor %}</tr>
    {% endfor %}
    </tbody>
  </table>
  </div>
{% elif ran and not error %}
  <div class="flash">OK -- {{ rowcount }} row{{ 's' if rowcount != 1 }} affected.</div>
{% endif %}
"""

BACKUPS_PAGE = """
<h2>Backups</h2>
<p class="muted">
  Your host backs up this site automatically to their own destination no
  matter what's set here -- that always happens, with no opt-out. This page
  is for an <strong>additional</strong> copy to a destination of your own
  choosing, in addition to that, never instead of it.
</p>
<div class="warn">Every restore -- from either destination -- is verified
against a cryptographic signature first; a corrupted or tampered snapshot is
refused outright rather than restored. Changes saved here take effect within
about 2 minutes, not instantly -- a background process on your host, not
this page, actually performs backups/restores.</div>
{% if error %}<div class="flash error">{{ error }}</div>{% endif %}
{% if saved %}<div class="flash">Saved -- takes effect within about 2 minutes.</div>{% endif %}
{% if age_first_reveal %}
<div class="warn">
  <strong>Your new encryption key -- copy this now, it will never be shown again:</strong>
  <pre style="white-space:pre-wrap;margin-top:0.5rem">{{ age_first_reveal }}</pre>
  If you lose it, backups already sent to your destination become permanently
  unreadable -- there is no recovery. Store it somewhere safe outside this panel.
</div>
{% endif %}
{% if dest_host and not encryption_enabled %}
<div class="warn">
  <strong>Encryption is off for your own destination.</strong> Anyone with
  access to that destination can read this site's backups in plain text
  (webroot, database, mail, mailbox/admin credentials). Turn encryption on
  below unless you have a specific reason not to.
</div>
{% endif %}

<div class="card">
  <h3 style="margin-top:0">Your destination</h3>
  {% if is_owner %}
  <form method="post">
    <input type="hidden" name="action" value="save_settings">
    <div class="field"><label>SFTP host</label><input type="text" name="dest_host" value="{{ dest_host }}" placeholder="backup.example.com"></div>
    <div class="field"><label>Port</label><input type="number" name="dest_port" value="{{ dest_port }}" style="max-width:8rem"></div>
    <div class="field"><label>Path</label><input type="text" name="dest_path" value="{{ dest_path }}" placeholder="/backup"></div>
    <div class="field"><label>Username</label><input type="text" name="dest_user" value="{{ dest_user }}"></div>
    <div class="field">
      <label>Encryption</label>
      <select name="encryption">
        <option value="none" {{ 'selected' if not encryption_enabled }}>Off (not recommended)</option>
        <option value="generate" {{ 'selected' if encryption_enabled }}>Generate a key for me / keep my current key</option>
        <option value="own">Provide my own age private key (only used the first time -- has no effect if a key is already set)</option>
      </select>
    </div>
    <div class="field">
      <label>Own age private key <span class="muted">(only used if "Provide my own" is selected above)</span></label>
      <textarea name="own_age_private_key" rows="2" placeholder="AGE-SECRET-KEY-1..." autocomplete="off"></textarea>
    </div>
    <button type="submit">Save</button>
  </form>
  {% else %}
  <p class="muted">Only a team owner can change this -- redirecting backups
  changes where a full, decrypted-at-the-source copy of this site ends up.</p>
  {% endif %}
</div>

<div class="card">
  <h3 style="margin-top:0">Your transport key</h3>
  <p class="muted">Generated for you the first time a destination is saved above -- install this
  <strong>public</strong> key as an authorized key on your own SFTP destination (never the private
  half, which never leaves your host). Safe to show/reuse any time.</p>
  {% if ssh_public_key %}
  <pre style="white-space:pre-wrap">{{ ssh_public_key }}</pre>
  {% else %}
  <p class="muted">Not generated yet -- save a destination host above first.</p>
  {% endif %}
</div>

<div class="card">
  <h3 style="margin-top:0">Back up now</h3>
  <p class="muted">Pushes to both the operator's destination and yours (if configured), rather than waiting for the next scheduled run.</p>
  <form method="post">
    <input type="hidden" name="action" value="backup_now">
    <button type="submit">Back up now</button>
  </form>
</div>

<div class="card">
  <h3 style="margin-top:0">Snapshots (your destination)</h3>
  <table>
    <thead><tr><th>Created</th><th>Size</th><th>Encrypted</th><th></th></tr></thead>
    <tbody>
    {% for s in recent_backups %}
    <tr>
      <td>{{ s.created_at|humanize_ts }}</td>
      <td>{{ s.size_mb }}</td>
      <td>{{ 'yes' if s.encrypted else 'no' }}</td>
      <td style="text-align:right">
        {% if is_owner %}
        <form class="inline" method="post"
              onsubmit="return confirm('Restore this snapshot? This overwrites this site\\'s current webroot, mail, database, and settings. Your security keys are not affected.');">
          <input type="hidden" name="action" value="restore">
          <input type="hidden" name="snapshot_name" value="{{ s.snapshot_name }}">
          <button type="submit">Restore</button>
        </form>
        {% else %}
        <span class="muted">owner-only</span>
        {% endif %}
      </td>
    </tr>
    {% else %}
    <tr><td colspan="4" class="muted">No backups to your own destination yet.</td></tr>
    {% endfor %}
    </tbody>
  </table>
</div>
"""

LOGS_PAGE = """
<h2>Logs</h2>
<p class="muted">Last {{ tail_lines }} lines of each. Reload the page to refresh.</p>
{% for fname, label, content in logs %}
  <h3>{{ label }}</h3>
  <div class="card" style="padding:0">
  {% if content is none %}
    <p class="muted" style="padding:1.25rem 1.5rem;margin:0">No entries yet.</p>
  {% else %}
    <pre style="margin:0; border:none; border-radius:var(--radius);">{{ content }}</pre>
  {% endif %}
  </div>
{% endfor %}
"""

SECURITY_KEY_PAGE = """
<h2>My account</h2>
<div class="card">
  <h3 style="margin-top:0">Password</h3>
  <p class="muted">Change your own login password (username stays <code>{{ username }}</code>).</p>
  {% if saved %}<div class="flash">Password updated.</div>{% endif %}
  {% if error %}<div class="flash error">{{ error }}</div>{% endif %}
  <form method="post" autocomplete="off">
    <div class="field"><label>Current password</label><input type="password" name="current_password" autocomplete="current-password" required></div>
    <div class="field"><label>New password</label><input type="password" name="new_password" autocomplete="new-password" required></div>
    <div class="field"><label>Confirm new password</label><input type="password" name="confirm_password" autocomplete="new-password" required></div>
    <button type="submit">Update password</button>
  </form>
</div>

<h2>Security key (WebAuthn)</h2>
<p class="muted">Only works over the real public hostname
(<code>https://{{ rp_id }}</code>) -- WebAuthn ties a key to the exact
origin it was registered on, and that has to be a real domain over
HTTPS, not the management-network path.
{% if keys %}Logging in currently requires one of these keys as a second
factor.{% else %}No key registered yet -- login is password-only until
you add one.{% endif %}</p>
{% if keys|length == 1 %}
<div class="warn">Only one security key registered. If you lose it,
you'll be locked out with no self-service recovery -- only your
operator can clear it for you, from their admin panel. Register a
backup key now.</div>
{% endif %}
<div class="card">
  <div id="webauthn-error" class="flash error" style="display:none"></div>
  <table>
    <thead><tr><th>Name</th><th>Added</th><th></th></tr></thead>
    <tbody>
    {% for k in keys %}
    <tr>
      <td>{{ k.name }}</td>
      <td class="muted">{{ k.added_at|humanize_ts }}</td>
      <td style="text-align:right">
        <form class="inline" method="post" action="/webauthn/remove"
              onsubmit="return confirm('Remove security key ' + '{{ k.name }}' + '?');">
          <input type="hidden" name="name" value="{{ k.name }}">
          <button class="danger" type="submit">Remove</button>
        </form>
      </td>
    </tr>
    {% else %}
    <tr><td colspan="3" class="muted">none registered</td></tr>
    {% endfor %}
    </tbody>
  </table>
  <div class="actions" style="margin-top:1.25rem">
    <input id="key-name" type="text" placeholder="name this key, e.g. YubiKey 5C" style="max-width:260px">
    <button id="register-btn">Register new security key</button>
  </div>
</div>
<script>
  document.getElementById('register-btn').addEventListener('click', async () => {
    const errEl = document.getElementById('webauthn-error');
    errEl.style.display = 'none';
    const name = document.getElementById('key-name').value.trim();
    if (!name) { errEl.textContent = 'Name the key first.'; errEl.style.display = 'block'; return; }
    try {
      const beginResp = await fetch('/webauthn/register/begin', {method: 'POST', headers: {'X-CSRF-Token': '{{ csrf_token() }}'}});
      if (!beginResp.ok) throw new Error((await beginResp.json()).error || 'Could not start registration.');
      const options = (await beginResp.json()).publicKey;
      const credential = await navigator.credentials.create({
        publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options)
      });
      const completeResp = await fetch('/webauthn/register/complete', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': '{{ csrf_token() }}'},
        body: JSON.stringify({name: name, credential: credential.toJSON()})
      });
      const result = await completeResp.json();
      if (!completeResp.ok || !result.ok) throw new Error(result.error || 'Registration failed.');
      window.location.reload();
    } catch (e) {
      errEl.textContent = e.message || String(e);
      errEl.style.display = 'block';
    }
  });
</script>

<h2>Authenticator app (TOTP)</h2>
<p class="muted">An alternative second factor to a security key above -- Google
Authenticator, Authy, 1Password, or anything else that reads a standard
<code>otpauth://</code> QR code. Either this or a security key (or both) satisfies
login's second-factor check; you don't need both.</p>
<div class="card">
  {% if totp_enabled %}
  <p>Enabled since <span class="muted">{{ totp_added_at|humanize_ts }}</span>.</p>
  <form method="post" action="/totp/remove"
        onsubmit="return confirm('Remove your authenticator app? You will need to set it up again to use it as a second factor.');">
    <button class="danger" type="submit">Remove authenticator app</button>
  </form>
  {% else %}
  <p class="muted">Not set up.</p>
  <a href="/totp/setup"><button type="button">Set up authenticator app</button></a>
  {% endif %}
</div>
"""

TOTP_SETUP_PAGE = """
<h2 style="margin-bottom:1.25rem">Set up an authenticator app</h2>
<div class="card">
  <p class="muted">Scan this with Google Authenticator, Authy, 1Password, or
  anything else that reads a standard TOTP QR code, then enter the 6-digit code
  it shows to confirm.</p>
  {% if error %}<div class="flash error">{{ error }}</div>{% endif %}
  <div class="qr-code" style="max-width:220px;margin:0 auto 1rem">{{ qr_svg|safe }}</div>
  <p class="muted" style="text-align:center">Can't scan? Enter this key manually: <code>{{ secret }}</code></p>
  <form method="post" autocomplete="off" style="max-width:280px;margin:0 auto">
    <div class="field"><label>6-digit code</label>
      <input name="code" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" placeholder="123456" autofocus required></div>
    <button type="submit" style="width:100%">Confirm</button>
  </form>
</div>
"""

API_TOKENS_PAGE = """
<h2 style="margin-bottom:1.25rem">API &amp; MCP access</h2>
<p class="muted">Bearer tokens for programmatic/AI-agent access to this site's own
self-service operations -- mailboxes, PHP function toggles, redirects, backups,
and the rest of what this panel exposes, deliberately excluding Files and Database
(the same two highest-trust actions already gated separately elsewhere in this
panel). Anyone holding a token can act as an owner through these two surfaces;
treat one like a password, not like a bookmark.</p>
{% if error %}<div class="flash error">{{ error }}</div>{% endif %}
{% if new_token %}
<div class="flash">
  <strong>New token -- shown once, copy it now:</strong><br>
  <code style="word-break:break-all">{{ new_token }}</code>
  <p style="margin-bottom:0">Use it right away -- note this is the platform's shared
  host, not your own domain:</p>
  <pre style="margin:0.4rem 0 0">curl -H "Authorization: Bearer {{ new_token }}" https://{{ platform_api_host }}/api/v1/self</pre>
</div>
{% endif %}

<div class="card">
  <h3 style="margin-top:0">Platform access</h3>
  {% if not access.api_allowed and not access.mcp_allowed %}
  <p class="muted">Your host hasn't allowed API or MCP access for this site yet --
  contact them if you'd like to use either. Nothing below will work until they do,
  even after turning it on here.</p>
  {% else %}
  <p class="muted">Your host allows the surface(s) marked "Allowed by your host"
  below -- you still need to turn each one on yourself before it actually works.</p>
  {% endif %}
  <table class="kv">
    <tr>
      <td>REST API</td>
      <td>
        {% if access.api_allowed %}<span class="badge badge-ok">Allowed by your host</span>{% else %}<span class="muted">Not allowed by your host</span>{% endif %}
        {% if access.api_allowed %}
        &middot;
        {% if access.api_enabled %}<span class="badge badge-ok">On</span>{% else %}<span class="muted">Off</span>{% endif %}
        <form class="inline" method="post"
              onsubmit="return confirm('{{ 'Turn off the REST API for this site?' if access.api_enabled else 'Turn on the REST API for this site?' }}');">
          <input type="hidden" name="action" value="{{ 'disable_api' if access.api_enabled else 'enable_api' }}">
          <button type="submit" class="{{ 'danger' if access.api_enabled else '' }}">{{ 'Turn off' if access.api_enabled else 'Turn on' }}</button>
        </form>
        {% endif %}
      </td>
    </tr>
    <tr>
      <td>MCP server</td>
      <td>
        {% if access.mcp_allowed %}<span class="badge badge-ok">Allowed by your host</span>{% else %}<span class="muted">Not allowed by your host</span>{% endif %}
        {% if access.mcp_allowed %}
        &middot;
        {% if access.mcp_enabled %}<span class="badge badge-ok">On</span>{% else %}<span class="muted">Off</span>{% endif %}
        <form class="inline" method="post"
              onsubmit="return confirm('{{ 'Turn off MCP for this site?' if access.mcp_enabled else 'Turn on MCP for this site?' }}');">
          <input type="hidden" name="action" value="{{ 'disable_mcp' if access.mcp_enabled else 'enable_mcp' }}">
          <button type="submit" class="{{ 'danger' if access.mcp_enabled else '' }}">{{ 'Turn off' if access.mcp_enabled else 'Turn on' }}</button>
        </form>
        {% endif %}
      </td>
    </tr>
  </table>
</div>

<div class="card">
  <h3 style="margin-top:0">Existing tokens</h3>
  <table>
    <thead><tr><th>Label</th><th>Created</th><th></th></tr></thead>
    <tbody>
    {% for t in tokens %}
    <tr>
      <td>{{ t.label }}</td>
      <td class="muted">{{ t.created_at|humanize_ts }}</td>
      <td style="text-align:right">
        <form class="inline" method="post" onsubmit="return confirm('Revoke ' + '{{ t.label }}' + '? Anything using it will stop working immediately.');">
          <input type="hidden" name="action" value="revoke">
          <input type="hidden" name="token_id" value="{{ t.token_id }}">
          <button class="danger" type="submit">Revoke</button>
        </form>
      </td>
    </tr>
    {% else %}
    <tr><td colspan="3" class="muted">none yet</td></tr>
    {% endfor %}
    </tbody>
  </table>
</div>
<div class="card">
  <h3 style="margin-top:0">Create a new token</h3>
  <form method="post">
    <input type="hidden" name="action" value="create">
    <div class="field"><label>Label</label>
      <input type="text" name="label" placeholder="e.g. laptop script, ops agent" required></div>
    <button type="submit">Create token</button>
  </form>
</div>
"""

AUDIT_PAGE = """
<h2>Audit log</h2>
<p class="muted">
  Every action taken in this panel -- by you, by anyone on your team, and by
  your host when they use their operator tools on your account. Logins
  (including failed ones) are recorded too, so an attempt to get in that
  wasn't you shows up here.
</p>
<div class="card">
  <p style="margin-top:0">
    {% if chain_ok %}<span class="badge badge-ok">Chain intact</span>
    <span class="muted">{{ chain_count }} entries verified -- nothing has been edited or removed.</span>
    {% else %}<span class="badge badge-warn">Chain broken</span>
    <span class="muted">Entries after #{{ chain_count }} don't match. Contact your host.</span>
    {% endif %}
  </p>
  <p class="muted" style="margin-bottom:0">
    Each entry is chained to the one before it, so editing or deleting past
    entries is detectable. Passwords, one-time codes, SQL you run, and file
    contents are never recorded -- only that the action happened.
  </p>
</div>
<form method="get" class="table-filter">
  <label class="sr-only" for="f-action">Filter by action</label>
  <input type="search" id="f-action" name="action" value="{{ action_filter }}" placeholder="Filter by action&hellip;" autocomplete="off">
  <label class="sr-only" for="f-actor">Filter by user</label>
  <input type="search" id="f-actor" name="actor" value="{{ actor_filter }}" placeholder="Filter by user&hellip;" autocomplete="off">
  <button type="submit">Filter</button>
  {% if action_filter or actor_filter %}<a href="/audit" class="muted">clear</a>{% endif %}
</form>
<div class="card">
  <table>
    <thead><tr><th>When</th><th>User</th><th>Action</th><th>From</th><th>Details</th></tr></thead>
    <tbody>
    {% for e in entries %}
    <tr>
      <td style="white-space:nowrap">{{ e.ts|humanize_ts }}</td>
      <td>{{ e.actor }}</td>
      <td><code>{{ e.action }}</code>{% if e.status and e.status >= 400 %} <span class="badge badge-warn">{{ e.status }}</span>{% endif %}</td>
      <td class="muted">{{ e.ip or '--' }}</td>
      <td style="word-break:break-word">
        {%- if e.detail -%}
          {%- for k, v in e.detail.items() %}<div class="muted"><code>{{ k }}</code>: {{ v }}</div>{% endfor -%}
        {%- else -%}<span class="muted">&mdash;</span>{%- endif -%}
      </td>
    </tr>
    {% else %}
    <tr><td colspan="5" class="muted">No matching entries.</td></tr>
    {% endfor %}
    </tbody>
  </table>
</div>
"""


TEAM_PAGE = """
<h2>Team</h2>
<p class="muted">
  <strong>Owners</strong> can manage the team, change the backup
  destination and restore a backup, and use the SQL console. <strong>Members</strong>
  can do everything else in this panel (PHP functions, mailboxes, redirects,
  and so on) but not those.
  {% if not is_owner %}You're a member -- this page is read-only for you;
  ask an owner below for anything that needs changing.{% endif %}
</p>
{% if error %}<div class="flash error">{{ error }}</div>{% endif %}
{% if generated_password %}<div class="flash">Password for <code>{{ generated_username }}</code> (shown once): <code>{{ generated_password }}</code></div>{% endif %}
<div class="card">
  <table>
    <thead><tr><th>Username</th><th>Role</th><th>Created</th><th>Security keys</th><th>Authenticator app</th>{% if is_owner %}<th></th>{% endif %}</tr></thead>
    <tbody>
    {% set owner_count = users|selectattr('role', 'equalto', 'owner')|list|length %}
    {% for u in users %}
    <tr>
      <td>{{ u.username }}{% if u.username == username %} <span class="muted">(you)</span>{% endif %}</td>
      <td>
        {% if not is_owner or (u.role == 'owner' and owner_count <= 1) %}
        {{ 'Owner' if u.role == 'owner' else 'Member' }}{% if is_owner and u.role == 'owner' and owner_count <= 1 %} <span class="muted">(last one -- can't change)</span>{% endif %}
        {% else %}
        <form class="inline" method="post"
              onsubmit="return confirm('Change ' + '{{ u.username }}' + '\\'s role to ' + this.role.value + '?');">
          <input type="hidden" name="action" value="set-role">
          <input type="hidden" name="target" value="{{ u.username }}">
          <select name="role" onchange="this.form.submit()">
            <option value="owner" {% if u.role == 'owner' %}selected{% endif %}>Owner</option>
            <option value="member" {% if u.role == 'member' %}selected{% endif %}>Member</option>
          </select>
        </form>
        {% endif %}
      </td>
      <td class="muted">{{ u.created_at|humanize_ts }}</td>
      <td>{{ key_counts[u.username] }}</td>
      <td>{{ 'yes' if totp_status[u.username] else '—' }}</td>
      {% if is_owner %}
      <td style="text-align:right">
        <form class="inline" method="post"
              onsubmit="return confirm('Generate a new password for ' + '{{ u.username }}' + '? Their current password stops working immediately.');">
          <input type="hidden" name="action" value="reset-password">
          <input type="hidden" name="target" value="{{ u.username }}">
          <button class="btn-ghost" type="submit">Reset password</button>
        </form>
        {% if users|length <= 1 %}
        <span class="muted">last user -- cannot remove</span>
        {% elif u.role == 'owner' and owner_count <= 1 %}
        <span class="muted">last owner -- cannot remove</span>
        {% else %}
        <form class="inline" method="post"
              onsubmit="return confirm('Remove ' + '{{ u.username }}' + '? They will no longer be able to log in.');">
          <input type="hidden" name="action" value="remove">
          <input type="hidden" name="target" value="{{ u.username }}">
          <button class="danger" type="submit">Remove</button>
        </form>
        {% endif %}
      </td>
      {% endif %}
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% if is_owner %}
<div class="card">
  <h3 style="margin-top:0">Add a team member</h3>
  <p class="muted">Generates a password shown once here -- pass it to them directly, they should change it (and register their own security key) on first login.</p>
  <form method="post">
    <input type="hidden" name="action" value="add">
    <div class="actions">
      <label class="sr-only" for="new-team-username">Username</label>
      <input id="new-team-username" type="text" name="target" placeholder="username" required style="max-width:220px">
      <label class="sr-only" for="new-team-role">Role</label>
      <select id="new-team-role" name="role">
        <option value="member" selected>Member</option>
        <option value="owner">Owner</option>
      </select>
      <button type="submit">Add</button>
    </div>
  </form>
</div>
{% endif %}
"""


def humanize_ts(value):
    """Jinja filter -- see vhsp_ctl/web.py's identical helper for why
    this exists (raw microsecond ISO timestamps shown everywhere, found
    during a real usability pass). Falls back to the original value
    unchanged on anything that doesn't parse."""
    if not value:
        return value
    try:
        dt = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return value
    return dt.strftime("%Y-%m-%d %H:%M UTC")


app.jinja_env.filters["humanize_ts"] = humanize_ts


def render(body_template, **ctx):
    body = render_template_string(body_template, **ctx)
    usage = get_disk_usage()
    quota_limit = get_quota_limit()
    quota_percent = min(100, round(usage["total"] / quota_limit * 100)) if quota_limit else 0
    quota_status = "danger" if quota_percent >= 100 else "warn" if quota_percent >= 80 else "ok"
    return render_template_string(
        LAYOUT, body=body, domain=TENANT_DOMAIN,
        usage_total_mb=format_mb(usage["total"]), quota_limit_mb=format_mb(quota_limit),
        quota_percent=quota_percent, quota_status=quota_status,
        maintenance_enabled=MAINTENANCE_MARKER_FILE.exists(),
        username=session.get("username", ""),
        is_owner=user_role(session.get("username", "")) == "owner",
        has_2fa=_has_2fa(session.get("username", "")),
        # Read from the grant file, not the session, so the banner shows
        # to the TENANT while their host is in here -- the whole point.
        operator_access=operator_access_state(),
        viewing_as_operator=session.get("username", "").startswith(OPERATOR_ACTOR_PREFIX),
    )


def read_enabled() -> set[str]:
    if not ENABLED_FILE.exists():
        return set()
    return {line.strip() for line in ENABLED_FILE.read_text().splitlines() if line.strip()}


def tail(path: Path, n: int) -> str | None:
    if not path.exists():
        return None
    lines = path.read_text(errors="replace").splitlines()
    return "\n".join(lines[-n:]) if lines else None


@app.route("/", methods=["GET"])
@require_login
def index():
    usage = get_disk_usage()
    quota_limit = get_quota_limit()
    quota_percent = min(100, round(usage["total"] / quota_limit * 100)) if quota_limit else 0
    # db_password: owner-only, same gate as /database's own SQL console
    # (require_role("owner") below) -- showing it here to every member
    # would make that gate pointless, since the password grants identical
    # access to what the console does. Host/name/user stay visible to
    # everyone (a member still needs to know what their own app is
    # already configured to connect to).
    is_owner = user_role(session["username"]) == "owner"
    return render(
        OVERVIEW_PAGE,
        domain=TENANT_DOMAIN,
        ssh_port=SSH_PORT, sftp_user=SFTP_USER,
        db_host=DB_HOST, db_name=DB_NAME, db_user=DB_USER,
        db_password=DB_PASSWORD if is_owner else None,
        web_mb=format_mb(usage["web"]), db_mb=format_mb(usage["db"]), mail_mb=format_mb(usage["mail"]),
        usage_total_mb=format_mb(usage["total"]), quota_limit_mb=format_mb(quota_limit),
        quota_percent=quota_percent,
    )


@app.route("/php-functions", methods=["GET", "POST"])
@require_login
@require_2fa
def php_functions():
    saved = False
    if request.method == "POST":
        submitted = set(request.form.getlist("fn"))
        # Only ever write names we actually know about -- never pass
        # arbitrary POST data straight through to the file the web
        # container's shell script parses.
        valid = {fn for fn, _ in FUNCTIONS}
        ENABLED_FILE.parent.mkdir(parents=True, exist_ok=True)
        ENABLED_FILE.write_text("\n".join(sorted(submitted & valid)) + "\n")
        saved = True
    return render(PAGE, functions=FUNCTIONS, enabled=read_enabled(), saved=saved)


@app.route("/fallback", methods=["GET", "POST"])
@require_login
def fallback():
    saved = False
    if request.method == "POST":
        # Checkbox absent from form data means "unchecked" -- i.e. opt out.
        if "enabled" in request.form:
            FALLBACK_MARKER.unlink(missing_ok=True)
        else:
            WEBROOT_DIR.mkdir(parents=True, exist_ok=True)
            FALLBACK_MARKER.touch()
        saved = True
    return render(FALLBACK_PAGE, enabled=not FALLBACK_MARKER.exists(), saved=saved)


@app.route("/auth", methods=["GET", "POST"])
@require_login
def auth():
    saved = False
    error = None
    lines = BASIC_AUTH_FILE.read_text().splitlines() if BASIC_AUTH_FILE.exists() else []
    current_user = lines[0].split(":", 1)[0] if lines and ":" in lines[0] else ""

    if request.method == "POST":
        action = request.form.get("action")
        if action == "disable":
            BASIC_AUTH_FILE.write_text("")
            current_user = ""
            saved = True
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if not username or not USERNAME_RE.match(username):
                error = "Username must be non-empty and contain only letters, digits, '.', '_', '-'."
            elif not password:
                error = "Enter a password (or use Disable protection instead)."
            else:
                htpasswd_hash = apr_md5_crypt.hash(password)
                BASIC_AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
                BASIC_AUTH_FILE.write_text(f"{username}:{htpasswd_hash}\n")
                current_user = username
                saved = True

    return render(
        BASIC_AUTH_PAGE,
        error=error,
        saved=saved,
        current_user=current_user,
        currently_enabled=bool(current_user),
    )


@app.route("/error-pages", methods=["GET", "POST"])
@require_login
def error_pages():
    return _textarea_page(
        ERROR_PAGES_PAGE,
        ERROR_PAGES_FILE,
        validate_error_page_line,
    )


@app.route("/redirects", methods=["GET", "POST"])
@require_login
@require_2fa
def redirects():
    return _textarea_page(
        REDIRECTS_PAGE,
        REDIRECTS_FILE,
        validate_redirect_line,
    )


@app.route("/noexec-dirs", methods=["GET", "POST"])
@require_login
@require_2fa
def noexec_dirs():
    return _textarea_page(
        NOEXEC_DIRS_PAGE,
        NOEXEC_DIRS_FILE,
        validate_noexec_dir_line,
    )


@app.route("/ip-acl", methods=["GET", "POST"])
@require_login
@require_2fa
def ip_acl():
    saved = False
    error = None
    existing = IP_ACL_FILE.read_text().splitlines() if IP_ACL_FILE.exists() else []
    mode = existing[0] if existing and existing[0] in ("allow", "deny") else ""
    current = "\n".join(existing[1:]) if mode else "\n".join(existing)

    if request.method == "POST":
        mode = request.form.get("mode", "")
        current = request.form.get("lines", "")
        if mode not in ("", "allow", "deny"):
            error = "Invalid mode."
        else:
            entries = [ln.strip() for ln in current.splitlines() if ln.strip()]
            bad = None
            for ln in entries:
                try:
                    ipaddress.ip_network(ln, strict=False)
                except ValueError:
                    bad = ln
                    break
            if bad:
                error = f"Not a valid IP or CIDR: {bad!r}"
            elif mode and not entries:
                error = "Add at least one IP/CIDR, or choose Disabled."
            else:
                IP_ACL_FILE.parent.mkdir(parents=True, exist_ok=True)
                if mode:
                    IP_ACL_FILE.write_text(mode + "\n" + "\n".join(entries) + "\n")
                else:
                    IP_ACL_FILE.write_text("")
                saved = True

    return render(IP_ACL_PAGE, error=error, saved=saved, mode=mode, current=current, your_ip=request.remote_addr)


@app.route("/fail2ban-allowlist", methods=["GET", "POST"])
@require_login
@require_2fa
def fail2ban_allowlist_view():
    saved = False
    error = None
    current = FAIL2BAN_ALLOWLIST_FILE.read_text() if FAIL2BAN_ALLOWLIST_FILE.exists() else ""

    if request.method == "POST":
        current = request.form.get("lines", "")
        entries = [ln.strip() for ln in current.splitlines() if ln.strip()]
        bad = None
        for ln in entries:
            try:
                ipaddress.ip_network(ln, strict=False)
            except ValueError:
                bad = ln
                break
        if bad:
            error = f"Not a valid IP or CIDR: {bad!r}"
        else:
            FAIL2BAN_ALLOWLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
            FAIL2BAN_ALLOWLIST_FILE.write_text("\n".join(entries) + "\n" if entries else "")
            saved = True

    return render(FAIL2BAN_ALLOWLIST_PAGE, error=error, saved=saved, current=current)


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


def _textarea_page(template: str, data_file: Path, validate_line):
    saved = False
    error = None
    current = data_file.read_text() if data_file.exists() else ""

    if request.method == "POST":
        current = request.form.get("lines", "")
        raw_lines = [ln.strip() for ln in current.splitlines() if ln.strip()]
        cleaned = []
        for ln in raw_lines:
            parts = ln.split(None, 1)
            problem = validate_line(parts)
            if problem:
                error = f"Line {ln!r}: {problem}"
                break
            cleaned.append(" ".join(parts))
        if not error:
            data_file.parent.mkdir(parents=True, exist_ok=True)
            data_file.write_text("\n".join(cleaned) + ("\n" if cleaned else ""))
            saved = True

    return render(template, error=error, saved=saved, current=current)


# Each mailbox is {"hash": <SHA512-CRYPT>, "quota_bytes": int | None}.
# quota_bytes None means unlimited -- a per-mailbox limit independent of
# and additional to the tenant-wide combined quota (get_quota_limit()
# above), enforced for real by Dovecot at delivery time (see
# images/mail/entrypoint.sh's quota plugin), unlike the tenant-wide one
# which is soft/monitor-only. Whatever a mailbox actually uses still
# counts toward the tenant-wide total either way -- get_disk_usage()'s
# `du` over the whole mail directory doesn't care about per-mailbox
# limits.

def read_mailboxes() -> dict[str, dict]:
    if not MAILBOXES_FILE.exists():
        return {}
    boxes = {}
    for line in MAILBOXES_FILE.read_text().splitlines():
        if ":" not in line:
            continue
        parts = line.split(":", 2)
        user, hash_ = parts[0], parts[1]
        quota_str = parts[2] if len(parts) > 2 else ""
        if user:
            boxes[user] = {"hash": hash_, "quota_bytes": int(quota_str) if quota_str.isdigit() and int(quota_str) > 0 else None}
    return boxes


def write_mailboxes(boxes: dict[str, dict]) -> None:
    MAILBOXES_FILE.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for u, b in boxes.items():
        quota_str = str(b["quota_bytes"]) if b.get("quota_bytes") else ""
        lines.append(f"{u}:{b['hash']}:{quota_str}\n")
    MAILBOXES_FILE.write_text("".join(lines))


@app.route("/email", methods=["GET", "POST"])
@require_login
@require_2fa
def email():
    saved = False
    error = None
    boxes = read_mailboxes()

    if request.method == "POST":
        action = request.form.get("action")
        user = request.form.get("user", "").strip()
        password = request.form.get("password", "")

        # Resetting a mailbox's password (postmaster@ included) or
        # deleting one is a bigger prize than it looks -- email is the
        # recovery path into most of what a tenant owns outside this
        # platform too, so a member (not just an owner) being able to
        # take over postmaster@ or delete an address out from under
        # someone is a real escalation, unlike routine day-to-day
        # provisioning (add/quota), which stays available to members.
        # Same action-level owner gate as /backup's save_settings/restore.
        if action in ("reset", "delete") and user_role(session["username"]) != "owner":
            abort(403)

        if action == "add":
            if not user or not USERNAME_RE.match(user):
                error = "Username must be non-empty and contain only letters, digits, '.', '_', '-'."
            elif user in boxes:
                error = f"{user}@{TENANT_DOMAIN} already exists."
            elif not password:
                error = "Enter a password."
            else:
                boxes[user] = {"hash": sha512_crypt.hash(password), "quota_bytes": None}
                write_mailboxes(boxes)
                saved = True
        elif action == "reset":
            if user not in boxes:
                error = f"No such mailbox: {user}@{TENANT_DOMAIN}."
            elif not password:
                error = "Enter a new password."
            else:
                boxes[user]["hash"] = sha512_crypt.hash(password)
                write_mailboxes(boxes)
                saved = True
        elif action == "delete":
            if user == POSTMASTER:
                error = "postmaster can't be deleted -- every domain must accept mail for it."
            elif user not in boxes:
                error = f"No such mailbox: {user}@{TENANT_DOMAIN}."
            else:
                del boxes[user]
                write_mailboxes(boxes)
                saved = True
        elif action == "quota":
            quota_mb = request.form.get("quota_mb", "").strip()
            if user not in boxes:
                error = f"No such mailbox: {user}@{TENANT_DOMAIN}."
            elif not quota_mb:
                boxes[user]["quota_bytes"] = None
                write_mailboxes(boxes)
                saved = True
            else:
                try:
                    mb = int(quota_mb)
                    if mb < 1:
                        raise ValueError
                    boxes[user]["quota_bytes"] = mb * 1024 * 1024
                    write_mailboxes(boxes)
                    saved = True
                except ValueError:
                    error = "Quota must be a whole number of MB, or blank for unlimited."

        boxes = read_mailboxes()

    dns_checked = request.args.get("check") == "1"
    dns_recs = _read_dns_records()
    if dns_checked and dns_recs:
        dns_recs = _check_dns_records_live(dns_recs)

    return render(
        EMAIL_PAGE,
        error=error,
        saved=saved,
        mailboxes=sorted(boxes, key=lambda u: (u != POSTMASTER, u)),
        boxes=boxes,
        postmaster=POSTMASTER,
        domain=TENANT_DOMAIN,
        dns_records=dns_recs,
        dns_checked=dns_checked,
        is_owner=user_role(session["username"]) == "owner",
    )


@app.route("/files", methods=["GET", "POST"])
@require_role("owner")  # write access to the live webroot -- equivalent to full site takeover, same tier as /database
@require_2fa  # deliberate carrot for 2FA adoption, not a generic floor -- see require_2fa's own docstring
def files():
    error = None
    rel_path = request.args.get("path", "") if request.method == "GET" else request.form.get("path", "")

    if request.method == "POST":
        action = request.form.get("action")
        try:
            if action == "upload":
                directory = _safe_webroot_path(rel_path)
                if not directory.is_dir():
                    raise FilesError("no such directory")
                uploads = request.files.getlist("uploads")
                if not uploads or all(f.filename == "" for f in uploads):
                    raise FilesError("choose at least one file")
                for f in uploads:
                    if not f.filename:
                        continue
                    name = secure_filename(f.filename)
                    if not name:
                        raise FilesError(f"can't accept the filename {f.filename!r}")
                    dest = _safe_webroot_path(str((Path(rel_path) / name)))
                    if _is_vhsp_internal(dest):
                        raise FilesError("that name is reserved")
                    f.save(dest)
            elif action == "delete":
                target = _safe_webroot_path(request.form.get("target", ""))
                if target == WEBROOT_DIR.resolve():
                    raise FilesError("can't delete the webroot itself")
                if _is_vhsp_internal(target):
                    raise FilesError("that file is managed by the 404 handling page, not here")
                if not target.exists():
                    raise FilesError("no such file or directory")
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()
            elif action == "move":
                source = _safe_webroot_path(request.form.get("target", ""))
                dest_rel = request.form.get("dest", "")
                if source == WEBROOT_DIR.resolve():
                    raise FilesError("can't move the webroot itself")
                if _is_vhsp_internal(source):
                    raise FilesError("that file is managed by the 404 handling page, not here")
                if not source.exists():
                    raise FilesError("no such file or directory")
                dest = _safe_webroot_path(dest_rel)
                if dest.exists():
                    raise FilesError(f"{dest_rel} already exists")
                if _is_vhsp_internal(dest):
                    raise FilesError("that name is reserved")
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(source), str(dest))
            else:
                raise FilesError("unknown action")
        except FilesError as e:
            error = str(e)
        except OSError as e:
            error = f"filesystem error: {e.strerror or e}"

    try:
        directory, entries = list_webroot_dir(rel_path)
    except FilesError:
        rel_path = ""
        directory, entries = list_webroot_dir("")
        if not error:
            error = "that directory doesn't exist -- back to the webroot root"

    root = WEBROOT_DIR.resolve()
    current_rel = "" if directory == root else str(directory.relative_to(root))
    crumbs = []
    if current_rel:
        parts = current_rel.split("/")
        for i, part in enumerate(parts):
            crumbs.append({"name": part, "rel_path": "/".join(parts[: i + 1])})

    return render(
        FILES_PAGE, error=error, entries=entries, current_rel=current_rel, crumbs=crumbs,
    )


@app.route("/files/edit", methods=["GET", "POST"])
@require_role("owner")
@require_2fa
def files_edit():
    rel_path = request.values.get("path", "")
    error = None
    saved = False
    try:
        target = _safe_webroot_path(rel_path)
        if _is_vhsp_internal(target):
            raise FilesError("that file is managed by the 404 handling page, not here")
        if not target.is_file():
            raise FilesError("no such file")
        if not _is_text_file(target):
            raise FilesError("this doesn't look like a text file -- download it instead")
        if request.method == "POST":
            content = request.form.get("content", "")
            if len(content.encode("utf-8")) > FILES_MAX_EDIT_BYTES:
                raise FilesError(f"too large to save from here (over {_human_size(FILES_MAX_EDIT_BYTES)})")
            target.write_text(content)
            saved = True
        size = target.stat().st_size
        if size > FILES_MAX_EDIT_BYTES:
            raise FilesError(f"too large to edit here (over {_human_size(FILES_MAX_EDIT_BYTES)}) -- download instead")
        content = target.read_text(errors="replace")
    except FilesError as e:
        return render(FILES_EDIT_ERROR_PAGE, error=str(e), rel_path=rel_path)

    return render(FILES_EDIT_PAGE, rel_path=rel_path, content=content, saved=saved, error=error)


@app.route("/files/download")
@require_role("owner")
@require_2fa
def files_download():
    try:
        target = _safe_webroot_path(request.args.get("path", ""))
    except FilesError:
        abort(404)
    if _is_vhsp_internal(target) or not target.is_file():
        abort(404)
    return send_file(target, as_attachment=True, download_name=target.name)


@app.route("/database", methods=["GET", "POST"])
@require_role("owner")  # arbitrary-SQL console -- equivalent to full DB access regardless of role
@require_2fa
def database():
    error = None
    columns = rows = rowcount = None
    ran = False
    sql = request.form.get("sql", "") if request.method == "POST" else ""
    if request.method == "POST" and sql.strip():
        ran = True
        try:
            conn = pymysql.connect(
                host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD,
                database=DB_NAME, connect_timeout=5, autocommit=True,
            )
            try:
                with conn.cursor() as cur:
                    cur.execute(sql)
                    if cur.description:
                        columns = [d[0] for d in cur.description]
                        rows = cur.fetchall()
                    rowcount = cur.rowcount
            finally:
                conn.close()
        except Exception as e:
            error = str(e)
    return render(
        DATABASE_PAGE,
        error=error, sql=sql, columns=columns, rows=rows, rowcount=rowcount, ran=ran,
        db_user=DB_USER, db_name=DB_NAME, db_host=DB_HOST,
    )


def _read_backup_status() -> dict:
    if not BACKUP_STATUS_FILE.exists():
        return {}
    try:
        return json.loads(BACKUP_STATUS_FILE.read_text())
    except json.JSONDecodeError:
        return {}


def _read_dns_records() -> list[dict]:
    if not DNS_RECORDS_FILE.exists():
        return []
    try:
        return json.loads(DNS_RECORDS_FILE.read_text())
    except json.JSONDecodeError:
        return []


def _is_dns_record_live(kind: str, name: str, expected_value: str) -> bool:
    """Verbatim duplicate of vhsp_ctl.dns_records.is_record_live -- this
    container has no access to that package (no docker/host access at
    all, see this file's own top-of-file trust-boundary note), so it's a
    standalone copy, not an import. @1.1.1.1, not the ambient resolver:
    this container's own mail sibling (same GATEWAY_NETWORK) has a
    network alias equal to this tenant's bare domain, so Docker's
    embedded DNS (127.0.0.11, the default here) shadows the REAL public A
    record for it with the mail container's own internal IP -- verified
    directly. TXT rows match on substring, not exact equality, same
    reasoning as the vhsp_ctl copy's own docstring."""
    try:
        result = subprocess.run(
            ["dig", "@1.1.1.1", "+short", "+time=3", "+tries=1", kind, name],
            capture_output=True, text=True, timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.warning("dns check: dig %s %s raised %r", kind, name, exc)
        return False
    if result.returncode != 0:
        logger.warning(
            "dns check: dig %s %s exited %d, stderr=%r",
            kind, name, result.returncode, result.stderr.strip(),
        )
        return False
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]

    if kind == "A":
        ok = expected_value in lines
        if not ok:
            logger.warning(
                "dns check: A %s wanted %r, dig returned %r", name, expected_value, lines,
            )
        return ok

    if kind == "MX":
        want_prio, _, want_host = expected_value.partition(" ")
        want_host = want_host.rstrip(".")
        for line in lines:
            prio, _, host = line.partition(" ")
            if prio == want_prio and host.rstrip(".") == want_host:
                return True
        logger.warning(
            "dns check: MX %s wanted %r, dig returned %r", name, expected_value, lines,
        )
        return False

    if kind == "TXT":
        for line in lines:
            segments = re.findall(r'"([^"]*)"', line)
            joined = "".join(segments) if segments else line
            if expected_value in joined:
                return True
        logger.warning(
            "dns check: TXT %s wanted %r, dig returned %r", name, expected_value, lines,
        )
        return False

    return False


def _check_dns_records_live(records: list[dict]) -> list[dict]:
    return [{**r, "ok": _is_dns_record_live(r["kind"], r["name"], r["value"])} for r in records]


@app.route("/backups", methods=["GET", "POST"])
@require_login
@require_2fa
def backups():
    saved = False
    error = None
    if request.method == "POST":
        action = request.form.get("action")
        # Changing the destination or restoring is owner-only -- unlike
        # backup_now (harmless, just enqueues an extra snapshot) these can
        # exfiltrate data (redirect the destination to somewhere the
        # attacker controls) or destroy it (restore overwrites live
        # content) -- the same blast-radius reasoning as the /database
        # and /team gates, not just "backups are sensitive" in general.
        if action in ("save_settings", "restore") and user_role(session["username"]) != "owner":
            abort(403)
        status = _read_backup_status()
        if action == "save_settings":
            req = {
                "dest_host": request.form.get("dest_host", "").strip(),
                "dest_port": request.form.get("dest_port", "").strip() or "22",
                "dest_path": request.form.get("dest_path", "").strip(),
                "dest_user": request.form.get("dest_user", "").strip(),
                "encryption": request.form.get("encryption", "none"),
                "own_age_private_key": request.form.get("own_age_private_key", "").strip(),
            }
            BACKUP_REQUEST_FILE.parent.mkdir(parents=True, exist_ok=True)
            BACKUP_REQUEST_FILE.write_text(json.dumps(req))
            saved = True
        elif action == "backup_now":
            BACKUP_NOW_MARKER.parent.mkdir(parents=True, exist_ok=True)
            BACKUP_NOW_MARKER.touch()
            saved = True
        elif action == "restore":
            snapshot_name = request.form.get("snapshot_name", "").strip()
            if not snapshot_name:
                error = "Missing snapshot."
            else:
                # _reconcile_tenant_backup_config re-applies dest_host/port/
                # path/user/encryption from THIS SAME file on every pass --
                # carrying the current settings back through here (rather
                # than just {action, restore_snapshot}) is what keeps this
                # restore request from wiping them out to blank on the next
                # ~2-minute reconciliation. "generate" is a safe no-op
                # re-submission whenever a key already exists (see
                # ensure_tenant_age_key).
                req = {
                    "dest_host": status.get("dest_host", ""),
                    "dest_port": status.get("dest_port", 22),
                    "dest_path": status.get("dest_path", ""),
                    "dest_user": status.get("dest_user", ""),
                    "encryption": "generate" if status.get("encryption_enabled") else "none",
                    "action": "restore_requested",
                    "restore_snapshot": snapshot_name,
                }
                BACKUP_REQUEST_FILE.parent.mkdir(parents=True, exist_ok=True)
                BACKUP_REQUEST_FILE.write_text(json.dumps(req))
                saved = True
        else:
            error = "Unknown action."

    status = _read_backup_status()
    recent = [
        {**b, "size_mb": format_mb(b["size_bytes"])}
        for b in status.get("recent_backups", [])
    ]
    return render(
        BACKUPS_PAGE, saved=saved, error=error,
        dest_host=status.get("dest_host", ""), dest_port=status.get("dest_port", 22),
        dest_path=status.get("dest_path", ""), dest_user=status.get("dest_user", ""),
        encryption_enabled=status.get("encryption_enabled", False),
        ssh_public_key=status.get("ssh_public_key", ""),
        age_first_reveal=status.get("age_private_key_once"),
        recent_backups=recent,
        is_owner=user_role(session["username"]) == "owner",
    )


@app.route("/logs")
@require_login
def logs():
    entries = [
        (fname, label, tail(LOGS_DIR / fname, TAIL_LINES))
        for fname, label in LOG_FILES
    ]
    return render(LOGS_PAGE, logs=entries, tail_lines=TAIL_LINES)


MANUAL_PAGE = """
<h2>Manual</h2>
<p class="muted">Every setting, option, and feature on this panel, in one place --
what each one does, when to use it, and what it doesn't do.</p>

<div class="card">
  <p class="eyebrow" style="margin-top:0">Jump to</p>
  <ul class="toc">
    <li><a href="#overview">Overview</a></li>
    <li><a href="#php-functions">PHP functions</a></li>
    <li><a href="#fallback">404 handling</a></li>
    <li><a href="#basic-auth">Password protection</a></li>
    <li><a href="#error-pages">Error pages</a></li>
    <li><a href="#redirects">Redirects</a></li>
    <li><a href="#noexec-dirs">No-exec directories</a></li>
    <li><a href="#ip-acl">IP restrictions</a></li>
    <li><a href="#fail2ban-allowlist">Login allowlist</a></li>
    <li><a href="#email">Email &amp; DNS</a></li>
    <li><a href="#files">Files</a></li>
    <li><a href="#database">Database</a></li>
    <li><a href="#backups">Backups</a></li>
    <li><a href="#my-account">My account</a></li>
    <li><a href="#team">Team</a></li>
    <li><a href="#logs">Logs</a></li>
    <li><a href="#api-mcp">API &amp; MCP access</a></li>
  </ul>
</div>

<div class="docs">

<h3 id="overview">Overview</h3>
<p>The landing page: links to the live site and shared webmail, the mail
server's hostname and ports (IMAP 993, SMTP submission 465, both implicit
TLS), the SFTP connection string, and the database host/name/user (the
password is shown here only to owners -- see Database, below). Also shows
combined web + database + mail disk usage against the site's quota.</p>

<h3 id="php-functions">PHP functions</h3>
<p>A fixed list of process-execution functions --
<code>exec</code>, <code>shell_exec</code>, <code>system</code>,
<code>proc_open</code>, and others -- all off by default. Turning one on
gives PHP code running on the site the ability to run arbitrary programs on
the server; only enable what the site's own application genuinely needs.
Changes reach the web container within a few seconds (PHP-FPM reloads
automatically); requests already in flight aren't interrupted. Needs a
second factor (security key or authenticator app) registered on the account
just to open this page, not only to change something on it.</p>

<h3 id="fallback">404 handling</h3>
<p>Controls whether a request for a path that isn't a real file falls back to
the site's front controller (<code>index.php</code> if present, otherwise
<code>index.html</code>) -- the mechanism that makes pretty permalinks work
for WordPress/Laravel/etc., the same job <code>.htaccess</code> rewriting
does on Apache. Turned off, missing paths get a plain 404 instead. Takes
effect immediately, no downtime.</p>

<h3 id="basic-auth">Password protection</h3>
<p>Locks the entire site behind a single HTTP Basic Auth username/password,
PHP included -- the same job Apache's <code>AuthUserFile</code> does. Setting
a new password replaces whatever was there before; a one-click button
disables it entirely. Reaches the web container within a few seconds.</p>

<h3 id="error-pages">Error pages</h3>
<p>Maps an HTTP status code to a page already in the site's own webroot, one
per line: <code>CODE /path/to/page.html</code> -- e.g. a custom 404. Paths
must start with <code>/</code> and point at a real file in the webroot;
anything else is rejected before saving.</p>

<h3 id="redirects">Redirects</h3>
<p>Permanent (301) redirects for exact paths, one per line:
<code>/old-path https://example.com/new-path</code> (the target can also be
an absolute path on the same site). Exact-match only -- no wildcards.
Needs a second factor registered on the account just to open this page, not
only to change something on it.</p>

<h3 id="noexec-dirs">No-exec directories</h3>
<p>Denies PHP execution under specific webroot subdirectories no matter what
ends up in them, one per line, no leading/trailing slash (e.g.
<code>wp-content/uploads</code>). The web process runs as the same user the
SFTP account does, so a dropped executable anywhere writable is a full
compromise, not a contained one -- keep this on for any directory the site or
its visitors can write to. Needs a second factor registered on the account just to open this page, not
only to change something on it.</p>

<h3 id="ip-acl">IP restrictions</h3>
<p>Restrict the whole site to an allowlist of IPs/CIDRs, or block a
denylist -- one mode active at a time, or disabled. Same job as
<code>.htaccess</code>'s <code>Allow</code>/<code>Deny from</code>. Separate
from the login allowlist below: this controls who can reach the live site,
not who's exempt from a failed-login ban on this admin panel. Needs a second
factor registered to change.</p>

<h3 id="fail2ban-allowlist">Login allowlist</h3>
<p>IPs/CIDRs here never count toward this admin panel's own failed-login
report to the platform's shared ban system -- useful for a home/office IP if
a mistyped password is a worry. Only covers failures against this site's own
login; it can't exempt an IP from a ban a different tenant's traffic
triggers, since a ban on this shared login page applies platform-wide once it
happens. The account's own local lockout (a short wait after repeated
failures) still applies regardless of this list -- it only affects what gets
reported outward. Needs a second factor registered on the account just to open this page, not
only to change something on it.</p>

<h3 id="email">Email &amp; DNS</h3>
<p>Add, delete, and set per-mailbox quotas for any mailbox
(quotas are independent of the site's combined disk quota, though usage still
counts toward it either way). Resetting a mailbox's password or deleting one
is owner-only -- email is the recovery path into most things a tenant owns
outside this platform, so it stays a bigger deal than day-to-day mailbox
provisioning; members can still add mailboxes and set quotas. This page also
shows the site's recommended DNS records (SPF, DKIM, DMARC, and mail
routing) with a live "Check records" button -- advisory only, nothing here
changes DNS. DKIM signing is already active for outbound mail from this
tenant regardless of whether the DNS record has been published yet. Needs a
second factor registered on the account just to open this page.</p>

<h3 id="files">Files</h3>
<p>Direct read/write browser access to the webroot -- the same directory
SFTP and the live site itself serve from. Owner-only, and requires a second
factor on the account: this is equivalent to full control over what the site
serves, the same tier as the SQL console below. Files open in a
syntax-highlighted editor for common text/code formats.</p>

<h3 id="database">Database</h3>
<p>A SQL console connected as the site's own database user to its own
database -- the exact same credentials the site's application code already
uses. It can't do anything the application's own code couldn't already do;
there's no extra restriction beyond MariaDB's own permissions for that user.
Owner-only, and requires a second factor on the account.</p>

<h3 id="backups">Backups</h3>
<p>The host backs up every site automatically to its own destination with no
opt-out -- that always happens regardless of anything set here. This page
configures an <strong>additional</strong>, tenant-controlled destination (an
SFTP host of the tenant's own choosing) -- in addition to the host's backup,
never instead of it. Only an owner can change the destination or restore a
backup (redirecting backups exposes a full decrypted-at-the-source copy of
the site to wherever they point); any team member with a second factor
registered on their own account can trigger an immediate backup -- the whole
page needs one just to open, not only to change the destination or restore.
Encryption uses an <code>age</code> key -- either generated for the
tenant (shown exactly once, store it outside this panel; losing it makes
already-sent backups permanently unreadable) or a tenant-supplied private
key. The transport key pair used to authenticate to the tenant's own SFTP
destination is separate and safe to display/reuse any time -- only its
public half is ever shown. Every restore, from either destination, is
signature-verified before anything is touched; a tampered or corrupted
snapshot is refused outright. Settings saved here take effect within about
two minutes, not instantly -- a background process on the host performs the
actual backup/restore work, not this page.</p>

<h3 id="my-account">My account</h3>
<p>The logged-in user's own settings:</p>
<ul>
  <li><strong>Password</strong> -- change the account's own login password.</li>
  <li><strong>Security keys (WebAuthn)</strong> -- register/remove hardware
  or platform security keys as a second factor. Only works over the site's
  real public admin hostname (WebAuthn ties a key to the exact origin it was
  registered on).</li>
  <li><strong>Authenticator app (TOTP)</strong> -- an alternative second
  factor to a security key. Either one (or both) satisfies the panel's
  second-factor requirement; no need for both.</li>
</ul>
<p>PHP functions, Redirects, No-exec directories, IP restrictions, the Login
allowlist, Email, Files, Database, and Backups all require the logged-in
account to have a second factor registered first -- for the whole page,
including just viewing it, not only for saving a change. (Backups in
particular: any team member can trigger an immediate backup per that page's
own text, but only if that member has a second factor registered too --
without one, even loading the page 403s.) Team is the one exception worth
calling out: it needs no second factor at all, only the owner role, for its
mutating actions -- anyone logged in can view who the owners are.</p>

<h3 id="team">Team</h3>
<p><strong>Owners</strong> can manage the team, change the backup destination
and restore a backup, and use the SQL console. <strong>Members</strong> can
do everything else on this panel (PHP functions, mailboxes, redirects, and
so on) but not those three. Adding a team member generates a password shown
exactly once; the same for a password reset. The last remaining user, and
the last remaining owner, can't be removed or demoted -- the panel would
otherwise lock itself out. Any logged-in user can view this page (e.g. to see
who the owners are and ask one for something owner-only); every action on it
is owner-only.</p>

<h3 id="logs">Logs</h3>
<p>The last 200 lines of each of the site's logs: web access, web error,
PHP-FPM error, mail (Postfix + Dovecot), and SFTP. Reload the page to
refresh -- nothing here auto-updates.</p>

<h3 id="api-mcp">API &amp; MCP access</h3>
<p>Programmatic/AI-agent access to this site's own self-service
operations -- mailboxes, PHP function toggles, redirects, backups, and
the rest of what this panel exposes, deliberately excluding Files and
Database (the same two highest-trust actions gated separately elsewhere
in this panel). Off by default, gated by two things that both have to
be true before any of it works:</p>
<ul>
  <li><strong>Your host has to allow it first.</strong> This is entirely
  their decision, made from their own admin panel, per site -- there's
  nothing to request from inside this panel; contact them directly if
  you want either surface allowed.</li>
  <li><strong>You then turn it on yourself.</strong> Once your host has
  allowed a surface, a Turn on/off button for it appears on this page.
  Allowing and enabling are independent -- your host allowing it doesn't
  turn it on for you, and you can turn it back off any time without
  losing that allowance.</li>
</ul>
<p>Minting, listing, and revoking tokens on this page is owner-only and
needs a second factor on your account first -- same tier as Files and
Database. A token is shown exactly once when created; treat it like a
password, not a bookmark, since anyone holding it can act as an owner
through either surface. Revoking takes effect immediately.</p>
<p>Once a surface is on, use the same bearer token for both. The REST API
lives at <code>https://{{ platform_api_host }}/api/v1/self/*</code> --
your host's own shared platform domain, <strong>not</strong> your own
site's domain (e.g. <code>/api/v1/self</code> for an overview,
<code>/api/v1/self/mailboxes</code>, and so on -- the token-creation
panel above shows a real, ready-to-run example the moment you mint one).
The MCP server exposes the same operations as callable tools
(<code>self_overview</code>, <code>self_list_mailboxes</code>,
<code>self_set_php_functions</code>, and so on) rather than HTTP routes.
Either way, your token only ever reaches your own site's data -- it's
rejected outright for anything else, including any other tenant's data
or anything operator-only.</p>

</div>
"""


@app.route("/manual")
@require_login
def manual():
    return render(MANUAL_PAGE, platform_api_host=PLATFORM_API_HOST)


# Never actually invoked in the real image -- the Dockerfile's CMD runs
# gunicorn against this module directly (`app:app`), which imports this
# file without ever hitting __main__. Left in place purely as a
# `docker run --entrypoint python` local-debugging fallback.
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
