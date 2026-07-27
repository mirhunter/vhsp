"""Shared configuration for the VHSP control plane.

All paths/ranges are read from environment variables with sane defaults so
the same code works whether it's running on the Docker host directly
(current MVP) or eventually talking to a remote Docker API (see
architecture.md's control-plane auth section).
"""

import json
import os
from pathlib import Path

# Docker API endpoint. Defaults to the raw socket for local dev; production
# deployments should point this at a scoped docker-socket-proxy instead
# (deploy/docker-socket-proxy.service) rather than the raw socket, so a
# compromised control-plane process can't reach the full, root-equivalent
# Docker API (swarm, secrets, arbitrary exec/build) directly -- see the
# control-plane README's "Docker socket exposure" section. Any
# `unix://` or `tcp://` URL the docker SDK accepts as `base_url` works here.
DOCKER_HOST_URL = os.environ.get("VHSP_DOCKER_HOST", "unix:///var/run/docker.sock")

# Root directory on the Docker host where tenant state and per-tenant
# host-side volume directories live.
STATE_DIR = Path(os.environ.get("VHSP_STATE_DIR", "/srv/vhsp"))
TENANTS_DIR = STATE_DIR / "tenants"
DB_PATH = STATE_DIR / "control-plane.db"
ROUTING_TABLE_PATH = STATE_DIR / "routing" / "domains.json"

# Shared gateway network Traefik (and eventually the mail gateway) use to
# reach tenant containers. Must already exist (created once, out of band).
GATEWAY_NETWORK = os.environ.get("VHSP_GATEWAY_NETWORK", "traefik")

# Traefik's file-provider directory (--providers.file.directory in
# DEPLOYMENT.md's docker-compose.yml) -- every route living here today
# (vhsp-admin.yml, and previously vhsp-mcp.yml written by hand) was
# created by a human over SSH, never by this codebase itself.
# provisioner.enable_mcp_server()/disable_mcp_server() are the first code
# in this repo to write here programmatically, for the operator UI's MCP
# toggle. Defaults relative to the running process's own home directory
# (the control-plane user's, for vhsp-admin.service) rather than a hardcoded path, since
# that's genuinely portable across deployments unlike e.g.
# deploy/vhsp-mcp-toggle's own hardcoded checkout path.
TRAEFIK_DYNAMIC_DIR = Path(os.environ.get("VHSP_TRAEFIK_DYNAMIC_DIR", str(Path.home() / "traefik" / "dynamic")))

# Reserved external SSH port range handed out one-per-tenant.
SSH_PORT_RANGE = (2200, 2299)

# Tenant web container: nginx + PHP-FPM (hand-rolled, built locally --
# see images/web/), matching the WordPress/PHP-app-shaped workloads
# DEFAULT_DB_IMAGE's comment already assumes. Dangerous PHP functions
# disabled per architecture.md's security section -- see images/web/www.conf.
DEFAULT_WEB_IMAGE = os.environ.get("VHSP_DEFAULT_WEB_IMAGE", "vhsp-web:latest")
WEB_DOCUMENT_ROOT = "/var/www/html"

# Per-tenant DB container. MariaDB chosen as a default matching the
# WordPress/PHP-app-shaped workloads this is standing in for cPanel; per
# architecture.md, the isolation model doesn't actually require every
# tenant to use the same engine, this is just the MVP default.
DEFAULT_DB_IMAGE = os.environ.get("VHSP_DEFAULT_DB_IMAGE", "mariadb:11")
DB_INTERNAL_PORT = 3306

# cgroup limits applied to each tenant's DB container -- isolation/noisy-
# neighbor mitigation per architecture.md's "Database isolation" section.
DB_MEM_LIMIT = os.environ.get("VHSP_DB_MEM_LIMIT", "512m")
DB_NANO_CPUS = int(float(os.environ.get("VHSP_DB_CPUS", "1")) * 1_000_000_000)

# Same cgroup-isolation reasoning as DB_MEM_LIMIT/DB_NANO_CPUS above, now
# also applied to the web and mail containers -- those had no cap at all
# until now, so a single compromised or just abusive tenant could still
# starve CPU/memory for every other tenant on the host even with the DB
# side already capped. Defaults match the DB ones; independently tunable
# since a webapp's real memory needs can differ a lot from a DB engine's.
WEB_MEM_LIMIT = os.environ.get("VHSP_WEB_MEM_LIMIT", "512m")
WEB_NANO_CPUS = int(float(os.environ.get("VHSP_WEB_CPUS", "1")) * 1_000_000_000)
MAIL_MEM_LIMIT = os.environ.get("VHSP_MAIL_MEM_LIMIT", "512m")
MAIL_NANO_CPUS = int(float(os.environ.get("VHSP_MAIL_CPUS", "1")) * 1_000_000_000)
# Same cgroup-isolation reasoning again, extended to the two containers a
# follow-up security review found still had no cap at all: tenant-admin
# and SFTP. tenant-admin matches the DB/web/mail default (512m) rather
# than going lighter -- it has its own 200MB upload endpoint
# (MAX_CONTENT_LENGTH in images/tenant-admin/app.py), and Werkzeug's
# request-body buffering plus gunicorn's own baseline (2 workers) would
# leave too little headroom under a smaller cap, risking OOM-killing a
# legitimate large upload rather than just an abusive one. SFTP has no
# equivalent concern -- OpenSSH's SFTP subsystem streams through small
# buffers regardless of transfer size, not proportional to file size the
# way a buffered HTTP upload can be -- so it keeps a lighter default.
TENANT_ADMIN_MEM_LIMIT = os.environ.get("VHSP_TENANT_ADMIN_MEM_LIMIT", "512m")
TENANT_ADMIN_NANO_CPUS = int(float(os.environ.get("VHSP_TENANT_ADMIN_CPUS", "1")) * 1_000_000_000)
SFTP_MEM_LIMIT = os.environ.get("VHSP_SFTP_MEM_LIMIT", "256m")
SFTP_NANO_CPUS = int(float(os.environ.get("VHSP_SFTP_CPUS", "0.5")) * 1_000_000_000)

# Coraza WAF (OWASP Core Rule Set) reverse-proxy sidecar, one per tenant --
# see control-plane README's "Coraza WAF" section for why this is a real
# per-tenant container rather than a Traefik plugin (the open-source
# Traefik-native path can't load the actual OWASP CRS at all). Pinned by
# digest, not `:latest` or even a bare version tag -- confirmed via direct
# image inspection (not just docs) that this build genuinely bundles and
# activates the full CRS rule families (SQLi/XSS/RCE/LFI/RFI/etc, not a
# stub). Check https://github.com/coreruleset/coraza-crs-docker for
# upstream updates before ever changing this pin -- re-verify a new
# digest the same way (pull it, inspect /opt/coraza/owasp-crs/rules/, its
# /templates/nginx.conf) before trusting it, same as this one was.
WAF_IMAGE = os.environ.get(
    "VHSP_WAF_IMAGE",
    "ghcr.io/coreruleset/coraza-crs@sha256:8e55eca37e42003a00f4f0d9cd5eac3dc5f9945ec1ffd57f3438346a2db7ebdf",
)
# The image's own default listen port (its PORT env var default) -- an
# implementation detail of the image, not a deployment-topology fact, so
# a plain constant here rather than another env-tunable knob, same
# treatment as DB_INTERNAL_PORT above.
WAF_INTERNAL_PORT = 8080
WAF_MEM_LIMIT = os.environ.get("VHSP_WAF_MEM_LIMIT", "256m")
WAF_NANO_CPUS = int(float(os.environ.get("VHSP_WAF_CPUS", "0.5")) * 1_000_000_000)
# Coraza/CRS's own SecRuleEngine setting (the image's CORAZA_RULE_ENGINE
# env var) -- DetectionOnly by default, deliberately not "On". OWASP CRS
# is well known to false-positive against real-world app traffic (rich
# HTML/form posts, file uploads), and unlike a fail2ban false-positive
# ban (self-heals in 15-30 minutes), a WAF false positive in blocking
# mode just breaks a legitimate request outright with no auto-recovery.
# Same "safe default, escalate deliberately" posture as the PHP
# dangerous-functions toggle. Flip to "On" only after a real observation
# period in DetectionOnly against real traffic -- see the README's
# rollout notes.
WAF_ENGINE_MODE = os.environ.get("VHSP_WAF_ENGINE_MODE", "DetectionOnly")
# The image's own defaults (CORAZA_REQ_BODY_LIMIT=13107200 [12.5MB],
# CORAZA_REQ_BODY_NOFILES_LIMIT=524288 [512KB] -- confirmed via direct
# image inspection, not docs) are too conservative for this platform:
# tenant sites do real file uploads (WordPress media, etc.), and
# TENANT_ADMIN_MEM_LIMIT's own 200MB upload cap already establishes large
# uploads as expected, normal traffic here, not something to reflexively
# block. NOFILES stays much smaller than the full body limit deliberately
# -- it governs non-file form fields, which have no legitimate reason to
# need anywhere near what a file upload does.
WAF_REQ_BODY_LIMIT_BYTES = int(os.environ.get("VHSP_WAF_REQ_BODY_LIMIT_BYTES", str(210 * 1024 * 1024)))
WAF_REQ_BODY_NOFILES_LIMIT_BYTES = int(os.environ.get("VHSP_WAF_REQ_BODY_NOFILES_LIMIT_BYTES", str(4 * 1024 * 1024)))

# Per-tenant SFTP (file access to the webroot -- "www"). atmoz/sftp is a
# minimal OpenSSH build that's SFTP-only (ForceCommand internal-sftp, no
# shell), chrooted per user -- matches architecture.md's "dedicated
# external SSH port per tenant" design instead of a shared SSH gateway.
SFTP_IMAGE = os.environ.get("VHSP_SFTP_IMAGE", "atmoz/sftp:latest")

# Per-tenant mail container (hand-rolled Postfix+Dovecot, built locally --
# see images/mail/). Joins GATEWAY_NETWORK only: reachable by the shared
# inbound SMTP gateway (relaying per architecture.md's transport_maps
# design) and by Traefik for SNI-routed IMAPS/SMTPS, per the doc's mail
# layer section.
MAIL_IMAGE = os.environ.get("VHSP_MAIL_IMAGE", "vhsp-mail:latest")
MAIL_DEFAULT_USER = "postmaster"  # RFC 5321 requires this address to exist
MAIL_IMAPS_PORT = 993
MAIL_SMTPS_PORT = 465
# Fixed, not per-tenant/rotating -- a selector change means republishing a
# new DNS TXT record for every tenant, so this only needs to change if the
# key itself is ever deliberately rotated platform-wide.
DKIM_SELECTOR = os.environ.get("VHSP_DKIM_SELECTOR", "vhsp1")

# Shared inbound SMTP gateway (architecture.md: "the one piece that can't
# be solved with routing tricks"). Single instance, not per-tenant --
# publishes port 25 directly (SMTP has no SNI/TLS at connect time, so it
# can't go through Traefik at all, unlike IMAPS/SMTPS above).
MAILGW_IMAGE = os.environ.get("VHSP_MAILGW_IMAGE", "vhsp-mailgw:latest")
MAILGW_CONTAINER = "vhsp-mailgw"
MAILGW_HOSTNAME = os.environ.get("VHSP_MAILGW_HOSTNAME", "mail-gateway.vhsp.local")
MAILGW_MAPS_DIR = STATE_DIR / "mailgw" / "maps"

# The one IP every tenant's A/AAAA/mail-A records point at (architecture.md's
# "shared platform IP" -- single-public-IP premise). No default: DNS record
# generation refuses to guess this rather than emit a wrong IP into a
# suggested zone file.
PLATFORM_PUBLIC_IP = os.environ.get("VHSP_PLATFORM_PUBLIC_IP", "")

# Per-tenant self-service admin page (hand-rolled Flask, built locally --
# see images/tenant-admin/). First feature: re-enabling specific PHP
# functions the web container disables by default. Routed through Traefik
# like the web/mail containers, but on a SEPARATE entrypoint bound only to
# the management interface -- reachable at admin.<tenant-domain>, but only
# from the mgmt network, never the tenant-facing gateway. No login of its
# own; the network restriction *is* the access control for this pass.
TENANT_ADMIN_IMAGE = os.environ.get("VHSP_TENANT_ADMIN_IMAGE", "vhsp-tenant-admin:latest")
TENANT_ADMIN_ENTRYPOINT = "mgmtweb"

# Whether this deployment's Traefik actually has a "mgmtweb" entrypoint
# bound to a genuinely separate management interface -- true on the
# original two-network dev VM (see vhsp-infra-access project memory), but
# NOT true on a single-public-IP deployment (see
# single-public-ip-deployment project memory), where there's no spare
# IP/interface to bind a management-only entrypoint to at all. The
# mgmtweb-entrypoint router provisioner.py still creates in that case is
# inert (Traefik has no such entrypoint configured, so it never matches
# anything) -- WITHOUT this flag, cli.py/web.py would keep advertising a
# "mgmt-network-only" path that doesn't actually work on that deployment,
# which is exactly the bug this flag exists to prevent. Defaults to true
# so the original dev VM's display is unchanged.
TENANT_ADMIN_MGMTWEB_EXISTS = os.environ.get("VHSP_TENANT_ADMIN_MGMTWEB_EXISTS", "1").strip().lower() in ("1", "true", "yes")

# Shared webmail (architecture.md/the user: one Roundcube instance for
# every tenant, not one per tenant -- it holds no tenant data of its own
# (just its own small address-book/prefs DB), and Roundcube's built-in
# %d host templating is purpose-built for exactly this multi-domain
# hosting scenario. Third-party image, used as-is (same "don't hand-roll
# what a well-maintained upstream image already does well" reasoning as
# atmoz/sftp) -- SQLite backend, no separate DB container needed at this
# scale.
ROUNDCUBE_IMAGE = os.environ.get("VHSP_ROUNDCUBE_IMAGE", "roundcube/roundcubemail:latest")
ROUNDCUBE_CONTAINER = "vhsp-roundcube"
ROUNDCUBE_DATA_DIR = STATE_DIR / "roundcube"

# Soft disk quota -- combined web + DB + mail usage, checked/displayed on
# demand (see provisioner.py's get_tenant_disk_usage), not kernel-enforced.
# architecture.md already scoped disk usage as something to monitor per
# volume type but explicitly deferred hard enforcement ("not something
# this doc is committing to yet") -- there's no single mechanism that
# could enforce it anyway: these tenant directories are all bind-mounts of
# the one shared root ext4 filesystem (no per-tenant partition/loopback
# image to attach a real quota to), and MariaDB has no native disk quota
# concept at all. 200 MiB matches what the user asked for as the default
# for newly-created tenants; adjustable per-tenant afterward (see
# set_tenant_quota_limit) since nothing here assumes every tenant gets
# the same number forever.
DEFAULT_TENANT_QUOTA_BYTES = 200 * 1024 * 1024

# Admin web UI bind address. Defaults to localhost-only -- deliberately
# NOT 0.0.0.0 by default, since a deployment with no other access control
# in front of this would otherwise expose it on every interface including
# a tenant-facing one. Login (see web.py) is what actually gates access
# once a deployment does choose to bind more broadly than localhost/the
# management interface -- e.g. this VM's deployment binds 0.0.0.0 and
# reaches the public internet via the swarm's Traefik + Let's Encrypt,
# per the user's own choice to go public now for WebAuthn's
# secure-context requirement rather than wait for WebAuthn to land first.
ADMIN_BIND_HOST = os.environ.get("VHSP_ADMIN_BIND_HOST", "127.0.0.1")
ADMIN_BIND_PORT = int(os.environ.get("VHSP_ADMIN_BIND_PORT", "8000"))

# How long an idle operator session cookie stays valid (web.py sets
# session.permanent + PERMANENT_SESSION_LIFETIME from this, and refreshes
# the cookie's expiry on every request -- Flask's SESSION_REFRESH_EACH_REQUEST
# default -- so this is an idle timeout, not a fixed session length: an
# operator actively using the UI never gets logged out mid-task). Previously
# unset entirely, which for a signed-but-unexpiring Flask session cookie
# meant a stolen/left-open cookie stayed valid indefinitely.
ADMIN_SESSION_LIFETIME_MINUTES = int(os.environ.get("VHSP_ADMIN_SESSION_LIFETIME_MINUTES", "30"))

# mcp_server.py's own bind address -- a separate process/port from the
# admin UI above, not a path on the same one, since fastmcp is
# ASGI/Starlette-based and vhsp-admin.service's gunicorn/Flask stack is
# WSGI; there's no clean way to mount one inside the other. Same
# "127.0.0.1 by default, deployment opts into wider exposure" posture
# as ADMIN_BIND_HOST.
MCP_BIND_HOST = os.environ.get("VHSP_MCP_BIND_HOST", "127.0.0.1")
MCP_BIND_PORT = int(os.environ.get("VHSP_MCP_BIND_PORT", "8001"))

# Off by default -- trusting X-Forwarded-* blindly is exactly how IP
# allowlists and origin checks get spoofed by anyone who can reach the app
# directly, and reaching it directly is the default here too (ADMIN_BIND_HOST
# above). Only turn this on when a single reverse proxy hop genuinely sits in
# front of every request path to this process (e.g. this VM's deployment:
# vhsp.dvce.us -> the swarm's Traefik -> here over plain HTTP) -- one hop is
# what's actually deployed today, so this trusts exactly one, not an
# arbitrary chain. Without it, request.remote_addr is Traefik's own address
# for every request and request.scheme reports "http" even though the real
# client came in over https, which would misattribute the audit log's actor
# IP if that's ever added and would make any future same-origin/IP-based
# check on this app wrong in exactly the cases it matters most.
ADMIN_TRUST_PROXY = os.environ.get("VHSP_ADMIN_TRUST_PROXY", "0").strip().lower() in ("1", "true", "yes")

# Off by default, deliberately -- the operator REST API + MCP server are
# a genuinely new, higher-risk attack surface (a bearer token is easier
# to leak into a script/log/shell-history than a live browser session
# tied to one machine) sitting on top of the same privileged
# control-plane operations the web UI already exposes. web.py only
# registers the API Blueprint at all when this is true (see
# api.py/register_api_blueprint) -- when off, /api/v1/* routes don't
# exist, not just 403. mcp_server.py checks its own MCP_ENABLED (below,
# separate flag) at startup too and refuses to bind if unset, same
# "opt-in means genuinely absent, not just gated" posture.
#
# Runtime-mutable, not just env-var-fixed-at-startup: vhsp_ctl/web.py's
# /account/platform-access route lets an operator flip this from the UI
# (platform_settings.py's write side), which persists to
# STATE_DIR/platform_settings.json and restarts vhsp-admin.service to
# apply it. _platform_setting() below checks that file first and only
# falls back to the env var (a deployment's original VHSP_API_ENABLED in
# its systemd unit) if the file doesn't exist yet or doesn't mention this
# key -- so a deployment that's never touched the toggle keeps behaving
# exactly as before, env-var-only.
def _platform_setting(env_var: str, settings_key: str) -> bool:
    settings_path = STATE_DIR / "platform_settings.json"
    if settings_path.exists():
        try:
            data = json.loads(settings_path.read_text())
            if settings_key in data:
                return bool(data[settings_key])
        except (json.JSONDecodeError, OSError):
            pass
    return os.environ.get(env_var, "0").strip().lower() in ("1", "true", "yes")


def current_api_enabled() -> bool:
    """Live re-read of the same value API_ENABLED below freezes at import
    time -- use this, not the frozen constant, anywhere that displays
    current on/off state to an operator (the toggle UI on
    /account/api-tokens, /account, and the Manual). The frozen constant
    is correct for the one thing it actually gates -- Blueprint
    registration, a decision only made once, at process startup -- but
    goes stale the instant a toggle changes the underlying file, until
    this process happens to restart for some other reason. Found and
    fixed live: after turning the REST API off then MCP off, the UI kept
    showing MCP as "On" with a Turn-off button even though the toggle had
    genuinely succeeded (settings file and live infrastructure were both
    already correct) -- because MCP's own toggle deliberately never
    restarts this process (no functional need to, unlike the REST API's
    Blueprint), the frozen MCP_ENABLED constant below never got a chance
    to catch up."""
    return _platform_setting("VHSP_API_ENABLED", "api_enabled")


def current_mcp_enabled() -> bool:
    """See current_api_enabled()'s docstring -- same reasoning, same bug,
    same fix, for the flag that actually triggered it."""
    return _platform_setting("VHSP_MCP_ENABLED", "mcp_enabled")


API_ENABLED = current_api_enabled()

# Separate from API_ENABLED above -- originally mcp_server.py gated on
# API_ENABLED itself (a "second, redundant safety net" from when MCP
# always shipped bundled with the REST API flag, per that module's own
# earlier docstring), but now that each surface gets its own toggle in
# the UI, coupling them would be inaccurate: an operator can reasonably
# want one without the other.
MCP_ENABLED = current_mcp_enabled()

# WebAuthn RP ID for the operator admin UI -- must match the real public
# hostname this UI is actually served at (see webauthn.py's docstring on
# why this can't be derived from the request). Defaults to the original
# dev VM's own hostname so that deployment's behavior is unchanged; every
# other deployment (e.g. a second host with its own hostname) needs its
# own value here or WebAuthn registration/login will fail with an origin
# mismatch.
ADMIN_RP_ID = os.environ.get("VHSP_ADMIN_RP_ID", "vhsp.dvce.us")

# Comma-separated CIDRs for reverse-proxy hops *beyond* the immediate one
# every tenant web container always has (the VM-local Traefik, resolved
# dynamically by images/web/entrypoint.sh -- not this setting's concern).
# Empty by default: trusts nothing beyond that one hop, so a fresh
# deployment with no further upstream proxy just gets the local Traefik's
# already-correct behavior with no extra config needed. Set this when
# something else sits in front of that -- e.g. this VM's actual setup,
# where the swarm's own Traefik (172.16.45.0/24) is a second hop that
# already computes the real client IP correctly and just needs to be
# trusted to relay it rather than have it discarded. Passed into each
# tenant web container's environment at creation time (see
# provisioner.py's create_tenant) since, like ADMIN_TRUST_PROXY, this is a
# platform-topology fact a tenant has no business controlling themselves.
WEB_TRUSTED_PROXY_CIDRS = os.environ.get("VHSP_WEB_TRUSTED_PROXY_CIDRS", "")

# --- Backup / restore (see backup.py) ---
# Three purpose-specific operator keypairs live here, plain 600 host files,
# never mounted into any container -- deliberately not Docker Swarm secrets
# (only mountable into Swarm *services*, would need swarm-mode init on a
# host that otherwise never uses it) and not systemd-creds (TPM/host-key
# bound -- a recoverability trap if this specific host is lost, which
# defeats a chunk of the point of having backups at all). Generated once by
# `vhsp backup init`, each shown exactly once in that command's own output
# with a warning to copy it to secure offline storage -- same "generated,
# shown once, never re-displayed" pattern this codebase already uses for
# operator/tenant admin passwords.
BACKUP_KEYS_DIR = STATE_DIR / "backup" / "keys"
BACKUP_OPERATOR_SSH_KEY_PATH = BACKUP_KEYS_DIR / "operator_transport_ed25519"
BACKUP_OPERATOR_AGE_KEY_PATH = BACKUP_KEYS_DIR / "operator_encryption_age.key"
BACKUP_OPERATOR_SIGNING_KEY_PATH = BACKUP_KEYS_DIR / "operator_signing_ed25519"

# A tenant's own additional destination gets its own keypairs here, one
# subdirectory per tenant slug -- same "host file only, chmod 600" rule as
# the operator's own keys above, even though it's the tenant's own key:
# the requirement is specifically that it's shown once and never
# re-readable via the UI, which a phpconf-volume file (writable into the
# tenant-admin container itself) couldn't guarantee.
BACKUP_TENANT_KEYS_DIR = STATE_DIR / "backup" / "tenant-keys"

# Scratch space for building/decrypting snapshot tars -- always cleaned up
# at the end of every backup.py operation, same "temp dir per invocation"
# shape as provisioner.py's tempfile use in _fingerprint_public_key.
BACKUP_WORKDIR = STATE_DIR / "backup" / "work"

# How many bytes of audit.py's local AUDIT_LOG_PATH have already been
# shipped to the operator SFTP destination -- see backup.ship_audit_log.
# A plain marker file, not a registry row: this is host-wide, one value,
# same "small persistent marker" shape as auth.py's own SECRET_KEY_PATH.
AUDIT_SHIP_STATE_PATH = STATE_DIR / "audit_ship_state.json"

# Platform-wide fail2ban allowlist -- IPs/CIDRs an operator never wants
# banned by any jail (their own home/office IP, monitoring services,
# etc.). Read live by deploy/vhsp-fail2ban-allowlist-check on every ban
# decision (fail2ban's ignorecommand hook), not just at jail load time,
# so an edit here takes effect immediately with no fail2ban reload
# needed. See the control-plane README's fail2ban section.
FAIL2BAN_OPERATOR_ALLOWLIST_PATH = STATE_DIR / "fail2ban_operator_allowlist.txt"

# The SUBSET of the allowlist above that additionally bypasses the WAF.
# A separate file rather than a flag column in the one above, for one
# concrete reason: deploy/vhsp-fail2ban-allowlist-check parses that file
# in bash+python and SKIPS any line it can't parse as an IP/CIDR
# (`except ValueError: continue`). Adding a suffix like "1.2.3.4 waf"
# there would make the entry silently stop exempting that IP from bans
# -- a security regression with no error anywhere. The admin UI presents
# both files as one list with a per-entry checkbox; only the storage is
# split.
#
# Being on this list is strictly more dangerous than being on the one
# above: that one means "never ban this IP for failed logins", this one
# means "send this IP's request bodies to the app without inspecting
# them for SQLi/RCE". Opt-in per entry, never implied.
WAF_ALLOWLIST_PATH = STATE_DIR / "waf_allowlist.txt"

# The operator's ONE shared destination. Every tenant lands here
# unconditionally, no opt-out -- an empty host means "not configured yet",
# and backup.py refuses to run until this is set.
BACKUP_OPERATOR_SFTP_HOST = os.environ.get("VHSP_BACKUP_SFTP_HOST", "")
BACKUP_OPERATOR_SFTP_PORT = int(os.environ.get("VHSP_BACKUP_SFTP_PORT", "22"))
BACKUP_OPERATOR_SFTP_USER = os.environ.get("VHSP_BACKUP_SFTP_USER", "")
BACKUP_OPERATOR_SFTP_PATH = os.environ.get("VHSP_BACKUP_SFTP_PATH", "/backup")

# Platform-wide defaults, overridable per tenant via registry.py's
# backup_retention_count/backup_interval columns -- same "platform default
# + per-tenant override" shape as DEFAULT_TENANT_QUOTA_BYTES /
# set_tenant_quota_limit. Retention is a per-tenant backup COUNT, not a
# global cap across every tenant combined.
DEFAULT_BACKUP_RETENTION_COUNT = int(os.environ.get("VHSP_BACKUP_RETENTION_COUNT", "30"))
DEFAULT_BACKUP_INTERVAL = os.environ.get("VHSP_BACKUP_INTERVAL", "daily")
BACKUP_INTERVAL_CHOICES = ("daily", "weekly", "monthly")
BACKUP_INTERVAL_DAYS = {"daily": 1, "weekly": 7, "monthly": 30}

# Bumped only if the manifest's own structure ever changes incompatibly --
# lets a future restore_backup tell an old-format backup apart from a new
# one rather than guessing from field presence.
BACKUP_MANIFEST_FORMAT_VERSION = 1
