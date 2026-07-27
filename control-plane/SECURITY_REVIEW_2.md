# vhsp Security Review 2 -- Follow-up (2026-07-24)

Scope: read-only review of the local repo at `/home/astjohn/Projects/vhsp`
(`architecture.md`, `control-plane/`). This is a follow-up to a prior
review whose 10 findings were all remediated and verified against live
infra. This pass (a) sanity-checks those fixes for regression, and (b)
scrutinizes what's been built since: fail2ban (replacing CrowdSec),
the tenant-admin chown/host-UID fix, and the new vendored static asset
serving -- plus a general pass over anything else that looked off.

No infrastructure was touched. All findings are based on reading the
code and cross-checking it against its own documentation and its own
stated design rationale (the comments throughout this codebase are
unusually load-bearing -- several findings below are places where the
code's own comments describe an invariant or a prior bug that the
current code doesn't actually uphold).

---

## Summary

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 2 |
| Medium | 3 |
| Low / informational | 5 |

**Regressions in the original 10 fixes: none found.** Sudoers scoping,
the docker-socket-proxy allowlist, login throttling + minimum password
length on both admin UIs, owner-gating of the tenant DB password,
audit-log hash chaining, session cookie flags, cgroup limits on
web/mail/db containers, the pinned `requirements-lock.txt`, and
key-rotation/backup-encryption via `secretbox.py` were all re-checked
directly against the current code and are intact.

**Single most important fix:** Finding #1 -- the tenant-admin
container's Flask `SECRET_KEY_FILE` is written world-readable (no
`os.chmod`), unlike the near-identical operator-side implementation it
was explicitly modeled on (`vhsp_ctl/auth.py:ensure_secret_key`, which
does chmod it 0600). A leaked secret key means a forged session
cookie, which means full owner-level access to that tenant's admin
panel with **no password and no 2FA** -- the entire auth chain is
bypassed by a file that's currently one `chmod` away from being fixed.

---

## (a) Regressions in previously-fixed items

None found. Specifically re-verified against current code:

- `deploy/vhsp-sudoers`: still scoped to exactly five wrapper scripts
  via `Cmnd_Alias` (`VHSP_HOSTDIR`, `VHSP_BACKUP`, `VHSP_FAIL2BAN_TENANT`)
  plus four literal `systemctl restart` lines (`VHSP_RESTART`) -- no
  blanket grant, no wildcarded arguments. The new
  `VHSP_FAIL2BAN_TENANT` alias follows the exact same pattern as the
  pre-existing two.
- `deploy/vhsp-docker-proxy.service`: still a `tecnativa/docker-socket-proxy`
  allowlist with `SWARM/SERVICES/SECRETS/CONFIGS/PLUGINS/NODES/BUILD/
  COMMIT/DISTRIBUTION/AUTH/TASKS/SESSION/SYSTEM` all `=0`; astjohn's
  processes only reach Docker via `127.0.0.1:2375`, not the raw socket.
- Login throttling (`vhsp_ctl/login_throttle.py` on the operator side,
  an independently-implemented equivalent in `images/tenant-admin/app.py`
  at `LOGIN_MAX_FAILURES=5` / `LOGIN_LOCKOUT_SECONDS=15m`) and minimum
  password length (`MIN_PASSWORD_LENGTH = 12` in both `web.py` and
  `app.py`) are both present and unchanged in shape.
- Tenant DB password on the Overview page: still gated to
  `is_owner` (`app.py` line ~2374, `db_password=DB_PASSWORD if is_owner else None`).
- Audit log hash chain: `vhsp_ctl/audit.py`'s `prev_hash` field and
  `verify_chain()` are intact and unchanged in logic.
- Session cookies: `HttpOnly`/`SameSite=Lax` unconditional, `Secure`
  conditioned on a deployment flag (`ADMIN_TRUST_PROXY` /
  `TENANT_ADMIN_MGMTWEB_EXISTS`) in both `web.py` and `app.py`.
- cgroup limits: `mem_limit`/`nano_cpus` still set for DB/web/mail
  container creation in `provisioner.py`. (See Finding #4 below,
  though -- this was never extended to the tenant-admin or SFTP
  containers, in the original review or since.)
- `requirements-lock.txt` still present and pinned (33 lines, `pip
  freeze`-derived per its own header comment).
- `vhsp secrets rotate` (`cli.py`) and `vhsp backup init --force`
  still present; `vhsp_ctl/backup.py` still round-trips every private
  key (SSH, signing, age) through `secretbox.decrypt`/`encrypt`.

---

## (b) New findings in the three focus areas

### 1. [CRITICAL] Tenant-admin Flask session secret is written world-readable -- full auth bypass if disclosed

`images/tenant-admin/app.py`, lines ~594-598:

```python
if not SECRET_KEY_FILE.exists():
    SECRET_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    SECRET_KEY_FILE.write_text(secrets.token_hex(32))
app.secret_key = SECRET_KEY_FILE.read_text()
```

No `os.chmod` call. The file is created with the process's default
umask (typically `644`), so on the host bind mount it ends up
world-readable. Compare this to the operator-side code this was
explicitly modeled on -- the comment two lines above literally says
*"same reasoning as vhsp_ctl/auth.py's ensure_secret_key for the
operator admin UI"* -- but `vhsp_ctl/auth.py:ensure_secret_key`
actually does:

```python
SECRET_KEY_PATH.write_text(secrets.token_hex(32))
os.chmod(SECRET_KEY_PATH, stat.S_IRUSR | stat.S_IWUSR)
```

The tenant-admin copy dropped the `os.chmod` line. This is also the
*only* one of the sensitive files this container writes that isn't
locked down: `webauthn_credentials.json`, `totp_secrets.json`,
`tenant_users.json`, and `login_attempts.json` all get an explicit
`os.chmod(..., stat.S_IRUSR | stat.S_IWUSR)` right after being
written (and are then `chown`'d back to the host UID/GID -- see
Finding on Focus Area 2 below). `SECRET_KEY_FILE` gets neither the
chmod nor the chown, and is the most sensitive file of the group.

**Why it matters:** Flask signs (not encrypts) session cookies with
this key. Anyone who can read this file for a given tenant can forge
an arbitrary session -- set `username` to that tenant's owner account
and mint a cookie that walks straight past `require_login`,
`require_role("owner")`, and `require_2fa` (all three just inspect
`session[...]`, they don't re-verify a live challenge), landing on
full control of the SQL console, file manager, and mailbox
management with zero credentials. This is a bigger prize than any
individual route-level bug in this file, because it's a total bypass
of the login form *and* every 2FA gate at once.

The realistic exposure path is local: this file lives on a bind
mount now owned by whatever OS user runs `vhsp-admin.service`
(`astjohn`, per the Focus-Area-2 fix), permissions `644`. Any other
local account on the host, any process that gets incidental read
access to `/srv/vhsp/tenants/*/phpconf/` (a misconfigured backup
step, a future bug, a support script run by hand), or a host-level
compromise well short of full root, now yields instant admin-panel
takeover for every tenant on that host, not just information
disclosure.

**Fix:** add the missing `os.chmod(SECRET_KEY_FILE, stat.S_IRUSR |
stat.S_IWUSR)` right after the `write_text` call, and add it to the
`_chown_to_host` list alongside the other four files so it also ends
up owned by the host UID rather than root (currently root would own
it before any host-side process could even attempt to read it, which
is incidentally probably why this was never noticed -- host-side code
never needed to read this one file, so nothing broke functionally the
way the original chown bug did).

---

### 2. [HIGH] Shared-Traefik fail2ban jail turns one bot hitting one tenant's admin login into a platform-wide outage for unrelated tenants

`deploy/fail2ban/jail.local`, `[vhsp-tenant-admin-login]`:

```ini
[vhsp-tenant-admin-login]
enabled = true
port = http,https
filter = vhsp-tenant-admin-login
logpath = /srv/vhsp/tenants/*/phpconf/login_attempts.log
```

No `maxretry`/`bantime`/`findtime` override, so it inherits
`[DEFAULT]`: `maxretry = 5`, `findtime = 10m`, `bantime = 30m`, and
crucially `banaction = nftables-multiport`, which firewalls the
offending IP off of `port = http,https` -- i.e. off of *every* port
443/80 connection on the box, for *every* tenant, since (per the
jail's own comment) "every tenant shares port 443 through the same
Traefik instance."

**Why it matters:** `admin.<tenant-domain>` hostnames are exactly the
kind of thing internet-wide background-scanning bots probe routinely
(the same class of traffic that hits `/wp-admin`, `/admin`, etc. on
every host on the internet, all day, unprompted). Five failed
login attempts from one scanner against *any single tenant's*
admin panel -- not even a targeted attack, just noise -- gets that
source IP nftables-banned from reaching **every tenant's public
website** on the platform for 30 minutes, not just the one tenant
that was probed. A tenant with a weak or default-guessable admin
username sitting behind a shared IP/CGNAT block with legitimate
other users creates real collateral damage: those unrelated users
get locked out of every site on the platform because someone else's
scanner tripped one tenant's login jail. This gets worse as the
tenant count grows -- more tenants means more `admin.*` surface for
bots to find and fail against, and each failure has platform-wide
blast radius. The `[vhsp-tenant-admin-login]` filter/jail comments
already acknowledge the shared-Traefik constraint explicitly, but the
resulting availability tradeoff (every tenant's admin-login noise can
firewall-ban visitors off every *other* tenant's storefront) doesn't
appear to have been evaluated as its own risk.

**Fix:** at minimum, raise `maxretry`/lengthen `findtime` specifically
for this jail (it's the one whose false-positive cost is
"platform-wide outage," so it should be the most conservative one,
not inherit the same default as `sshd`). Better: don't let a fail
against the tenant-*admin* subpath ban the shared web ports at all --
either (a) act via an nginx/Traefik-level per-Host-header deny (if
feasible) rather than a raw port-level nftables ban, so the ban stays
scoped to `admin.<that-tenant>` instead of the whole platform, or (b)
rely on the app-level `LOGIN_ATTEMPTS_FILE` per-account lockout
(already present, already independent of source IP) as the primary
control for this specific jail and treat the fail2ban layer here as
belt-and-suspenders rather than the first line of defense.

---

### 3. [MEDIUM] Path-consistency between config.py and the two new fail2ban wrapper scripts is comment-enforced only

**Status: FIXED.** New `vhsp doctor` CLI command
(`vhsp_ctl/cli.py`) reads each installed script's actual hardcoded path
off disk and asserts it matches `config.py`'s current value, exiting
non-zero on any mismatch. Verified on vhsp2: passes cleanly against the
real installed scripts, and correctly caught + reported a deliberately
introduced mismatch (then confirmed clean again after restoring the
original file). See `control-plane/README.md`'s "Follow-up security
review" section for the full writeup.

`deploy/vhsp-fail2ban-allowlist-check` and
`deploy/vhsp-fail2ban-tenant-jail` both hardcode:

```bash
OPERATOR_LIST="/srv/vhsp/fail2ban_operator_allowlist.txt"   # must match config.py's FAIL2BAN_OPERATOR_ALLOWLIST_PATH
TENANTS_DIR="/srv/vhsp/tenants"                              # must match config.py's TENANTS_DIR
```

`vhsp_ctl/config.py` derives both of these from `STATE_DIR =
Path(os.environ.get("VHSP_STATE_DIR", "/srv/vhsp"))` -- i.e.
overridable via an environment variable, with no single source of
truth shared with the two root-owned bash scripts. The comments
correctly flag the coupling but nothing enforces it.

**Why it matters:** if `VHSP_STATE_DIR` is ever set to something other
than the default on a given deployment (env-specific config,
multi-instance testing, a future path migration), the operator and
per-tenant allowlists silently stop being consulted -- `check_list`
just finds no file at the (now wrong) hardcoded path and returns
"don't skip the ban," so this fails *safe* (over-banning) rather than
open, which limits the damage, but it's still a silent, hard-to-debug
drift: an operator who adds their own IP to the allowlist via the web
UI (`fail2ban_allowlist.py`, gated behind 2FA) would have no way to
know the fail2ban layer isn't actually honoring it, until they
themselves get banned. This is exactly the class of bug the
project's own comments elsewhere ("verified directly," "confirmed
this was happening") suggest the team cares about catching before it
bites in production.

**Fix:** have `deploy/vhsp-harden-hostdir`-style installation (or a
small `vhsp deploy render-fail2ban-paths` step) generate these two
paths into the scripts from `config.py` at install time instead of
hardcoding them twice, or at minimum have `vhsp doctor`/an equivalent
health check assert the paths match.

---

### 4. [LOW] Stale comment in `vhsp_ctl/fail2ban_allowlist.py`

The module docstring says the allowlist file is plain text "since
`deploy/vhsp-fail2ban-allowlist-check` ... needs to read this with
nothing more than `grep -Fxq`" -- but the actual script does real CIDR
containment via a Python `ipaddress` subprocess, not `grep`. No
functional issue, but this codebase leans hard on comments as the
actual documentation of *why* something is built the way it is, so a
drifted comment here is a bit more costly than usual (the next person
touching this file will design around a constraint -- "must stay
`grep`-parseable" -- that no longer exists).

---

### 5. Focus areas verified clean (no finding)

- **Fail2ban injection surface:** confirmed `<HOST>` in fail2ban's
  default tag regex (used unmodified by all three of this project's
  custom filters -- none override `__extra_hostname_char`) is
  restricted to a safe character class (digits/dots for IPv4, hex/colons
  for IPv6, or `[\w\-.^_]+` for a hostname), which excludes shell
  metacharacters. Even though fail2ban's `ignorecommand` is ultimately
  executed through a shell after tag substitution, the substituted
  value can't carry injection payloads given that regex. The tenant
  slug baked into each per-tenant jail's `ignorecommand` line is
  validated (`^[a-z0-9-]+$`) both at generation time
  (`vhsp-fail2ban-tenant-jail`, itself fed only a provisioner-derived
  slug that's already constrained to that character set) and again
  defensively inside `vhsp-fail2ban-allowlist-check` before use. The
  `ip`/`file` values that actually reach the Python CIDR-check
  subprocess do so as real argv (`sys.argv[1]`, `sys.argv[2]`), not
  string-interpolated into a shell -- no injection there either.
- **Sudoers scope for the new script:** `VHSP_FAIL2BAN_TENANT` is as
  narrowly scoped as the pre-existing aliases (one literal command
  path, argument validation left to the wrapper script itself, same
  documented pattern as `VHSP_HOSTDIR`/`VHSP_BACKUP`).
  `vhsp-fail2ban-allowlist-check` correctly does *not* appear in
  sudoers at all, since it's invoked by fail2ban's own root-owned
  service directly, not via astjohn's sudo grant.
- **chown target in the tenant-admin UID fix:** `_chown_to_host(path:
  Path)` is called at exactly four call sites, all hardcoded
  module-level `Path` constants (`WEBAUTHN_CREDENTIALS_FILE`,
  `TOTP_SECRETS_FILE`, `TENANT_USERS_FILE`, `LOGIN_ATTEMPTS_FILE`).
  There is no code path where a request-influenced value reaches
  `os.chown`. `VHSP_HOST_UID`/`VHSP_HOST_GID` being broadcast into
  every tenant's container environment doesn't leak anything
  meaningful either -- it's the same fixed low UID/GID (whatever user
  runs `vhsp-admin.service`) on every tenant, not a secret or a
  per-tenant value. Root-in-container's blast radius is unchanged by
  this fix: the container already ran fully as root before, and
  `os.chown` to an arbitrary UID is something root-in-container could
  already do regardless of this feature.
- **Static asset serving:** `images/tenant-admin/Dockerfile` only
  `COPY`s `static/vhsp-editor.bundle.js` and
  `static/vhsp-editor.bundle.js.LICENSE.txt` into `/static/` --
  `static/src/` (including `package.json`/`package-lock.json`) is
  genuinely absent from the built image, confirmed by reading the
  Dockerfile directly rather than trusting the comment. Flask's
  default static route (Werkzeug's `send_from_directory`) has
  well-tested path-traversal protection; nothing here overrides or
  weakens it. No directory listing, no debug mode anywhere
  (`app.run()` calls are both behind `if __name__ == "__main__":`
  guards that the real gunicorn-driven image never executes).
  Supply-chain note (as flagged in the task): this review has no
  internet access to check the pinned CodeMirror package versions
  against CVE databases -- a real pre-adoption pass should do that
  check. See Finding #6 below for a related, more concrete supply-chain
  gap in the *same* container found during this pass.

---

## (c) Everything else worth flagging

### 6. [HIGH] `/email` (full mailbox control) requires neither owner role nor 2FA

`images/tenant-admin/app.py`, `/email` route (~line 2638): decorated
with only `@require_login`. Any team member -- not just the tenant
owner -- can add mailboxes, **reset any existing mailbox's password
(including `postmaster@`)**, delete mailboxes, and set quotas, with no
second factor at all. This is a deliberate, documented choice: the
`require_2fa` docstring explicitly lists "mailboxes" among the
"Routine, lower-impact pages" it decided to leave ungated, alongside
404 handling and error pages.

**Why this risk classification looks wrong:** email is disproportionately
valuable compared to almost anything else this app protects, because
it's the recovery mechanism for nearly every *other* account a tenant
owns (domain registrar, hosting billing, third-party SaaS, personal
accounts using the same domain for "forgot password" flows). Resetting
`postmaster@`'s password or adding a new mailbox and intercepting mail
flowing to an existing address is a direct pivot into taking over
accounts well outside this platform's own blast radius -- arguably a
bigger prize than the SQL console, which *is* 2FA-gated. Pairing this
with "no owner-role requirement either" compounds it: a lower-trust
"member" account (e.g. a contractor added for a narrow purpose) gets
full email-domain control for free, something `/files` and `/database`
correctly refuse even to a member with 2FA.

**Fix:** at minimum add `@require_2fa` to `/email` (consistent with
`/redirects`, `/noexec-dirs`, `/ip-acl`, which already get it without
being owner-only); consider `@require_role("owner")` for the
password-reset and delete actions specifically, since a member
managing day-to-day mailbox provisioning is more defensible than a
member being able to take over `postmaster@`.

### 7. [MEDIUM] tenant-admin and SFTP containers have no cgroup memory/CPU limits

`provisioner.py` sets `mem_limit`/`nano_cpus` for DB (`DB_MEM_LIMIT`/
`DB_NANO_CPUS`), web (`WEB_MEM_LIMIT`/`WEB_NANO_CPUS`), and mail
(`MAIL_MEM_LIMIT`/`MAIL_NANO_CPUS`) containers -- confirmed still
correct, no regression. `_create_tenant_admin_container` and
`_create_sftp_container` set neither. This predates the current round
of changes, but the tenant-admin container is exactly the surface that
grew the most since the last review: a 200MB file-upload endpoint
(`MAX_CONTENT_LENGTH`), a CodeMirror bundle, TOTP/WebAuthn crypto
ceremonies, and an arbitrary-SQL console, all running unconstrained
next to every other tenant's containers on the same Docker host with
no per-container ceiling.

**Why it matters:** on the small droplets this project explicitly
targets (`DEPLOYMENT.md` mentions ~1GB RAM instances), one abusive or
compromised tenant-admin session -- repeated large uploads, a
memory-heavy SQL query via `/database`, or just a runaway process --
can exhaust host memory or CPU with no cgroup ceiling stopping it,
degrading or crashing every *other* tenant's DB/web/mail containers
that share the host. This is precisely the failure mode the
`DB_MEM_LIMIT`/`WEB_MEM_LIMIT`/`MAIL_MEM_LIMIT` pattern was clearly
built to prevent elsewhere; it just wasn't extended to these two
containers.

**Fix:** add `TENANT_ADMIN_MEM_LIMIT`/`TENANT_ADMIN_NANO_CPUS` (and
equivalents for SFTP) to `config.py`, following the exact existing
pattern, and pass them into both `client.containers.run(...)` calls.

### 8. [MEDIUM] tenant-admin's Python dependencies are installed fully unpinned

`images/tenant-admin/Dockerfile`:

```dockerfile
RUN pip install --no-cache-dir flask passlib fido2 pymysql pyotp qrcode gunicorn
```

No version pins, no lock file referenced -- unlike the control-plane's
own `requirements-lock.txt` (pinned via `pip freeze` against the live
deployment, per that file's own header). Every image (re)build --
which happens routinely, since `recreate_tenant_admin.py` exists
specifically to rebuild/recreate these containers -- can silently pull
different, newer versions of every dependency, including `fido2`
(the WebAuthn implementation this container's entire second-factor
security model depends on) and `pymysql` (the arbitrary-SQL console's
transport). This is the same class of concern the task specifically
asked about for the vendored CodeMirror bundle, just on the Python
side of the same container, and arguably higher-stakes since `fido2`
is security-load-bearing in a way CodeMirror isn't.

**Fix:** generate a `requirements-lock.txt` (or pip hashes) for this
image the same way the control-plane package already has one, and
`COPY`+`pip install -r` it in the Dockerfile instead of a bare
`pip install` of package names.

### 9. [LOW] `_chown_to_host` fails silently if the host UID/GID env vars are ever missing

```python
def _chown_to_host(path: Path) -> None:
    """No-op if the host UID/GID wasn't passed in..."""
    if _HOST_UID is not None and _HOST_GID is not None:
        os.chown(path, _HOST_UID, _HOST_GID)
```

This is documented as intentional (falls back to the pre-fix
behavior), but there's no logging on the no-op path. If a future
refactor of `_create_tenant_admin_container` ever drops the
`VHSP_HOST_UID`/`VHSP_HOST_GID` env vars (e.g. someone simplifies the
`environment={...}` dict and misses these two undocumented-looking
entries), the exact bug this fix was built to resolve -- host-side
`EACCES` reading `webauthn_credentials.json`/`tenant_users.json`/etc.
-- silently comes back with no alarm anywhere, and would likely
resurface as a confusing production support ticket rather than a
caught regression. A one-line `warnings.warn(...)`/print to stderr on
the no-op path (visible in `docker logs`) would turn a silent
regression into a loud one.

### 10. [LOW] No security response headers anywhere in either admin UI or nginx.conf

**Status: PARTIALLY FIXED.** `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, and `Referrer-Policy:
strict-origin-when-cross-origin` now added via a new
`@app.after_request` hook on both `vhsp_ctl/web.py` and
`images/tenant-admin/app.py`, verified live on vhsp2 against real
responses on all three surfaces (operator UI, both tenant panels). A
real `Content-Security-Policy` remains deliberately not implemented --
both apps depend on inline `<script>`/`<style>` throughout, so a CSP
that actually restricts `script-src` needs a per-request nonce
threaded into every inline block (a real refactor) and real browser
verification that nothing silently breaks (a CSP violation fails
client-side with no server-side error) -- not available this session.
nginx.conf (tenant sites' own web-server config) intentionally left
untouched -- imposing these headers on arbitrary tenant-authored site
content is a different call than imposing them on this platform's own
admin surfaces, and wasn't in scope for what was asked.

Neither `vhsp_ctl/web.py`, `images/tenant-admin/app.py`, nor
`images/web/nginx.conf` set `Content-Security-Policy`,
`X-Content-Type-Options: nosniff`, `X-Frame-Options`, or
`Referrer-Policy` anywhere. This predates the current changes and
wasn't part of the original 10 (the "already known-good" list for
this review doesn't mention headers), so it's not a regression --
just an observation worth recording now that tenant-admin renders
more dynamic, request-adjacent content than it used to (the file
editor, log viewers, DNS-check output) and is reachable from the
public internet on both containers' second Traefik entrypoint. Not
urgent, but `X-Content-Type-Options: nosniff` in particular is a
cheap, no-downside addition given the app now serves a static JS
bundle for the first time.

### 11. Confirmed no regressions to the docker-socket-proxy allowlist, but noted `:latest`

`deploy/vhsp-docker-proxy.service` still runs
`tecnativa/docker-socket-proxy:latest` -- unpinned to a digest or even
a specific version tag. Purely a supply-chain-reproducibility note
(the allowlist scoping itself, which is the security-relevant part, is
unchanged and correct): a future `docker pull`/redeploy on a fresh
host could silently pick up a different proxy build than what's
running in production today. Same observation applies to the base
images used elsewhere (`python:3.12-alpine`, `alpine:3.19`,
`debian:12-slim`) -- tag-pinned, not digest-pinned, which is common
practice but worth a mention alongside Finding #8's more concrete gap.

---

## Closing note

The three explicitly-flagged focus areas held up well under scrutiny:
the fail2ban injection-safety question resolves cleanly once you trace
through fail2ban's own `<HOST>` character-class restriction, the
chown-target question in the tenant-admin UID fix has a clean answer
(four hardcoded constants, verified by reading every call site), and
the static-asset-serving question resolves cleanly once you check what
the Dockerfile actually `COPY`s versus what's merely present in the
source tree. The real findings this pass turned up were adjacent to
those areas rather than inside them: a missing `chmod` on a *different*
secret in the same file that was otherwise carefully fixed (#1), a
design tradeoff in the new fail2ban jail that wasn't fully thought
through for its multi-tenant blast radius (#2), and a pre-existing
authorization gap in the same container that's now carrying more
weight than it used to (#6). None of this should block adoption on its
own, but #1 should be fixed before this goes anywhere near production
traffic, and #2 and #6 are worth a decision (not just a fix) before the
tenant count grows.
