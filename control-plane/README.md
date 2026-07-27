# VHSP control plane (skeleton)

For installing this onto a fresh single-public-IP host (no separate
management network, vhsp's own Traefik as the sole TLS/routing layer),
see `DEPLOYMENT.md` -- a step-by-step prerequisites/install/setup guide
verified end to end on a real host. What follows here is feature
documentation, not an install runbook.

Implements the first slice of `architecture.md`'s "Control plane
responsibilities":

- Provisions a tenant web container (nginx + PHP-FPM, hand-rolled --
  `images/web/`) and a tenant DB container (MariaDB), each with its own
  `noexec,nosuid,nodev`-hardened volume. Dangerous PHP functions
  (`exec`, `shell_exec`, `system`, `proc_open`, etc.) are disabled by
  default per architecture.md's security section, since `noexec` alone
  doesn't stop an interpreter-based webshell -- PHP-FPM itself, not the
  uploaded `.php` file, is what's being exec'd. `open_basedir` additionally
  confines PHP file access to the webroot. A self-service per-tenant
  toggle to re-enable specific functions (the doc's own idea) *is* built
  -- see "Tenant self-service admin page" below. DB connection details
  (`DB_HOST`/`DB_PORT`/`DB_NAME`/`DB_USER`/`DB_PASSWORD`) are injected as
  environment variables and actually reachable from PHP -- required
  setting `clear_env = no` in the PHP-FPM pool, since PHP-FPM's default
  strips the container's environment before PHP ever sees it (verified:
  `getenv()` came back empty and a DB connection attempt failed with a
  misleading "No such file or directory" instead of an obviously
  env-related error).
- Registers Traefik labels so the tenant's domain routes automatically
  (no control-plane involvement in HTTP routing itself).
- Creates a private, `internal` per-tenant Docker network for the DB --
  only that tenant's web container joins it; it's unreachable from the
  shared gateway network, other tenants, or the host's published ports.
- Generates unique DB credentials per tenant at provisioning time (root
  password + app user/password), stored in the registry and injected into
  both containers via environment variables -- not baked into any image.
- Applies per-tenant cgroup limits (`VHSP_DB_MEM_LIMIT`, `VHSP_DB_CPUS`) to
  the DB container.
- Allocates a per-tenant SSH port from the 2200-2299 range and wires it to
  a dedicated per-tenant SFTP-only container (`atmoz/sftp`, forces
  `internal-sftp`, no shell) published directly on that host port --
  chosen over a shared SSH gateway per architecture.md's "no common daemon
  all tenants depend on" reasoning. Mounts the *same* hardened webroot
  volume the web container serves from, under `~/www`, so an upload is
  live immediately with no sync step.
- SFTP is **key-only, no password fallback at all** -- the SFTP container
  is created with an empty password field, which atmoz/sftp treats as "set
  this account's password hash to `*`" (verified directly), permanently
  unmatchable regardless of what's typed. There is no bootstrap password
  and never was one; a freshly-created tenant has *no* SFTP access until
  an operator installs a public key (`vhsp tenant set-ssh-key`, or the
  admin UI's tenant page) -- validated with `ssh-keygen` before
  installing. See `provisioner.set_ssh_public_key`'s docstring for two
  real atmoz/sftp gotchas hit and fixed while building this: an empty keys
  directory crashes the entrypoint outright (glob-expansion-of-nothing
  bug), and a plain `docker restart` does *not* pick up a newly-added key
  -- only a full container recreation does, since authorized_keys is only
  built on the user's first-ever boot.
- Maintains `$VHSP_STATE_DIR/routing/domains.json`, the domain -> container
  table the future SMTP gateway's `transport_maps` will consume.

- Admin web UI (`vhsp_ctl/web.py`) over the same provisioner/registry code
  as the CLI: list/create/destroy tenants, view credentials, view the
  audit log. Form-based login with per-operator identity plus a second
  factor once one is registered -- WebAuthn/FIDO2 (`auth.py`,
  `webauthn.py`) and/or TOTP/authenticator-app (`totp.py`), see "Two-factor
  authentication" below -- multiple operators supported, though
  flat/equal-privilege (no RBAC yet, a confirmed deliberate gap, not an
  oversight). Every create/destroy is
  appended to `$VHSP_STATE_DIR/audit.log` (`audit.py`) with the acting
  identity, per architecture.md's control-plane-auth section -- local and
  append-only only; shipping it off-host isn't built yet.

- Per-tenant mail container (`images/mail/`, hand-rolled Postfix+Dovecot,
  not a prebuilt image) with one starter mailbox (`postmaster@<domain>`,
  the RFC 5321-mandated address). Joins the shared gateway network only
  (same as the web container) -- not the tenant's private DB network.
- Shared inbound SMTP gateway (`images/mailgw/`, single instance, not
  per-tenant) implementing architecture.md's "the one piece that can't be
  solved with routing tricks": a Postfix relay using `transport_maps`
  keyed by recipient domain, regenerated and reloaded on every tenant
  create/destroy (`provisioner._regenerate_mail_gateway_maps`). Publishes
  port 25 directly on the host -- SMTP has no SNI/TLS at connect time, so
  unlike everything else it fundamentally can't go through Traefik.
- IMAPS (993) and SMTPS (465) are SNI-routed straight to the tenant's mail
  container via Traefik TCP passthrough (`tls.passthrough=true`) -- no
  mail-aware proxy needed for these, since (unlike SMTP) the TLS
  ClientHello carries the tenant's mail hostname at connect time, per
  architecture.md's mail-layer section. Deliberately used 465 (implicit
  TLS) over 587 (STARTTLS) for authenticated submission, since 587 doesn't
  have a TLS ClientHello until *after* the plaintext SMTP session has
  already started -- SNI passthrough can't route on something that
  doesn't exist yet.
- Real bugs hit and fixed while building the mail layer (each verified by
  actually sending/retrieving mail, not just checking containers were
  "Up" -- see the relevant docstrings for full detail):
  - **Dovecot auth "temp_fail" on every login.** The passwd-file was
    `root:600`; Dovecot's auth worker reads it as an unprivileged
    `dovecot` user and silently can't. Fixed: `root:dovecot`, `640`.
  - **Debian's Postfix chroots the outbound `smtp` delivery agent by
    default**, which can't see `/etc/resolv.conf` inside the jail --
    breaks DNS resolution for every nexthop, including the gateway's
    relay to a tenant's mail container by container name. Fixed with
    `postconf -F 'smtp/unix/chroot=n'` in both mail images.
  - **Postfix transport_maps tries an MX lookup on the nexthop by
    default**, and Docker's embedded DNS returns a retryable error (not a
    clean "no MX") for MX queries on container names -- mail sits queued
    forever with a "Name service error" that looks DNS-related but isn't,
    it's an MX-vs-A distinction. Fixed with bracket notation
    (`smtp:[container]:25`), which disables the MX lookup.
  - **Traefik silently drops TCP routers when one container defines more
    than one** (here: IMAPS + SMTPS on the same mail container) and it has
    to guess which same-container service each router should use --
    "cannot be linked automatically with multiple Services", and *both*
    routers vanish from `/api/tcp/routers`, not just one. Fixed with an
    explicit `traefik.tcp.routers.<id>.service=<id>` label per router.

Not in scope for this pass: DNS/DKIM/SPF/DMARC *push* automation (a
`vhsp dns records` command exists to suggest/verify records, but nothing
writes to a real DNS host -- architecture.md marks the two zone-hosting
models as separate, undecided work), outbound mail abuse/rate-limiting,
RBAC for the admin UI (MFA/WebAuthn *is* built, see "Admin web UI"
below). See `architecture.md` for the full design and open questions.
(Backups are now implemented -- see "Backup / restore" below. DB/mailbox/
panel-login credential rotation is now implemented too, as an
operator-only incident-response lever, not tenant self-service or
scheduled rotation -- see "Admin web UI" -> "Incident response" below.
SFTP has no password to rotate -- it's key-only; `vhsp tenant
set-ssh-key` already covers replacing that.)

## Requires

- The shared gateway network (`traefik` by default) must already exist.
- The user running this needs passwordless sudo, but **scoped**, not
  blanket -- the noexec/nosuid/nodev mount hardening (see "Mount
  hardening" below) requires real `mount(8)`/`/etc/fstab` calls, which
  need root. See "Sudo scoping" below for why this is two specific
  root-owned wrapper scripts plus restart access for the four
  vhsp-managed systemd units, not `ALL=(ALL) NOPASSWD:ALL` -- a blanket
  grant on the same account running the internet-facing admin process
  used to mean any RCE there was equivalent to root.
- Docker access is scoped, not raw `docker` group membership -- see
  "Docker socket exposure" below. `vhsp-docker-proxy.service` must be
  running before `vhsp-admin`/`vhsp-backup`/`vhsp-backup-reconcile` start.
  A human running `docker build`/`docker ps`/`docker logs` by hand needs
  actual root (e.g. a separate root SSH credential, not this account's
  own scoped sudo grant, which deliberately doesn't cover `docker`)
  rather than expecting ambient `docker` group access, since that
  account is deliberately not a member of it on a hardened deployment.
- `docker build -t vhsp-web:latest images/web`,
  `docker build -t vhsp-mail:latest images/mail`,
  `docker build -t vhsp-mailgw:latest images/mailgw`, and
  `docker build -t vhsp-tenant-admin:latest images/tenant-admin` once,
  before the first `tenant create` -- these aren't published anywhere,
  they're built locally from this repo.
- Traefik needs `imaps`/`smtps` TCP entrypoints (ports 993/465) in
  addition to the `web` entrypoint from the KVM setup notes -- not
  something the control plane manages itself, it's one-time Traefik
  config alongside creating the `traefik` network in the first place.
- Traefik also needs an `mgmtweb` HTTP entrypoint (port 8090) published
  bound *specifically* to the management interface's IP in its
  `docker-compose.yml` (e.g. `192.168.100.235:8090:8090`) -- the tenant
  self-service admin page's entire access control depends on this being
  an IP-bound publish, not the `8090:8090` shorthand that binds `0.0.0.0`
  and would make it reachable from the tenant-facing side too.
- `age`/`age-keygen` (e.g. `apt-get install age`) -- unlike `openssl`/
  `ssh-keygen`, this is not already ambient on a typical host; see
  "Backup / restore" below for what it's used for.

## Dependency lockfile

`pyproject.toml` uses floating `>=` floors only (`docker>=7.0`,
`flask>=3.0`, `cryptography>=42.0`, etc.) -- fine for normal development,
but it means a fresh install can silently pull newer, untested
transitive dependencies with no warning. `requirements-lock.txt` pins
the exact versions verified working on the real vhsp2.dvce.us
deployment (`pip freeze` against its live venv, stripped of the
checkout-path-specific editable-install line). Install order for a
reproducible environment:
```
python3 -m venv .venv
.venv/bin/pip install -r requirements-lock.txt
.venv/bin/pip install -e .
```
`pyproject.toml`'s own floors are unchanged and still what
`pip install -e .` alone would resolve against -- the lockfile is an
opt-in extra step for a production install, not a replacement. Regenerate
it after intentionally upgrading a dependency (`pip freeze | grep -v
'^-e \|^# Editable' > requirements-lock.txt`); no new tooling
(`pip-tools`/`uv`) added, matching this project's minimal-dependency
style elsewhere.

**Verified on vhsp2**: a completely separate, throwaway venv (not the
live one backing running services) built from `requirements-lock.txt` +
`pip install -e .` installed cleanly, `pip check` reported no dependency
conflicts, and `vhsp --help` ran correctly.

## Real client IPs in tenant nginx access logs

Every tenant web container's nginx trusts exactly one reverse-proxy hop by
default -- the local Traefik it always sits behind, resolved by container
name (`traefik`) at entrypoint startup, not a hardcoded IP. With nothing
else in front of that Traefik, this alone is enough for `$remote_addr` in
`/var/log/vhsp/web-access.log` (surfaced in the tenant admin page's Logs
view) to show the real client IP.

If something else sits in front of *that* Traefik too -- e.g. this VM's
actual deployment, where a swarm-hosted Traefik instance fronts it -- two
more things are needed, or every access log line instead shows that
outer Traefik's own address (still wrong, just a different wrong value):

1. That outer Traefik needs `forwardedHeaders.trustedIPs` set to the
   subnet it's reachable from, so it forwards through the `X-Forwarded-For`
   chain it already computed correctly instead of discarding it. On this
   deployment that's `--entrypoints.web.forwardedHeaders.trustedIPs=172.16.45.0/24`
   in `/home/astjohn/traefik/docker-compose.yml` on the VM (outside this
   repo -- that file isn't managed by the control plane).
2. Set `VHSP_WEB_TRUSTED_PROXY_CIDRS` (comma-separated CIDRs) before
   provisioning/recreating tenant web containers, so their nginx also
   trusts that second hop and walks past it
   (`real_ip_recursive on`) to the next entry in the chain. On this
   deployment: `VHSP_WEB_TRUSTED_PROXY_CIDRS=172.16.45.0/24`.

Verified end-to-end against the real deployed containers, not just in
isolation: confirmed the outer Traefik was silently overwriting
`X-Forwarded-For` with its own address before either fix (temporarily
logged the raw header to see it), fixed both hops, then confirmed a real
external visitor's actual public IP came through correctly in the access
log (a same-LAN test only recovers as far as the trusted CIDRs allow --
hairpin NAT on a home/office router can still mask a same-network test as
the router's own address, which isn't a bug in this fix, just an
artifact of testing from inside the same network the server is behind).

## Mount hardening: a real gotcha, not just a config flag

Docker's `local` volume driver bind-mounts a host directory with a single
raw `mount(2)` syscall. The kernel silently drops `noexec`/`nosuid`/`nodev`
on a bind mount unless they're applied via a *separate remount pass* --
which the `mount` CLI does automatically, but Docker's driver does not.
Passing `o=bind,noexec,nosuid,nodev` as a volume's `driver_opts` looks like
it should work and doesn't; verified by writing and executing a script
inside a volume created that way.

The fix (`provisioner._harden_host_dir`): before Docker ever touches the
tenant's directory, the control plane bind-mounts it to itself with
`noexec,nosuid,nodev` directly (`sudo mount --bind ... -o noexec,...`) and
adds a matching `/etc/fstab` entry so it survives a reboot. Docker's
later bind mount of that already-hardened path inherits the flags, since a
plain bind can't relax them.

## Usage

```
python3 -m venv .venv
.venv/bin/pip install -e .

.venv/bin/vhsp tenant create example.local
.venv/bin/vhsp tenant list
.venv/bin/vhsp tenant show example.local   # re-display DB credentials etc.
.venv/bin/vhsp tenant destroy example.local
```

State lives in `$VHSP_STATE_DIR` (default `/srv/vhsp`): a SQLite registry
(0600, holds DB credentials in plaintext -- see registry.py's note on why
that's a stopgap), the routing table JSON, and per-tenant
webroot/db directories.

`destroy` deletes the tenant's host-side directories outright (not just the
Docker volumes) -- see `_remove_host_dir`'s docstring for why leaving them
around causes a real, verified breakage on re-provisioning the same
domain (MariaDB chowns its datadir to an internal uid on the host).

## Admin web UI

Deliberately kept off the tenant-facing gateway on this dev VM: it has two
interfaces (see the KVM setup notes) -- the tenant/Traefik-facing NAT
network, and a second, isolated `vhsp-mgmt` NAT network the admin UI binds
to exclusively. Nothing published on the tenant-facing interface can reach
it; verified by curling the admin port from both interfaces during setup.
This two-NIC split is specific to this dev VM's topology, not the target
production shape -- see architecture.md's "Single public IP on the target
host" section, and `DEPLOYMENT.md` for how the same admin UI is deployed
*publicly*, with WebAuthn carrying the access-control weight that network
position can't on a single-IP host.

```
.venv/bin/vhsp admin init            # bootstrap the first operator (password shown once)
.venv/bin/vhsp admin add-operator    # add another named operator
.venv/bin/vhsp admin list-operators
.venv/bin/vhsp admin remove-operator
.venv/bin/vhsp admin reset-password  # regenerate an operator's password

VHSP_ADMIN_BIND_HOST=<mgmt-interface-ip> .venv/bin/vhsp-admin
```

Login is form-based (session cookie), not HTTP Basic -- per-operator
identity plus a second factor once one is registered from `/account`
(WebAuthn and/or TOTP, see "Two-factor authentication" below). Multiple
operators are supported but flat/equal-privilege; there's no
per-role scoping yet (see "Known gaps" below). Sessions (here and on a
tenant's own panel login) expire after 30 minutes idle by default --
`VHSP_ADMIN_SESSION_LIFETIME_MINUTES` / `TENANT_ADMIN_SESSION_LIFETIME_MINUTES`
to change it.

The `/login` page (only that page -- not the `/login/2fa` challenge that
follows it) embeds a Buy Me a Coffee button (third-party script,
`cdnjs.buymeacoffee.com`), since it's the single most publicly-reachable
page on the whole platform -- reachable by anyone who hits the
deployment's hostname, no auth required to see it.

### Billing account ID

Optional, plain (not encrypted -- it's an identifier, not a credential)
free-text field per tenant, set from the Overview page (or `vhsp tenant
set-billing-account-id <domain> <id>`) and shown in the Tenants list --
purely to tie a tenant to an account in external billing software, no
meaning to the platform itself. Deliberately operator-only: there's no
writer for it anywhere in `images/tenant-admin/app.py`, and it's never
shown on a tenant's own admin page. Never required -- `vhsp tenant
create` doesn't ask for it; the column defaults to empty and stays that
way until an operator sets it.

If (and only if) this deployment sits behind exactly one reverse proxy hop
that terminates TLS and forwards over plain HTTP -- e.g. this VM's own
setup, where the swarm's Traefik fronts `vhsp.dvce.us` -- set
`VHSP_ADMIN_TRUST_PROXY=1` so Flask trusts that hop's `X-Forwarded-*`
headers (via Werkzeug's `ProxyFix`) for the real client IP/scheme/host
instead of seeing the proxy's own address and plain HTTP on every request.
Off by default: turning this on with no reverse proxy in front (or more
than one untrusted hop) lets any direct client spoof those headers, so
don't set it unless the deployment's request path genuinely matches.

Deployed as a systemd unit (`deploy/vhsp-admin.service`), `gunicorn
--workers 2` behind it rather than Flask's own dev server (see "CSRF
protection and a real WSGI server" below), `Restart=on-failure`, enabled
at boot.

Known gaps, beyond what's already listed above: no RBAC (operators are
flat/equal-privilege -- architecture.md's control-plane-auth section calls
this out as a real, confirmed-deliberate gap, not an oversight).

### Incident response (per-tenant, on the tenant detail page)

Four buttons, separate from "Reset tenant admin password" and "Clear all
WebAuthn keys" above (both of which stay narrow and non-destructive --
routine lockout recovery for one known login, nothing else touched). These
four are coarse on purpose, for a *suspected compromise*: the operator has
no way to tell which specific login/mailbox/credential is the compromised
one, and an attacker who reached the panel could have added a backdoor of
their own -- so each resets **all** of its category at once rather than
targeting one. Every new credential is generated, shown once in a flash
message, and not saved anywhere else in this UI (same "shown once" pattern
as every other generated credential here). All four are audit-logged
(`tenant.reset_panel_access` / `reset_mailbox_passwords` / `reset_db_password`).

- **Admin password nuke** (`provisioner.reset_tenant_panel_access`) --
  wipes *every* tenant-admin panel login (not just `admin`, any
  team-member logins the tenant added themselves) down to one fresh,
  randomly-generated `admin` account, and rotates the panel's Flask
  session-signing secret (`tenant_admin_flask_secret`), restarting the
  tenant-admin container so that takes effect. The secret rotation is the
  actual point: panel sessions are a signed cookie checked against that
  secret, not re-verified against `tenant_users.json` on every request, so
  a password reset alone would leave an *already-logged-in* attacker's
  session working right through it. No downtime -- only the tenant-admin
  container restarts, not the tenant's website.
- **Email password nuke** (`provisioner.reset_tenant_mailbox_passwords`,
  `toggles.reset_all_mailbox_passwords`) -- regenerates a fresh password
  for every mailbox on the tenant at once. Mailbox self-service isn't
  owner-gated (see the tenant-admin RBAC section above), and panel access
  already shows the DB password in plaintext to any logged-in panel user,
  so a compromised panel login of any kind is a plausible route to a
  compromised mailbox too. Existing mail clients need reconfiguring
  afterward. No downtime, no container changes -- `images/mail/`'s
  entrypoint watches `mailboxes.txt` and reloads Dovecot live, same path
  the tenant's own single-mailbox self-service reset already uses.
- **Database nuke** (`provisioner.reset_tenant_db_password`) -- the one
  with a real cost. Runs a live `ALTER USER ... IDENTIFIED BY ...` against
  the tenant's DB container (as `db_root_password`, never exposing that
  root credential itself), then **recreates** (not restarts -- `DB_PASSWORD`
  is baked into container env at create time, not hot-reloadable) both the
  web container and the tenant-admin container so they pick up the new
  value. This is real credential rotation, something this platform never
  had before (`_create_web_container` was factored out of `create_tenant()`
  specifically to make the recreate here possible without duplicating its
  volume/label/network wiring). **Brief downtime on the tenant's actual
  website** while those two containers restart (seconds, verified
  end-to-end on a real tenant: site back to a real `200` within ~10s).
  Doesn't touch panel logins or mailboxes.
- **Nuke all passwords** (`provisioner.reset_tenant_all_passwords`) -- all
  three above in one action, in that order (DB last, since it's the only
  one with downtime -- a failure partway through still leaves the cheaper,
  already-applied resets in place rather than the reverse). Returns and
  flashes all three new credentials at once.

## Tenant self-service admin page

Per-tenant (`images/tenant-admin/`, one container per tenant, not
shared), routed publicly at `https://admin.<tenant-domain>/` with a real
cert -- required, since WebAuthn needs a stable public origin to register
against. On this dev VM it's *also* reachable at
`admin.<tenant-domain>:8090` on the management network only (Traefik's
`mgmtweb` entrypoint bound to the management interface's IP specifically,
e.g. `192.168.100.235:8090:8090`, not the `8090:8090` shorthand that would
bind `0.0.0.0`) -- but that's a bonus path specific to this VM's two-NIC
topology (`VHSP_TENANT_ADMIN_MGMTWEB_EXISTS`), not the primary access
control; a single-public-IP deployment (`DEPLOYMENT.md`) has no such
network to fall back to. Login is form-based, per-account, with a second
factor once one is registered from the Security key page -- same model
and code path as the operator admin UI above (WebAuthn and/or TOTP, see
"Two-factor authentication" below). Multiple named users per tenant
supported.

Two roles, **owner** and **member** (a `role` field in `tenant_users.json`,
default "member" for anyone added via the Team page) -- unlike the
operator side above, this one *is* role-gated. Members get everything
except: managing the team itself, changing the backup destination or
restoring a backup, and the SQL console -- all real "lose data" or
"exfiltrate data" surfaces, not just "sensitive". At least one owner is
always guaranteed to exist (`remove_user`/`set_user_role` both refuse to
drop the last one) -- otherwise a team of members-only would be
permanently unable to reach any owner-only surface itself, recoverable
only through the operator's own coarse tools (`vhsp tenant show`'s
password-reset lever). Pre-RBAC installs migrate lazily: every existing
user with no `role` field becomes "owner" on first load, the same
undifferentiated access they already had.

Two features so far:

### PHP function toggle

Re-enabling specific PHP functions the web container disables by default,
with per-function descriptions and a warning. Getting this to actually
take effect without violating
architecture.md's "tenant self-service stays local to the tenant's own
container, not a call back into a shared control-plane API" -- and
without giving a tenant-facing container access to `docker.sock` to
restart its own web container, which would be root-equivalent on the
host -- shaped the whole design:

- The tenant-admin container only ever *writes* a plain list of
  currently-enabled function names to a small shared volume (`phpconf`,
  hardened the same as every other tenant volume).
- The web container's own entrypoint (`images/web/entrypoint.sh`) is what
  reads that file, regenerates its PHP-FPM pool's `disable_functions`
  directive, and reloads itself (`SIGUSR2` -- verified this spawns
  genuinely new worker processes that pick up the change, not just a
  config re-read with old workers still running old settings) via a
  background loop polling the file's mtime every few seconds.
- No cross-container signaling, no shared PID namespace, no API call --
  the only thing that crosses the container boundary is a write to a
  volume both containers already have mounted (write for tenant-admin,
  read-only for web).

Verified end-to-end through the real deployed containers, not just a
standalone test: toggled `exec` on via the actual `admin.demo1...`
hostname, confirmed a PHP script on the real tenant domain saw it enabled
within the poll interval, confirmed a second tenant's toggle state stayed
completely independent, then reverted and confirmed it was disabled again.

### 404 handling, password protection, error pages, redirects, IP restrictions

nginx has no per-directory config file the way Apache's `.htaccess` does,
so anything a tenant would normally self-serve through `.htaccess` needs a
real toggle here instead: a front-controller-aware 404 fallback (prefers
`index.php` over `index.html` so WordPress/Laravel-style pretty permalinks
work out of the box -- opt out per-tenant with an empty
`.vhsp-no-404-fallback` file in the webroot, writable via SFTP directly,
no admin-page involvement needed for that one), HTTP Basic Auth for the
whole site, `CODE /path` custom error pages, exact-path 301 redirects, and
an IP allow/deny list. Each writes a small, independently-validated data
file to the shared `phpconf` volume; images/web/'s own entrypoint is the
only thing that ever turns them into real nginx syntax, and it validates
everything a second time with `nginx -t` before reloading -- a bad value
here can only ever break that one tenant's own site (fully separate
nginx process/container per tenant), never anyone else's, but "reload into
a config that won't parse" is still worth guarding against on its own.

Real bug hit and fixed here: `nginx -t` creates an empty placeholder pid
file as a side effect even in test-only mode. The first cut checked
`[ -f nginx.pid ]` to decide whether nginx was already running before
attempting a reload, which false-positived on that empty file and fired a
premature `nginx -s reload` -- which fails loudly enough under `set -e` to
abort the whole entrypoint and crash-loop the container. Fixed by checking
the pid file is non-empty *and* actually corresponds to a running process
(`kill -0`), and by guarding the reload call itself with `|| true` so a
future reload failure can never take the container down again.

### Email

Mailbox add/remove/password-reset beyond the one starter `postmaster@`
mailbox provisioning creates (kept undeletable here -- RFC 5321 requires
every domain to accept mail for it). Same split as the nginx toggles:
tenant-admin only ever writes `username:SHA512-CRYPT-hash` lines to a
`mailboxes.txt` on the shared `phpconf` volume (passwords hashed
immediately with `passlib`, the plaintext never touches disk); the mail
container's own entrypoint watches that file and regenerates dovecot's
passwd-file and postfix's `vmailbox` map from it, reloading both. Seeded
by `provisioner.py` at tenant-creation time (via `openssl passwd -6
-stdin`, the actual authority on the hash format dovecot's
`scheme=SHA512-CRYPT` passdb expects) so the file is the single source of
truth for every mailbox, postmaster included, from the very first boot.

### Logs

Read-only view of web (nginx access/error + PHP-FPM error), mail
(Postfix + Dovecot, combined), and SFTP logs -- last 200 lines each,
reload to refresh. Same reasoning as the PHP toggle for why this reads
files off a shared volume instead of calling `docker logs`: that would
need `docker.sock`, i.e. root on the host, mounted into a tenant-facing
container. Getting there took more fixing than expected, since none of
these three sources wrote usable log files by default:

- **nginx** logs to files inside its own container filesystem unless
  redirected -- just needed `access_log`/`error_log` pointed at the
  shared `logs` volume.
- **Postfix and Dovecot both default to syslog**, and these are minimal
  containers with no syslog daemon (verified: `/dev/log` doesn't exist) --
  messages were going nowhere. Fixed with Postfix's `maillog_file` and
  Dovecot's `log_path`, both pointed at the same combined `mail.log`,
  matching the traditional single-mail-log layout.
- **atmoz/sftp** (third-party image, can't edit its Dockerfile) already
  writes connection/auth events to its own stdout -- but that only reaches
  `docker logs`, not a file. Wrapped its entrypoint with a shell script
  that `exec`s the real `/entrypoint` with stdout/stderr redirected into
  the shared volume via `>>`, not a `tee` pipe -- `exec` keeps the
  replaced process at PID 1 so it still receives docker's stop signal
  directly; a `tee` pipe would leave a wrapper shell holding PID 1 instead.
- **All three** of Postfix/Dovecot/php-fpm create their log files with
  restrictive permissions (verified: `root:root 600`) regardless of the
  parent directory's mode -- opening an existing file for append doesn't
  change its mode, so each entrypoint now pre-creates its log file with
  `touch` + `chmod 666` before the logging process starts.

Verified with real activity end-to-end: a live HTTP request, a real
inbound email through the actual gateway, and a failed SFTP password
attempt (itself a meaningful log entry, since these tenants are key-only)
all showed up correctly in the real `admin.demo1...:8090/logs` page,
correctly HTML-escaped, with a second tenant's logs staying completely
separate.

### Database password: owner-only

The Overview page (`/`) shows a tenant's DB connection info -- host,
name, user, password -- but only the password itself is gated to the
`owner` role now. A member sees host/name/user (still useful: it's what
their own application is already configured to connect to) with
`password visible to owners only -- see /database` in place of the
value. This closes a real gap: the SQL console at `/database` is
deliberately `require_role("owner")`-gated, but the DB password grants
identical access to what that console offers, so showing it on an
ungated page made the console's own gate pointless -- a member denied
`/database` could just take the password from `/` to any external DB
client instead. `/database` itself is unchanged (still 403s a member);
this only removes the value from the one page that wasn't already
gated to match.

## phpconf file ownership: chowning container-written credential files back to the host user

`images/tenant-admin/`'s container has always run as root (no `USER` in
its Dockerfile), so any file it creates on the shared `phpconf` bind
mount is root-owned on the host. Most files there are fine either way
(root can always write them, and nothing on the host side ever needs to
read them back). Four aren't: `webauthn_credentials.json`,
`totp_secrets.json`, `tenant_users.json`, and `login_attempts.json`
(the lockout *state* file -- not `login_attempts.log`, the fail2ban
one, which is already deliberately world-readable, see the fail2ban
section) are all written 0600 by `app.py`, and two of them --
`webauthn_credentials.json` and `tenant_users.json` -- are also read or
written directly from the **host** side by `provisioner.py`
(`count_tenant_webauthn_keys` for the operator's tenant-detail page,
`reset_tenant_admin_password` for the "Set tenant admin password"
recovery action), running as whatever OS user runs
`vhsp-admin.service`. Root writing one of those files first breaks that
host-side access outright -- a plain Python `open(..., "r")` as a
non-root user against a `0600 root:root` file is just `PermissionError:
[Errno 13]`, no privilege escalation path around it.

**Found as a real, currently-broken page**, not a theoretical gap: the
operator's `/tenants/<domain>` page started 500ing on `smoketest`
partway through this session's fail2ban work, once
`webauthn_credentials.json` happened to get rewritten (root-owned) by
its lazy legacy-entry migration path -- almost certainly triggered by
the fail2ban jail verification's own repeated logins against that
tenant's admin panel. `tenant_users.json` had the identical latent bug,
just not yet triggered on any live tenant at the time this was found.

Fixed with a UID handoff rather than loosening any file's permissions
(WebAuthn/TOTP/password-hash data staying 0600 and non-world-readable
matters more here than papering over the mismatch): `provisioner.
_create_tenant_admin_container` passes its own `os.getuid()`/
`os.getgid()` into the container as `VHSP_HOST_UID`/`VHSP_HOST_GID`;
`app.py`'s four write helpers `os.chown()` each file back to that UID
right after their existing `os.chmod(..., 0600)`. Root inside the
container can still freely read/write these files afterward
(`DAC_OVERRIDE` -- ownership never restricted root's own access, only
everyone else's), so nothing about the container's own behavior
changes; only *who* the file belongs to on the host does. No-ops
gracefully (stays root-owned, today's pre-fix behavior) if a container
somehow starts without those two env vars set, rather than raising.

**Verified on vhsp2**: rebuilt `vhsp-tenant-admin:latest`, recreated
both live tenants' containers, confirmed the new env vars actually
landed (`docker inspect` showing `VHSP_HOST_UID=1000`/`VHSP_HOST_GID=1000`,
astjohn's real host UID/GID). Manually `chown`'d the pre-existing
root-owned files on both tenants back to astjohn (the code fix only
takes effect on the *next* write; it doesn't retroactively fix files
written before it shipped). Confirmed `provisioner.
count_tenant_webauthn_keys("smoketest.vhsp2.dvce.us")` -- the exact
call the broken page made -- now returns cleanly instead of raising,
and confirmed both tenants' live sites and admin panels still serve
traffic normally after the container recreate.

## Files page: CodeMirror in-browser editor

`/files/edit` used to be a plain `<textarea>` (still capped at
`FILES_MAX_EDIT_BYTES`, 2MB, above which it's more likely to hang a
browser tab than help). Replaced the widget, not the mechanism: a
vendored CodeMirror 6 build (syntax highlighting for PHP/JS/TS/CSS/
HTML/JSON/SQL/Python/Markdown/YAML/XML, line numbers, bracket matching)
mounts over the same textarea client-side and mirrors every keystroke
back into it, so `files_edit()`'s server-side save path
(`request.form.get("content", "")`, unchanged) has no idea the input
widget changed at all -- this was a pure frontend swap.

Vendored, not CDN-loaded (`images/tenant-admin/static/vhsp-editor.bundle.js`,
~800KB minified/~270KB gzipped, MIT-licensed -- see that directory's own
`README.md` for the entry-point source and rebuild instructions, and
`vhsp-editor.bundle.js.LICENSE.txt` for attribution), matching this
project's "no external runtime dependencies" posture everywhere else.
Theme follows `prefers-color-scheme` like the rest of this app's own
`DARK_AWARE_CSS` -- CodeMirror's `oneDark` theme under the dark media
query, its own plain (light) default otherwise -- rather than a
hardcoded theme independent of the page around it.

**Verified**: a real Docker build + standalone container run confirmed
the static route serves the bundle correctly (200,
`text/javascript`) and every other route is unaffected. Since no
authenticated browser session was available to click through this in a
real UI, the bundle's actual behavior was verified by executing the
real built file (not a rewritten test copy) against a jsdom-simulated
DOM: mounts correctly, hides the original textarea, loads the file's
real starting content, PHP syntax highlighting produces real
highlighted spans (language support wired up correctly, not silently a
no-op), and -- the one thing that actually matters for correctness --
dispatching a real CodeMirror edit transaction (the same code path a
keystroke takes) correctly syncs the change back into the underlying
textarea, both via the live update listener and the form's own submit
handler.

## Follow-up security review (2026-07-24): 7 findings fixed, 1 partially

A second CISO-style review (same read-only, doc-vs-code audit posture as
the original 10-item review, see "CISO-style security review +
remediation plan" in project history), scoped specifically at what had
shipped since: fail2ban, the tenant-admin UID/chown fix, and the
CodeMirror static asset addition, plus a general sweep. Full report
kept at `SECURITY_REVIEW_2.md`. No regressions found in any of the
original 10 items. Seven of the eleven findings fixed (six same-day,
one -- the fail2ban path-consistency check below -- as an explicit
follow-up once asked to); the fail2ban
injection-safety, chown-target, and static-asset-serving questions the
review specifically scrutinized all came back clean.

**[Critical] Tenant-admin session secret was written world-readable.**
`images/tenant-admin/app.py`'s `SECRET_KEY_FILE` -- the key Flask signs
every session cookie with -- was missing the `os.chmod(0600)` call its
own comment claims it copies from `vhsp_ctl/auth.py:ensure_secret_key`
(which does chmod it). Anyone able to read this file for a tenant could
forge an arbitrary session and land on full owner access with no
password and no 2FA -- `require_login`/`require_role`/`require_2fa` all
just inspect `session[...]`, none re-verify a live credential. Fixed:
added the missing `os.chmod` + `_chown_to_host` call, same treatment as
the other four sensitive files this container writes. Confirmed live on
vhsp2 both tenants' `flask_secret_key` were genuinely `644 root`/`644
astjohn` beforehand (the code fix alone doesn't retroactively fix a
file already on disk -- had to `chmod`/`chown` both by hand too, same
"next write only" caveat the original webauthn ownership fix already
documented) and are `600 astjohn` now.

**[High] `[vhsp-tenant-admin-login]` fail2ban jail's ban blast radius.**
Inheriting `[DEFAULT]`'s `maxretry=5`/`bantime=30m` meant 5 routine
failed logins against *any one* tenant's admin panel -- the same
background-scanner noise every internet-facing host gets, not a
targeted attack -- firewalled that IP off of every tenant's public site
for 30 minutes, since a ban here is platform-wide regardless of which
tenant's log triggered it (every tenant shares port 443 through one
Traefik instance). Fixed by giving this one jail its own, much more
conservative thresholds (`maxretry=20`, `findtime=15m`, `bantime=15m`)
instead of the shared default -- a higher bar to trigger, and a shorter
collateral-damage window if it still does. The per-account app-level
lockout (`LOGIN_ATTEMPTS_FILE`, source-IP-independent, unaffected by
this) stays the primary defense against credential stuffing on one
account; this jail is now a backstop against a genuinely abusive single
source, not the first line of defense.

**[High] `/email` required neither owner role nor 2FA.** Any team
member could reset any mailbox's password (`postmaster@` included),
delete mailboxes, or add new ones -- `require_2fa`'s own docstring had
explicitly classified mailboxes as "routine, lower-impact." Reclassified:
email is the recovery path into most of what a tenant owns *outside*
this platform too (registrar, billing, other SaaS), so a no-2FA member
compromise taking over `postmaster@` is a bigger prize than it first
looks. Fixed: `/email` now requires `@require_2fa` (matching
`/redirects`/`/noexec-dirs`/`/ip-acl`); the `reset` and `delete` actions
specifically are further gated to `@require_role("owner")` (same
action-level pattern already used for `/backup`'s `save_settings`/
`restore`), while day-to-day `add`/`quota` provisioning stays available
to members. The page itself now shows members a read-only view of the
reset/delete controls with an explanation, rather than just 403ing a
form submit after the fact.

**[Medium] tenant-admin and SFTP containers had no cgroup limits.**
`DB_MEM_LIMIT`/`WEB_MEM_LIMIT`/`MAIL_MEM_LIMIT` existed; these two
didn't, despite tenant-admin carrying real memory-spike surface (a
200MB upload endpoint, an arbitrary-SQL console). Added
`TENANT_ADMIN_MEM_LIMIT`/`NANO_CPUS` (512MB/1 CPU -- matches DB/web/mail
rather than going lighter, deliberately: a smaller cap plus Werkzeug's
upload buffering plus gunicorn's own baseline risked OOM-killing a
*legitimate* large upload, not just an abusive one) and
`SFTP_MEM_LIMIT`/`NANO_CPUS` (256MB/0.5 CPU -- SFTP has no equivalent
buffering concern, OpenSSH streams through small buffers regardless of
transfer size). New `recreate_sftp.py` (mirroring `recreate_web.py`'s
own reasoning) -- critically passes the tenant's *existing*
`ssh_keys_volume` rather than a fresh one, since `_create_sftp_container`'s
own docstring warns atmoz/sftp only builds `authorized_keys` from that
volume on a container's first-ever boot. Verified on vhsp2: recreated
both live tenants' tenant-admin and SFTP containers, confirmed via
`docker inspect` all four report the correct `Memory`/`NanoCpus`,
confirmed `testing.bigchimp.org`'s real SFTP key (`smoketest` never had
one set) was still present in `authorized_keys` after its SFTP
container's recreate -- the exact failure mode the docstring warns
about, checked directly rather than assumed.

**[Medium] tenant-admin's Python dependencies installed fully unpinned.**
`images/tenant-admin/Dockerfile` did a bare `pip install flask passlib
fido2 pymysql pyotp qrcode gunicorn` with no version pins -- every image
rebuild could silently pull newer versions of `fido2` (this container's
entire WebAuthn implementation) or `pymysql` (the SQL console's
transport). Fixed: new `images/tenant-admin/requirements-lock.txt`
(same `pip freeze`-derived, tracked-separately-from-loose-dev-floors
pattern as the control-plane's own top-level lockfile), Dockerfile now
`COPY`s it and does `pip install -r` instead of a bare package list.
Verified: a real Docker build against the pinned versions succeeds and
the resulting image starts and serves `/login` correctly.

**[Low] Two smaller fixes.** A stale comment in
`vhsp_ctl/fail2ban_allowlist.py` claimed the allowlist file needs to
stay `grep -Fxq`-parseable; the real check script has done real CIDR
containment via Python's `ipaddress` module since Part 1 of the
fail2ban work -- corrected. `_chown_to_host()` (the helper backing the
critical fix above and the earlier webauthn-ownership fix) silently
no-ops if `VHSP_HOST_UID`/`GID` are ever missing from a container's
environment -- added a stderr warning (visible in `docker logs`) so a
future refactor that accidentally drops those two env vars produces a
loud regression instead of a silent one.

**[Medium] fail2ban wrapper-script paths were comment-enforced only,
now checked by a new `vhsp doctor` command.** Both
`deploy/vhsp-fail2ban-allowlist-check` and
`deploy/vhsp-fail2ban-tenant-jail` hardcode `OPERATOR_LIST`/
`TENANTS_DIR` paths derived from `config.py`'s `STATE_DIR`
(`VHSP_STATE_DIR`), with nothing actually enforcing the two copies stay
in sync beyond a "must match config.py's X" comment in each script.
These scripts run outside this process entirely -- one via fail2ban's
own root-owned systemd service, one via sudo -- so there's no live
Python import boundary to share the value through; templating the
paths in at install time was the alternative considered and rejected
here as more machinery than a fails-*safe* (over-bans, doesn't skip
real bans), deployment-time-only edge case warrants. Instead: new
`vhsp doctor` command (`vhsp_ctl/cli.py`) reads each installed script's
actual hardcoded value straight off disk and asserts it matches
`config.py`'s current value, printing a clear per-check result and
exiting non-zero if anything's out of sync -- turns a silent drift into
a loud, actionable one, safe to run by hand or wire into a deploy
check. Skips (doesn't fail) if a script isn't installed yet, since
that's a legitimate pre-deploy state, not drift.

**Verified on vhsp2**: a clean run against the real installed scripts
reports all three checks passing. To confirm it actually catches real
drift and not just a config.py-vs-itself tautology, deliberately edited
the live installed `vhsp-fail2ban-tenant-jail` to a wrong path,
re-ran `vhsp doctor`, confirmed it correctly reported the exact
mismatch and exited 1, then restored the original file (diffed against
the repo source to confirm the restore was byte-for-byte clean) and
confirmed a clean run passes again.

**[Low, partially fixed] Security response headers.** Split into two
tracks given very different cost: three headers with no legitimate
reason to differ by deployment or page (`X-Content-Type-Options:
nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy:
strict-origin-when-cross-origin`) were added via a new `@app.after_request`
hook on both admin apps -- one-line-per-header, zero behavior change,
zero risk. A real `Content-Security-Policy` is deliberately **not**
included: both admin UIs lean heavily on inline `<script>`/`<style>`
throughout (WebAuthn ceremonies, the CodeMirror mount script, DNS
copy-to-clipboard, per-page `<style>` blocks), so a CSP that actually
restricts `script-src` needs a per-request nonce threaded into every
one of them -- a real refactor, not a header add, and one where a CSP
violation fails *silently* client-side rather than raising a Python
exception, so it needs real browser testing to trust (not available
this session -- no Chrome extension connected). Deliberately left as a
separate, later follow-up rather than shipping a `'unsafe-inline'` CSP
that would permit almost exactly what CSP exists to block. Verified on
vhsp2: all three headers confirmed present on real responses from the
operator UI and both live tenants' admin panels (`curl -sI`), no
regressions in either app or the editor bundle's own static route.

**Still open, not fixed**: `docker-socket-proxy`/base images being
tag-pinned rather than digest-pinned (finding #11) -- a pure
reproducibility note, not a vulnerability, not picked up yet.

## Two-factor authentication: WebAuthn and TOTP

Two independent second-factor mechanisms, on both the operator admin UI
(`/account`) and every tenant panel (`/security-key`) -- same shape and
same code path on both sides, just an independently-duplicated
implementation per side (this file's own top-of-file trust-boundary
note: the tenant-facing side keeps its own copy of everything
security-relevant rather than importing the control plane's package). A
user can register **WebAuthn, TOTP, both, or neither** -- login accepts
whichever they've got; registering the first one is what starts
requiring it; there's no way to require "WebAuthn specifically" or "TOTP
specifically" per user.

- **WebAuthn/FIDO2** (`vhsp_ctl/webauthn.py`, and an inline copy in
  `images/tenant-admin/app.py`) -- hardware security keys, Touch ID,
  Windows Hello, phone passkeys; anything that speaks the standard
  browser WebAuthn API. Ties a credential to one fixed origin (`RP_ID`),
  so it only works over the real public hostname each side is deployed
  on. Was the first (and until now, only) second-factor option; see
  architecture.md's control-plane-auth section for why it was
  prioritized (single-public-IP hosts can't lean on network position for
  admin-access control, so strong auth has to carry that weight instead).
- **TOTP / authenticator app** (`vhsp_ctl/totp.py`, and an inline copy in
  `images/tenant-admin/app.py`) -- Google Authenticator, Authy,
  1Password, or anything else that reads a standard `otpauth://` QR
  code. Added as a lower-friction alternative for anyone without a
  hardware key -- **not** a WebAuthn replacement; it doesn't carry
  WebAuthn's phishing resistance (a TOTP code can be phished and replayed
  by an attacker-in-the-middle in a way a WebAuthn signature can't).

### TOTP implementation details

- **Libraries**: `pyotp` (RFC 6238 TOTP, generation and verification) and
  `qrcode` using its SVG image factory specifically
  (`qrcode.image.svg.SvgPathImage`) -- deliberately avoids `qrcode`'s
  default Pillow-based PNG output so the QR code doesn't pull an image
  library into either the control-plane venv or the tenant-admin Alpine
  image just to draw a QR code. The SVG markup is embedded directly in
  the setup page (`{{ qr_svg|safe }}`), no data-URI/base64 needed.
- **One secret per user**, not a list like WebAuthn's credentials (which
  intentionally support multiple named keys per user) -- there's no TOTP
  equivalent to "multiple physical keys"; scanning the same QR/secret
  into a second device already works without a second stored secret.
  Stored in its own file, separate from `webauthn_credentials.json`:
  `totp_secrets.json` in `STATE_DIR` (operator) / `/data/totp_secrets.json`
  (tenant), root-only (`0600`), keyed by username.
- **Setup never persists an unconfirmed secret.** `/totp/setup` (GET)
  generates a fresh secret and QR every load and stashes the secret in
  the session only -- nothing is written to disk yet. The confirm POST
  verifies the submitted 6-digit code against that *session-held* secret
  and only writes it to `totp_secrets.json` if it verifies. Closing the
  tab mid-setup leaves nothing behind to clean up: there's no "pending"
  state anywhere except that one session. A failed confirm attempt
  redisplays the *same* secret/QR (not a freshly regenerated one) --
  regenerating here would silently invalidate whatever the user already
  scanned into their app.
- **Login** (`/login/2fa`, replacing the old WebAuthn-only
  `/login/webauthn` route/name on both sides) shows whichever the user
  has: a "use security key" WebAuthn button, a 6-digit code field, or
  both with an "or" divider between them. TOTP verification itself needs
  no JavaScript/browser API (unlike WebAuthn) -- it's a plain form POST.
- **Issuer naming differs deliberately** between the two sides so
  entries are distinguishable inside one authenticator app: the operator
  side's QR labels entries "VHSP"; each tenant's labels
  `<domain> admin`, so a person who's a tenant on several different vhsp
  sites (or both an operator and a tenant) doesn't end up with several
  identically-named, unlabeled entries in their app.
- **Accepted gap, same shape as WebAuthn's own documented one**:
  verification uses `valid_window=1` (accepts the code from one 30s step
  before/after the current one, ~90s of effective tolerance for clock
  drift between the host and the authenticator app) with no last-used-step
  tracking, so a valid code could in principle be replayed within that
  window. `webauthn.py`'s own docstring makes the identical tradeoff for
  not tracking WebAuthn signature counters -- "a real consideration for a
  high-value target, more than this platform's MVP needs," noted rather
  than silently skipped, not fixed here either.
- **Visibility elsewhere**: the operator's `/operators` list and each
  tenant's Team page both gained an "Authenticator app" column alongside
  the existing security-key count, so a TOTP-only user doesn't misleadingly
  read as having no second factor at all.

### Gating destructive/high-blast-radius actions behind 2FA

Both sides have a `require_2fa` decorator (independently implemented,
same "no shared import across the trust boundary" pattern as everything
else duplicated between `vhsp_ctl/` and `images/tenant-admin/`) that
blocks an action entirely -- not just hides a button -- unless the
logged-in user has *some* second factor registered, WebAuthn or TOTP,
either one. **Deliberate product choice, not a blanket security floor**:
the goal is a carrot for turning 2FA on at all (TOTP is free and takes a
couple of minutes), applied specifically to the surfaces where a
compromised no-2FA account would do real damage -- most pages stay
ungated.

**Tenant panel** (`images/tenant-admin/app.py`) -- gated: the file
manager (`/files*`, full site takeover), the SQL console (`/database`,
full DB access), and the config knobs that change what the live site
serves or how it's reached: `/php-functions`, `/redirects`,
`/noexec-dirs`, `/ip-acl`, `/backups`. Ungated: mailboxes, 404 handling,
password protection, error pages, logs, Team, and the account/security-key
page itself (has to stay reachable to actually set 2FA up).

**Operator admin UI** (`vhsp_ctl/web.py`), 23 routes across three groups:
- The same five self-service knobs, mirrored for operators managing a
  tenant directly (`tenant_php`, `tenant_redirects`, `tenant_noexec_dirs`,
  `tenant_ip_acl`, `tenant_backups` + its `settings`/`now`/`restore`
  sub-routes) -- no SQL-console equivalent exists on the operator side to
  gate. Also the operator's own cross-tenant backup-destination browser
  (`/backups`, `/backups/<domain>`, `/backups/<domain>/restore`), same
  "backups" category as the per-tenant view.
- Genuinely destructive tenant actions: `tenant_destroy`, all four
  incident-response nuke buttons (see "Incident response" above),
  `tenant_set_admin_password` and `tenant_set_ssh_key` (both hand an
  operator-chosen credential to a tenant -- a compromised operator
  account could use either to silently take over a tenant's panel or
  file access), `tenant_clear_webauthn` (strips a tenant's own MFA), and
  `tenant_set_maintenance` (takes a tenant's site offline).
- Operator account management: `operator_add`/`remove`/`reset-password`
  -- arguably the sharpest edge of all, since a compromised no-2FA
  operator account could otherwise add a backdoor operator or hijack a
  colleague's account, i.e. persist past the original compromise.

Ungated on the operator side: viewing a tenant or the tenant list,
creating a tenant, setting a quota, DNS/audit views, and changing your
*own* password -- routine or low-impact enough not to be worth the
friction.

**Discoverability, not just enforcement**: both nav bars mark gated
tabs with "(2FA required)" when the current user lacks one (tenant side:
extended the existing owner-only nav-hiding mechanism with a second,
independent `needs_2fa` flag per item; operator side: `render()` now
injects `has_2fa` into every template's context automatically, since
`TENANT_NAV` is shared across ~15 different route handlers and threading
an extra kwarg through each call site wasn't worth it). `tenant_detail`
and `/operators` both show a `{% if not has_2fa %}` warning banner up
top listing exactly which actions on that page need it. Every blocked
attempt gets a real 403 page explaining why and linking straight to
`/account` or `/security-key` -- not Flask's bare default 403 or a
silent redirect.

**Escape hatch, not a lockout**: none of this touches the CLI (`vhsp
tenant ...`, `vhsp admin ...`) -- it's a web-UI-only gate. A fresh
install with zero operators having 2FA yet is never actually locked out
of destroying a tenant or managing operators, just off the web UI for
those specific actions until someone registers a key or sets up TOTP.

## Login throttling and password requirements

2FA above is opt-in -- a brand-new account, before it's registered a
WebAuthn key or TOTP, has nothing but a password standing between it and
anyone who wants in. Two gaps that left open: unlimited login attempts
(nothing stopped a script from just trying passwords, or TOTP codes,
forever), and no minimum length on self-chosen passwords.

**Login throttling** (`vhsp_ctl/login_throttle.py`, independently
duplicated in `images/tenant-admin/app.py` per this codebase's usual
cross-trust-boundary pattern): after 5 failed attempts for one username
within 15 minutes, that username is locked for 15 minutes -- checked
*before* the password/code is even verified, so a locked account gets
refused immediately regardless of whether the submitted credential would
otherwise have been correct. Applies to both the password step
(`login()`) and the TOTP-code step (`login_2fa()`) on both admin
surfaces; WebAuthn doesn't need it, since a challenge-response credential
isn't something you can usefully brute-force. File-based (a small
`STATE_DIR`-backed JSON file, same shape as `auth.py`'s `operators.json`),
not `flask-limiter`/Redis-backed -- `vhsp-admin.service` runs
`gunicorn --workers 2`, so in-memory rate-limiter state wouldn't be
shared across workers, and this deployment has no Redis to back a shared
limiter with. Keyed by username, not IP, since this deployment sits
behind at most one reverse-proxy hop where a spoofed
`X-Forwarded-For` would be no more trustworthy than no IP at all.

**Minimum password length**: 12 characters, enforced on the two
self-chosen-password paths (`/account` on the operator side,
`/security-key` on the tenant side). Nowhere else needed it --
`auth.create_operator()`'s own generated passwords and the tenant team
page's "reset password" action both already generate long random values
(`secrets.token_urlsafe`), never something a person types in.

**Verified on vhsp2** against the real running services (not a local
test): 5 wrong-password POSTs against a disposable test operator
correctly returned "Invalid username or password" each time, and the
6th attempt -- submitted with the *correct* password -- was refused with
the lockout message instead of succeeding, confirming the check runs
before credential verification, not after. Repeated identically against
a real tenant's `/login` on the tenant-admin side with the same result.
Confirmed a short (8-character) password is rejected on both `/account`
and `/security-key` with the new length error. Both admin surfaces
restarted/recreated clean afterward with no errors.

## Session cookie hardening

Neither Flask app set `SESSION_COOKIE_SECURE`/`HTTPONLY`/`SAMESITE`,
so both ran on Flask's own defaults (`SECURE=False`, `SAMESITE=None`).
`HTTPONLY`/`SAMESITE=Lax` are now hardcoded True on both -- no legitimate
reason for client-side JS to read the session cookie, and `Lax` still
allows top-level navigation (a bookmarked/typed link into the admin UI)
while blocking the cross-site-POST case `SameSite` exists for.

`SECURE` couldn't be hardcoded the same way on either app, since both
are deliberately allowed to run somewhere without TLS in front of them
on at least one real topology:

- **Operator UI** (`web.py`): reuses `ADMIN_TRUST_PROXY` -- the same
  flag that already signals "there's a real TLS-terminating proxy hop in
  front of this," since this app is explicitly allowed to bind directly
  on a plain-HTTP management network (see the module's own docstring).
- **Tenant-admin** (`images/tenant-admin/app.py`): every tenant-admin
  container is *always* given two Traefik routers -- one on the public
  `web` entrypoint (real TLS) and one on the mgmtweb entrypoint, which is
  a real, reachable plain-HTTP path on deployments with an actual
  management-network interface (the original dev-VM topology), but an
  inert router object nothing ever matches on vhsp2's single-public-IP
  setup. Hardcoding `Secure=True` would silently break legitimate
  plain-HTTP mgmt-network logins wherever that path is real. Fixed by
  having `provisioner._create_tenant_admin_container` pass the *existing*
  `config.TENANT_ADMIN_MGMTWEB_EXISTS` flag (previously only used for
  operator-UI display text) into the container's own environment, so the
  container can make the same "is this deployment HTTPS-only in
  practice?" determination.

**Verified on vhsp2** against real `Set-Cookie` headers, not template
inspection: `curl -i https://vhsp2.dvce.us/login` and
`curl -i https://admin.smoketest.vhsp2.dvce.us/login` both show
`Secure; HttpOnly; Path=/; SameSite=Lax` on the session cookie. Confirmed
the tenant-admin container actually received `TENANT_ADMIN_MGMTWEB_EXISTS=0`
in its environment (`docker inspect`) before trusting the cookie's
`Secure` flag was set for the right reason, not by accident.

## cgroup limits on web and mail containers

`config.py`'s `DB_MEM_LIMIT`/`DB_NANO_CPUS` (per architecture.md's
"Database isolation" section) were wired into the DB container only --
the web and mail containers had no cap at all, so a single compromised
or just abusive tenant could still starve CPU/memory for every other
tenant on the host even with the DB side already capped.

Added `WEB_MEM_LIMIT`/`WEB_NANO_CPUS` and `MAIL_MEM_LIMIT`/`MAIL_NANO_CPUS`
to `config.py`, same `os.environ.get(...)`-tunable pattern as the DB
ones, defaulting to the same 512MB/1 CPU. Wired into
`_create_web_container`/`_create_mail_container`'s `client.containers.run()`
calls in `provisioner.py`. New `recreate_web.py` (mirroring the existing
`recreate_mail.py`/`recreate_tenant_admin.py` one-off scripts) exists
purely so already-provisioned tenants can pick up the new limit without
a full tenant recreate -- there's no image to rebuild here (no
Dockerfile changed), just a fresh container with the new
`mem_limit`/`nano_cpus` kwargs applied, which Docker won't retroactively
apply to an already-running container.

**Verified on vhsp2**: recreated both live tenants' web and mail
containers (`recreate_web.py`/`recreate_mail.py`), confirmed via
`docker inspect` that all four now report the correct `Memory`
(536870912 = 512MB) and `NanoCpus` (1000000000 = 1 CPU), and confirmed
both tenants' real websites and tenant-admin panels still serve traffic
normally (real `curl` 200s) after the recreation. Enforcement itself
wasn't independently OOM-stress-tested -- Docker's own cgroup limit
enforcement is a well-established engine feature, not something this
change implements itself, and the pre-existing DB container limit was
never OOM-tested either; `docker inspect` confirming the limit landed
correctly is the same standard already implicitly accepted there.

**Extended to tenant-admin and SFTP containers later** (the two
remaining container types with no cap) -- see "Follow-up security
review" below for that addition; every container type this platform
runs now has a cgroup ceiling.

## CSRF protection and a real WSGI server

Two platform-wide hardening changes, independently implemented on both
sides per this codebase's usual trust-boundary duplication.

**CSRF**: one unpredictable per-session token (`secrets.token_urlsafe(32)`,
same primitive every other generated credential here already uses),
checked on every `POST`/`PUT`/`PATCH`/`DELETE` request via a
`before_request` hook that runs before any view function -- including its
own `require_auth`/`require_role`/`require_2fa` decorators. A mismatch or
missing token gets a real 403 page ("Your session expired... reload and
try again"), not a bare Werkzeug error.

Real HTML forms get the token via a small injector script in
`LAYOUT`/`AUTH_PAGE` (every page routes through one or the other) rather
than a hidden field hand-added to the ~50 forms across both apps:

```html
<script>
  document.querySelectorAll('form').forEach(function (f) {
    var i = document.createElement('input');
    i.type = 'hidden'; i.name = 'csrf_token'; i.value = '{{ csrf_token() }}';
    f.appendChild(i);
  });
</script>
```

This is a sound defense despite touching so few places: the script only
ever runs on a page this server actually rendered, so a cross-origin
attacker's forged form can never carry the right value even though the
check itself doesn't need anything clever. Already JS-dependent anyway
(WebAuthn's `navigator.credentials` API requires it), so this adds no new
constraint. The 4 WebAuthn `fetch()` calls per app (not native form
submissions) set the same token as an `X-CSRF-Token` header instead --
`{{ csrf_token() }}` where the surrounding template is genuinely
Jinja-parsed, or the token passed as a Python f-string value where it
isn't (see the bug note below for why that distinction matters).

**A real bug found and fixed while building this**: `vhsp_ctl/web.py`'s
`login_2fa()` built its body with `{% if has_key %}...{% endif %}` written
directly inside a Python string, then passed that string as the `body`
kwarg to `render_template_string(AUTH_PAGE, ..., body=...)`. AUTH_PAGE
only ever substitutes `body` via `{{ body|safe }}` -- a single-pass
render that inserts the string's characters verbatim rather than
re-parsing them as a nested template, so those `{% if %}` markers were
inert text, not logic. Both the WebAuthn button and the TOTP form
rendered unconditionally, with literal `{% if %}`/`{% endif %}` visible
on the live page, for anyone with a second factor registered -- not a
security hole (the actual verification logic still checked correctly
against whatever was actually registered), just broken-looking markup
that shipped and went unnoticed until this session. Fixed by switching to
plain Python `if`/`+=` string building, which `images/tenant-admin/app.py`'s
own `login_2fa()` already did correctly from the start -- worth checking
for this exact shape (Jinja syntax typed into a string that only ever
reaches `{{ var|safe }}`) anywhere else a `body`-style kwarg gets built.

**WSGI server**: both apps now run under `gunicorn --workers 2` instead of
Flask's own dev server (`app.run()`), which prints its own warning against
exactly this use on every startup. Sessions are cookie-based (Flask's
default), not server-side, so multiple worker processes need no shared
state -- safe to run more than one with zero extra work. Operator side:
`deploy/vhsp-admin.service`'s `ExecStart` wraps the command in `/bin/sh -c`
so `${VHSP_ADMIN_BIND_HOST}`/`${VHSP_ADMIN_BIND_PORT}` (set via the unit's
own `Environment=` lines) expand into `--bind` -- systemd's `ExecStart`
doesn't do shell-style substitution on its own. Tenant-admin side:
`images/tenant-admin/Dockerfile`'s `CMD` runs gunicorn against `app:app`
directly; the `vhsp-admin` console script and `app.py`'s own
`if __name__ == "__main__":` block are both left in place as local-dev-only
fallbacks, never invoked by a real deployment.

## Docker socket exposure

architecture.md's control-plane-auth section flagged this as the
sharpest edge in the whole design: `provisioner.py`/`dns_records.py`
talked to Docker via `docker.from_env()`, i.e. the raw
`/var/run/docker.sock`, which is root-equivalent on the host -- any
compromise of the control-plane process (a web-app vulnerability, a
dependency CVE, anything) meant root on the host, not just "control over
tenant containers."

**Fix: a scoped proxy in front of the socket, not a raw connection to
it.** `deploy/vhsp-docker-proxy.service` runs
[`tecnativa/docker-socket-proxy`](https://github.com/Tecnativa/docker-socket-proxy)
as a root-launched container -- the *only* thing on the host with the raw
socket mounted (read-only) -- and re-exposes a curated subset of the
Docker API on `127.0.0.1:2375`, loopback-only:

- **Allowed**: `CONTAINERS`, `VOLUMES`, `NETWORKS`, `EXEC`, `IMAGES`,
  `POST`, `LOGS` -- exactly what tenant provisioning/destruction,
  backup/restore, the mail gateway's exec-based postfix reloads, and the
  operator UI's WAF-log viewer actually use. `LOGS` gates
  `GET /containers/{id}/logs` -- `tecnativa/docker-socket-proxy` treats
  it as a separate toggle from the general `CONTAINERS` flag (log
  *content* is more sensitive than container metadata), added
  specifically for the Coraza WAF log viewer (see that section) and
  verified with a real `container.logs()` call through the proxy before
  anything was built on top of it.
- **Denied**: `SWARM`, `SERVICES`, `NODES`, `SECRETS`, `CONFIGS`,
  `PLUGINS`, `BUILD`, `COMMIT`, `DISTRIBUTION`, `AUTH`, `TASKS`,
  `SESSION`, `SYSTEM` -- none of this is used by any code path, and
  several of these are exactly the kind of thing worth denying even to a
  process that's *supposed* to have container access (`SECRETS`/`CONFIGS`
  in particular overlap with the "Secrets management" gap this same
  architecture.md section separately flags -- no reason to let a Docker
  API compromise become a secrets-manager compromise too, even before
  that manager exists).

**What this does and does not buy — stated plainly, because it's easy to
read more into it than is there.** The denied list above is real: those
API sections are genuinely unreachable through the proxy. But the
*allowed* set is not a reduction in privilege level. `CONTAINERS` +
`POST` + `EXEC` + `IMAGES` + `VOLUMES` together are sufficient to start
a container with a host bind mount and exec inside it, which is root on
the host. **Anything that can reach `127.0.0.1:2375` is
root-equivalent.** That's accepted rather than overlooked — those are
precisely the calls `provisioner.py` needs to do its job, and a
provisioning control plane that can't create containers isn't one.

The consequence worth carrying forward is about the *other* control:
the sudo scoping described below is a genuine defence-in-depth layer,
but it is **not** a containment boundary by itself, because the same
compromised process it refuses a root shell to can reach this proxy
instead and get there anyway. Both controls raise the cost of a
compromise and neither one closes the path alone. Actually narrowing
this would mean brokering the specific container operations behind
wrapper scripts, the way the sudo wrappers already broker
mount/fstab/tar — a design change, not a config toggle. Nothing in the
current threat model justifies that yet; it's recorded here so the
question is re-asked deliberately rather than assumed closed.

The proxy image is **pinned by digest**, not `:latest` — for the one
container mediating all root-equivalent access, "whatever the registry
serves today" is a supply-chain gap the rest of this stack doesn't have.
The pinned digest is the image vhsp2 was already running when the pin
was introduced (verified against its `RepoDigests`), so adopting it is a
no-op rather than a silent upgrade. It is deliberately *not* the current
`:latest`, which had already moved on — that drift, discovered while
adding the pin, is exactly what the pin exists to stop.

`vhsp_ctl.config.DOCKER_HOST_URL` (read from `VHSP_DOCKER_HOST`,
defaulting to the raw socket for local dev where no proxy is running)
is the single place this is wired in. `provisioner._client()` is the
construction point every other module delegates to (`backup.py`, the
`recreate_*.py` one-offs) -- `dns_records.py` is the one exception,
constructing its own client against the same `DOCKER_HOST_URL` rather
than calling `provisioner._client()`, functionally identical in
practice (same URL, same proxy) but worth naming accurately rather than
overstating "the only place" this happens.
One env var on `vhsp-admin.service`/`vhsp-backup.service`/
`vhsp-backup-reconcile.service` (`VHSP_DOCKER_HOST=tcp://127.0.0.1:2375`)
covers every consumer.

**The actual privilege boundary is group membership, not the client
URL.** Pointing the code at the proxy accomplishes nothing on its own if
the OS still lets the process open the raw socket directly -- so the
`astjohn` user (which runs all three of those services, plus the CLI) is
removed from the host's `docker` group entirely on a hardened deployment.
A compromised `vhsp-admin`/`vhsp-backup`/`vhsp-backup-reconcile` process
now has no path to the raw socket at all, only whatever the proxy's
allow-list exposes over loopback TCP. `vhsp-docker-proxy.service` itself
runs as root (by design -- something has to hold the real socket), but
it's a fixed, minimal, non-web-facing process with nothing resembling the
admin UI's attack surface.

**No TLS on the proxy's endpoint, deliberately.** It never leaves
loopback -- there's no network hop for a client certificate to protect
against, and adding cert issuance/rotation would be complexity defending
against a threat that doesn't exist on this single-host topology. Worth
revisiting only if the control plane ever splits across multiple hosts
and this endpoint needs to leave `127.0.0.1`.

**Human/manual Docker access**: `docker build`, `docker ps`, `docker
logs`, and similar ad hoc commands run by hand over SSH need `sudo`
now too, same as the mount-hardening calls already required it --
`astjohn` isn't in the `docker` group, and the proxy doesn't expose
`BUILD` at all (deliberately, since nothing in the codebase needs it).

**Verified on vhsp2**: proxy installed and running, confirmed serving
`/version`/`/containers/json` on `127.0.0.1:2375` while a denied endpoint
(`/swarm`) returns 403 -- so the allow-list is actually enforced, not
just configured. `astjohn` removed from the `docker` group and all three
consuming services restarted; a real tenant create → destroy cycle
(containers, volumes, networks, and the DKIM `exec_run` check all
exercised) and a real `vhsp backup create` both succeeded end-to-end
purely through the proxy, with zero raw socket access available to any
of those processes.

## Sudo scoping

The Docker socket proxy above closes one root-equivalent surface; the
`astjohn` sudoers grant (`DEPLOYMENT.md`'s original `NOPASSWD:ALL`) was
the other, and it quietly defeated the proxy work above -- any RCE in
`vhsp-admin.service` (which runs as `astjohn`, internet-facing, with
`NoNewPrivileges=false` specifically so `sudo` keeps working) was
equivalent to root regardless of what the Docker API allow-list said.

**The fix**: sudo is now scoped to exactly two root-owned wrapper
scripts, `deploy/vhsp-harden-hostdir` and `deploy/vhsp-remove-hostdir`
(installed to `/usr/local/sbin`), which do their own internal argument
validation rather than trusting a sudoers pattern to constrain them.
This is deliberate, not a simplification for its own sake: modern
`sudo` refuses wildcards inside command arguments (`visudo -cf` rejects
them outright), so a `Cmnd_Alias` can't safely express "mount only
under `/srv/vhsp/tenants/*`" directly -- the standard pattern for "sudo
access to an action with a dynamic target" is a narrow wrapper script
that validates its own arguments, which is what these two scripts do
(reject anything outside `^[a-z0-9-]+$` for the tenant slug and a fixed
literal set for the purpose, before ever touching `mount`/`tee
/etc/fstab`/`rm -rf`). `provisioner.py`'s `_harden_host_dir`/
`_remove_host_dir` now call these scripts via one scoped `sudo`
invocation each instead of four separate inline `sudo mount`/`sudo tee`/
`sudo rm` calls.

**Honest limit**: this removes "arbitrary command as root" but not all
abuse of the two commands actually granted -- an attacker with RCE in
the admin process could still, say, delete a tenant's data or rewrite
one `/etc/fstab` line via the exact command shapes the scripts
implement. A real, meaningful reduction in blast radius, not a complete
elimination of it.

**`astjohn` stays in the `sudo` group** (Ubuntu's default `%sudo
ALL=(ALL:ALL) ALL`, password-required) for the human operator's own
interactive system administration (`apt`, `ufw`, etc. throughout
`DEPLOYMENT.md`) -- this is a single-operator deployment where the same
OS account is both the service user and the human's login, unlike the
Docker-proxy case where a separate process could hold the privilege
instead. This is safe to leave as-is: it requires a password and a TTY,
neither of which an unattended, non-interactive RCE in
`vhsp-admin.service` has access to (confirmed below via `sudo -n`). The
part that *was* reachable by an unattended compromise -- the
passwordless, unattended `NOPASSWD:ALL` grant -- is what's actually
gone.

**Verified on vhsp2**: `visudo -cf` confirmed the new grant parses
before it was trusted; `sudo -n cat /etc/shadow` (simulating what an
unattended RCE would attempt) refused with "interactive authentication
is required"; `sudo -n /usr/local/sbin/vhsp-harden-hostdir` (no args)
ran non-interactively and correctly rejected the missing-argument case
from inside the script. A real tenant create → destroy cycle exercised
both wrapper scripts across all seven hardened-volume purposes
(webroot/db/ssh_keys/mail/phpconf/logs/dkim) -- confirmed identical
`/etc/fstab` entries and `findmnt` mount flags
(`nosuid,nodev,noexec`) to the pre-change behavior, and confirmed
`vhsp tenant destroy` cleanly removed every fstab entry and every
purpose subdirectory.

### Two more wrapper scripts: backup creation and restore-into-existing-tenant

A real regression, discovered (and fixed) while doing the backup-key
encryption work below: `backup.py`'s `_tar_directory` (`sudo tar`, used
by *every* backup creation) and `_restore_into_existing_tenant` (`sudo
find ... -delete` + `sudo chown`) were never added to the scoped
sudoers grant above -- confirmed non-interactively broken
(`sudo -n tar ...` → `interactive authentication is required`) before
fixing it. Same wrapper-script pattern as `vhsp-harden-hostdir`/
`vhsp-remove-hostdir`: `deploy/vhsp-backup-tar <slug> <purpose>
<dest_file>` validates its arguments (purpose restricted to the literal
`webroot|mail|phpconf` set `_tar_directory` actually uses, `dest_file`
resolved and confirmed under `BACKUP_WORKDIR` to block `../` traversal)
before running `tar -czf`; `deploy/vhsp-restore-clean <slug> <purpose>`
does the `find -delete` + `chown` pair internally, using sudo's own
`SUDO_UID`/`SUDO_GID` for the chown target rather than taking it as an
argument. Both added to `deploy/vhsp-sudoers`'s `astjohn` grant
alongside the existing two.

**Verified on vhsp2**: a real `vhsp backup create` against a live
tenant (exercising the new tar wrapper) and a real `vhsp backup
restore` into that same already-existing tenant (exercising the new
restore-clean wrapper) both succeeded, with the site and tenant-admin
panel confirmed still serving traffic normally afterward. Confirmed a
raw `sudo tar` call is still refused non-interactively, and that both
new wrapper scripts correctly reject a missing-argument invocation.

## Secrets management

architecture.md's control-plane-auth section named this as a real gap:
tenant DB/mail/panel credentials (`registry.py`'s SQLite columns) and
operator TOTP shared secrets (`totp.py`'s JSON file) were plaintext on
disk, protected only by 0600 file permissions -- a single trust
boundary, since whoever can read files as the owning user reads
everything at once.

**Fix: envelope encryption with a locally-held master key, not a full
secrets manager.** `vhsp_ctl/secretbox.py` is a thin wrapper around
`cryptography`'s `Fernet` (authenticated symmetric encryption). A single
master key, generated once by `vhsp secrets init` and stored at
`MASTER_KEY_PATH` (`/srv/vhsp/master.key`, 0600) -- deliberately a
separate file from what it protects, not embedded in a systemd unit
where it'd be as readable as any other `Environment=` line -- encrypts:

- `registry.py`'s four credential columns (`db_password`,
  `db_root_password`, `mail_password`, `tenant_admin_password`), at the
  three write points (`add_tenant`, `set_tenant_db_password`,
  `set_tenant_admin_password`) and transparently decrypted at the one
  read point (`_row_to_tenant`) -- every other call site in the codebase
  (`provisioner.py`, `web.py`, `backup.py`, `cli.py`) still just sees a
  plaintext `Tenant` object, unaware this exists.
- `totp.py`'s per-operator shared secret (not `added_at`, which isn't
  sensitive), at its own single load/save choke point.

**Why this, not Vault/cloud KMS**: considered and deliberately not built
-- discussed with and confirmed by the user rather than assumed. vhsp2 is
a single-process, single-host, explicitly non-permanent deployment (see
project memory); standing up Vault (its own storage backend, unseal
handling, a new always-on service to operate and back up) is real
engineering investment this box doesn't warrant. Cloud KMS isn't
available on a bare DigitalOcean droplet without third-party glue either.
Envelope encryption with a local master key gets the actual value that
matters here for near-zero new surface: a leaked SQLite file, a stray
backup, or a narrow file-read bug no longer hands over plaintext
credentials on its own -- the same reasoning `backup.py` already applies
to snapshot encryption (age), just extended to secrets that never leave
this host at all.

**What this does NOT defend against**: a full compromise of the live
host. The master key sits on the same disk as everything it protects --
same limitation the Docker socket proxy fix above has for a different
piece of the same problem, and a deliberate one: the alternative (a real
external KMS) wasn't judged worth the complexity for what's currently a
disposable test deployment, not the intended long-term production host.
`MASTER_KEY_PATH` must never be swept into any future "back up the
control plane's own state" tooling -- no such feature exists today, but
shipping the key alongside the database it decrypts would defeat the
entire premise above.

**Backup private keys (SSH transport, age encryption, manifest signing)
are now also covered** -- see "Backup private keys at rest" below for
the full design. Originally scoped out of this pass (twice: once here,
once again when a later CISO-style review re-surfaced it) as
meaningfully more invasive than swapping a `TEXT` column's string
value -- `backup.py` passes these as raw file paths into `age`/
`ssh-keygen`/`ssh`/`scp` subprocess calls (~10 call sites), so
encrypting them at rest means staging a decrypted temp copy before
every one of those calls and reliably cleaning it up after, including
on exceptions. Named explicitly as a follow-up both times rather than
silently dropped, and eventually done.

**Migration for existing plaintext data**: `secretbox.decrypt()`
transparently passes through any value without the `enc1:` prefix (data
written before this feature existed, or before a master key was ever
generated), so nothing breaks the moment this code ships. `vhsp secrets
migrate` re-encrypts everything still in plaintext (every tenant row
regardless of status, so destroyed tenants' old credentials aren't left
exposed either, plus every TOTP secret) -- idempotent, safe to re-run,
reports 0 changed once everything's already encrypted.

**CLI**:

```
vhsp secrets init [--force]     # generate the master key (shown once, refuses to silently overwrite)
vhsp secrets migrate            # encrypt anything still in plaintext
```

**Verified on vhsp2**: local round-trip tests first confirmed encrypted
values never appear in the raw SQLite file or the raw TOTP JSON, decrypt
back to the exact original plaintext, and that the two credential-
rotation setters (`set_tenant_db_password`, panel password reset) also
encrypt correctly, including on a simulated pre-existing plaintext row
(migration decrypts and re-encrypts it correctly, then reports 0 changed
on a second run). On the live host: `vhsp secrets init` + `vhsp secrets
migrate` run back-to-back immediately after deploying the code
(encryption writes fail loudly with no master key present, by design --
same "loud failure over a silent security regression" posture as the
CSRF/Docker-proxy work above -- so this gap was kept as small as
possible, and reads were never affected either way since `decrypt()`'s
plaintext pass-through needs no key at all), migrating all 7 existing
tenant rows (active and destroyed) in one pass -- 0 TOTP secrets existed
yet to migrate. Confirmed via direct SQLite inspection that every tenant
row is now ciphertext, then exercised the real write path end to end: a
real tenant create (`add_tenant`), a real DB password rotation
(`reset_tenant_db_password` → `set_tenant_db_password`) confirmed both
encrypted on disk and correctly decrypted back via `vhsp tenant show`,
and a real destroy -- plus a clean `vhsp-admin.service` restart with
nothing but expected output in its journal.

## Key rotation

Two independent "what if this specific key leaked" procedures -- the
`secretbox` master key and the operator backup keypairs each needed
their own answer, since they protect different things and were
generated by different mechanisms.

**`secretbox` master key**: `vhsp secrets rotate` generates a fresh key
and re-encrypts every tenant credential and TOTP secret under it, then
replaces the old key file. Ordering matters here, since credentials live
in two different stores (the registry's SQLite database and TOTP's own
JSON file): both `registry.rotate_credentials()` and `totp.rotate_secrets()`
decrypt-then-re-encrypt using explicit `Fernet` instances
(`secretbox.encrypt_with()`/`decrypt_with()`, new alongside the existing
key-implicit `encrypt()`/`decrypt()`) rather than reading
`secretbox.MASTER_KEY_PATH` themselves -- the whole point of rotation is
that the on-disk key hasn't been swapped yet while this runs. The key
file itself is only swapped (write-to-temp, then atomic rename) after
*both* stores have been fully rewritten, so a failure partway through
either one leaves the old key still valid for everything, rather than
some rows becoming permanently undecryptable.

**Must stop `vhsp-admin.service` and any `vhsp-backup*`/`vhsp-audit-ship`
timers before running this** -- there's no cross-process coordination
here, just a documented precondition matching this deployment's single-
operator scale. A process still reading with the old key while rotation
runs would fail to decrypt rows already rewritten under the new one.
Restart everything once it finishes. `registry.rotate_credentials()`
also implicitly finishes migrating any row that was somehow still
plaintext (the pass-through in `decrypt_with()` hands the value back
unchanged, which then gets freshly encrypted under the new key) -- no
separate migration step needed first.

**Backup keypairs** (SSH transport / `age` / signing): no new code --
`vhsp backup init --force` already regenerates all three (it refuses to
overwrite without `--force`, existing behavior). The tradeoff to
understand before using it: new keys only protect *future* backups.
Existing snapshots encrypted/signed under the old keys remain readable
*only* with the old keys until a fresh full backup cycle re-encrypts
them under the new ones -- there's no retroactive re-encryption of old
snapshots. This is an accepted, disclosed tradeoff matching the
already-one-way nature of the existing key-init design, not a gap to
close later. If the old keys are suspected compromised, keep a copy of
them somewhere safe until every tenant has a fresh backup under the new
keys, in case an old snapshot ever needs restoring in the meantime.

**Verified on vhsp2** against real production data, not a throwaway
test: backed up `control-plane.db`/`master.key`/`totp_secrets.json` to
`/tmp` first (a safety net, deleted immediately after -- leaving an old
master key lying around would itself be a residual secret exposure),
stopped `vhsp-admin.service` and all three timers, ran `vhsp secrets
rotate` (rotated 9 tenant rows, 1 TOTP secret), restarted everything
clean. Confirmed `vhsp tenant show` returns the exact same plaintext
credentials as before rotation (decrypting correctly under the new key),
confirmed `mbott`'s TOTP secret still loads (`has_totp` succeeds, which
requires successful decryption), and directly compared the SQLite
ciphertext before/after to confirm it actually changed -- not a silent
no-op -- plus confirmed `master.key`'s bytes on disk genuinely differ
from the pre-rotation copy. Ran the same rotation logic first in a fully
isolated local sandbox (a temp `VHSP_STATE_DIR`, a synthetic tenant, a
synthetic TOTP secret) before ever touching production data, confirming
correctness end to end -- including that the *old* key correctly fails
to decrypt the rotated ciphertext -- and only then repeated the
procedure for real.

## Backup private keys at rest

The one credential category `secretbox` didn't cover when "Secrets
management" above first shipped: the SSH transport, `age` encryption,
and Ed25519 signing private keys `backup.py` uses, previously plain
0600 files passed as raw paths directly into `ssh`/`scp`/`age`/
`ssh-keygen` subprocess calls.

**Design**: every low-level function that actually shells out to one of
those binaries (`_sign_manifest`, `_decrypt`, `_ssh_opts` and its six
consumers) is **completely unchanged** -- they still just take a `Path`,
no idea encryption exists. A single new context manager,
`_decrypted_key_file(encrypted_path)`, stages one key's plaintext into a
0600 temp file under `BACKUP_WORKDIR` for exactly the duration of one
subprocess call, deleting it in a `finally` so cleanup runs whether the
wrapped call succeeds or raises. Only the ~10 call sites that used to
pass one of the three operator key constants or a tenant's
`backup_ssh_key_path`/`backup_age_key_path` directly now wrap that
argument in `with _decrypted_key_file(...) as tmp:` instead. `age`/
`ssh-keygen` unavoidably write plaintext to disk themselves when
*generating* a key (no way to have them emit ciphertext directly) --
`_generate_ssh_keypair`/`_generate_age_keypair` encrypt immediately
after, before ever returning to a caller; `age-keygen`'s own pubkey
derivation has to run against the real plaintext file first, since it
can't read the `enc1:...` wrapper.

`_dest_identity` (previously a plain lookup returning a bare `Path`)
became a context manager itself, since all three of its callers
(`list_remote_domains`, `list_remote_snapshots`, `_fetch_and_verify`)
immediately consume the returned key for exactly one ssh/scp call --
consolidating what would otherwise be three separate wrap points into
one.

**Migration**: `backup.migrate_operator_keys()` -- same idempotent
`is_encrypted()`-per-file shape as `registry.reencrypt_all_credentials`/
`totp.reencrypt_all` -- walks the three operator key paths plus every
tenant's own `ssh_ed25519`/`age.key`, encrypting any not already
`enc1:`-prefixed. Wired into the *existing* `vhsp secrets migrate`
command rather than a new one -- conceptually the same "already-
plaintext secretbox-protected data" gap that command already closes for
registry credentials and TOTP secrets.

**One correctness fix found along the way**: `process_requests` (the
~2-minute tenant-backup reconciler) used to read a tenant's age key
file directly (`Path(...).read_text()`) to detect a freshly-generated
key for its one-time-reveal-to-tenant-admin flow (checking for the
literal substring `"AGE-SECRET-KEY-"`). Once that file holds ciphertext,
a raw read would never match, silently breaking the reveal on every
run -- fixed to `secretbox.decrypt(...)` first.

**Verified on vhsp2** against real production keys and real backup
infrastructure, not a synthetic test: local sandbox first (isolated
`VHSP_STATE_DIR`, using the repo's own `.venv` since system Python has
no dependencies installed) confirmed key generation produces genuine
ciphertext, confirmed `_decrypted_key_file` round-trips correctly
against a real `age-keygen -y` subprocess call, confirmed the temp file
is gone both after a successful call *and* after a deliberately raised
exception mid-`with`-block (the `finally` firing either way), and
confirmed migration of simulated pre-existing plaintext keys correctly
converts to ciphertext, decrypts back to the identical original
content, and is idempotent. Then on vhsp2 itself: `vhsp secrets
migrate` correctly converted all three real operator keys (which
predate this feature) from plaintext to ciphertext; a real `vhsp backup
create` succeeded end-to-end (exercising the signing, age, and SSH keys
in one run, now all encrypted at rest); a real `vhsp backup restore`
into the same already-existing tenant succeeded (fetch, decrypt, and
signature verification all working correctly against the
now-encrypted-at-rest keys); the same adversarial tamper test already
documented for the original signature work -- decrypt a real snapshot,
edit its manifest, re-encrypt without re-signing, attempt to restore --
was repeated and still correctly refused
("backup signature verification FAILED"), confirming the security
guarantee wasn't weakened by the encryption-at-rest change. Confirmed
`find /srv/vhsp/backup/work -type f` was empty after all of the above --
no decrypted key material left behind anywhere.

## fail2ban: intrusion prevention with no external account

architecture.md's abuse-monitoring section originally named CrowdSec
for this (watch for external attackers -- brute force, scanning --
hitting the platform from outside; a different concern from the
per-tenant abuse-monitoring section, which is about *a tenant's own*
container misbehaving). Replaced with fail2ban before ever deploying
CrowdSec: a hosted service's community blocklist/console features want
an account, and a company can change what's gated behind that at any
time -- fail2ban is zero-account, zero-external-service, pure local
log-watching + local firewall banning, matching this project's general
posture of not depending on something that can change policy out from
under it.

**A real architectural constraint shapes this whole design**: every
tenant's site, tenant-admin panel, and the operator UI all share port
443 through the same Traefik instance, so a firewall-level ban on that
port is inherently platform-wide regardless of which tenant's log line
triggered it. SFTP is different -- each tenant has its own distinct
port in the 2200-2299 range, so bans genuinely can be tenant-scoped
there. This shapes both the jail design and the allowlist design below;
neither oversells isolation the network layer can't actually deliver.

**Operator allowlist** (`vhsp_ctl/fail2ban_allowlist.py`, a new
`/allowlist` page in the admin UI, gated behind `require_2fa` for the
same reason the tenant-facing IP-restrictions page is -- a compromised
no-2FA account misusing this could exempt an attacker's own IP from
being banned platform-wide): a flat list of IPs/CIDRs never banned by
*any* jail. Checked live via `deploy/vhsp-fail2ban-allowlist-check`,
used as every jail's `ignorecommand` (fail2ban's per-ban-decision
external hook) -- an operator's edit takes effect immediately, no
`fail2ban-client reload` needed. Deliberately a plain-text file, not
JSON: the check script is bash + a small inline Python snippet (for
real CIDR containment math via the `ipaddress` module, not hand-rolled
bash arithmetic), not a JSON parser. This script runs as fail2ban's own
already-root systemd service -- it does **not** go through `astjohn`'s
own scoped sudoers grant at all, unlike every wrapper script described
in "Sudo scoping" above.

**A real bug caught during rollout, not glossed over**: fail2ban's
stock `banaction = iptables-multiport` silently creates no firewall
rule at all on this host -- `actionstart` logs no error, the jail
reports "started" cleanly, but no `f2b-*` chain ever appears in either
`iptables -S` or `nft list ruleset`. Root cause: this OS's actual
firewall backend is nftables (`iptables` here is just the nft-compat
shim), and confirmed directly that fail2ban's `nftables-multiport`
action *does* correctly create its chain -- just lazily, on the first
real ban decision, not at jail start (a legitimate design choice, not a
bug, once understood -- a quiet jail never needs to touch the firewall
at all). Switched `banaction` to `nftables-multiport`. Verified the
fix with a real ban/unban cycle against `192.0.2.1` (RFC 5737, reserved
for documentation/testing, guaranteed never a real client) rather than
either waiting for a live attacker to trigger it or risking a real IP
-- confirmed the ban correctly created the firewall rule (`nft list
table inet f2b-table` showed the reject rule with `192.0.2.1` in the
banned set) and the unban correctly cleared it.

**`[sshd]` jail**: reuses fail2ban's own stock, well-tested `sshd`
filter against `/var/log/auth.log` -- no need to hand-roll one, and
this filter is also reused as-is in the planned per-tenant SFTP jails
(the atmoz/sftp containers are themselves OpenSSH under the hood,
confirmed their connection logs are standard OpenSSH format). Moderate
`maxretry = 5` / `findtime = 10m` / `bantime = 30m` for initial
rollout, not permanent -- a false positive should self-heal within
half an hour, not require manual `fail2ban-client unbanip` recovery.

**Verified on vhsp2**, dry-run wherever a real ban wasn't already the
safest option: `fail2ban-regex` against the real `auth.log` confirmed
2033 real failure-pattern matches out of 13779 lines (including the
live attack traffic already visible from a real scanning IP) before
ever trusting the filter with ban authority. Checked recent
`auth.log` activity near this session's own active SSH connections
before ever starting the service, to avoid an immediate self-inflicted
lockout. The operator allowlist was verified end-to-end against the
real deployed files: wrote real entries via the same function the web
UI calls, confirmed `vhsp-fail2ban-allowlist-check` correctly allows an
exact-match IP, a CIDR-contained IP, and correctly refuses one outside
either -- then cleared the test entries. `astjohn`'s own SSH access was
confirmed still working throughout every restart and test cycle.

### Operator admin-login jail

`audit.log_action()` (`vhsp_ctl/audit.py`) gained an optional `ip`
parameter, populated only by `web.py`'s three login-related call sites
(`admin.login`, `admin.login_failed`, `admin.logout`) via Flask's
`request.remote_addr` -- already correctly resolved through `ProxyFix`
since `ADMIN_TRUST_PROXY` is on. Every other `log_action()` call site is
completely unaffected: the field is omitted from the entry entirely
when not passed (not even an empty string), so nothing that reads this
file sees a schema change for actions that never had an IP concept.
New `deploy/fail2ban/filter.d/vhsp-admin-login.conf` matches
`audit.log`'s JSON-lines format for `"action": "admin.login_failed"`,
capturing `<HOST>` from the new `"ip"` field. New jail
`[vhsp-admin-login]`: `logpath = /srv/vhsp/audit.log`, `port =
http,https`, `ignorecommand` calls the same allowlist-check script with
no tenant slug (this jail has no tenant concept -- it's the single
shared operator UI, so only the platform-wide operator allowlist
applies).

**Verified on vhsp2** against real traffic, including a genuinely
external request, not just localhost: a real failed login from *this
session's own actual outbound IP* (curled directly, not through SSH to
the host, so the request took a real external network path) landed in
`audit.log` with that exact IP captured correctly -- confirming
`ProxyFix`/`X-Forwarded-For` resolve the real client, not Traefik's own
address. (A second test curled *from the vhsp2 host itself* against its
own public URL showed the Docker bridge gateway IP instead, a hairpin-
NAT artifact specific to self-requests -- not something a real client
ever hits, and not something the fix needed to handle.) `fail2ban-regex`
against the real `audit.log` confirmed the filter matches (3/3 real
test failures, correctly skipping 90 unrelated entries). After
`fail2ban-client reload`, watched the jail pick up a *new* failed login
live (file-based `logpath` jails only watch forward from reload time,
unlike the journal-backed `sshd` jail, which does scan back) --
confirmed via `fail2ban.log` showing the real IP being evaluated,
correctly recognized as within the operator's own already-populated
allowlist (CIDR range `216.106.72.200/30`) and ignored. Confirmed the
actual ban path separately, same safe-IP method as Part 1
(`192.0.2.1`, RFC 5737). `vhsp audit verify` still reports the chain
intact (94 real entries) after the new field shipped, confirming the
hash chain is genuinely content-agnostic, not just assumed to be.

### Tenant-admin login jail, with app-layer tenant allowlisting

Deliberately **one shared jail across every tenant, not per-tenant
fail2ban jails** -- a ban on port 443 is platform-wide regardless of
which tenant's log triggered it (the constraint explained above), so
per-tenant jail machinery here would be complexity without a matching
benefit. `images/tenant-admin/app.py` gained a genuine append-only
`login_attempts.log` (`/data/login_attempts.log`, distinct from the
existing `login_attempts.json` *state* file the local lockout already
used) written from `_login_record_failure`, plus a new
`fail2ban_allowlist.txt` (same host-visible-via-phpconf pattern as the
existing `ip_acl.txt`) and a new `require_2fa`-gated `/fail2ban-allowlist`
page mirroring the existing IP-restrictions page. Before writing a
failure line, the IP is checked against *that tenant's own* allowlist
-- if present, the line is never written at all. This is the tenant
allowlist's honest, real effect: it can't override a ban a *different*
tenant's traffic triggers (still platform-wide once it happens), but it
does mean a tenant's own allowlisted IPs never contribute to triggering
one. New `deploy/fail2ban/filter.d/vhsp-tenant-admin-login.conf`
matches this log's JSON-lines format; new jail
`[vhsp-tenant-admin-login]` uses a wildcarded `logpath =
/srv/vhsp/tenants/*/phpconf/login_attempts.log` (fail2ban's standard
"one log per site" pattern, picks up new tenants automatically) with no
tenant slug passed to `ignorecommand` (can't know which tenant's file
matched from a wildcarded jail -- the per-tenant precision lives in the
app-layer gating above, not here).

**Two real bugs caught during rollout, not glossed over**:

1. fail2ban's config test (`fail2ban-client -t`) hard-fails if a
   wildcarded `logpath` matches *zero* files -- true for a brand-new
   tenant whose container hasn't started yet, and true for a completely
   fresh deployment with no tenants at all. Fixed two ways: `app.py`
   now touches `login_attempts.log` into existence at import time
   (every container start, not just first failure), and a permanent
   placeholder (`TENANTS_DIR/_f2b-placeholder/phpconf/login_attempts.log`
   -- a name that can never collide with a real tenant slug, since
   `slugify()` never produces underscores) keeps the glob non-empty even
   with zero real tenants.
2. **The more important one**: `images/tenant-admin/app.py` had *no*
   `ProxyFix`/`X-Forwarded-For` handling anywhere, unlike `web.py`'s own
   `ADMIN_TRUST_PROXY`-gated setup. Without it, `request.remote_addr`
   was just Traefik's own bridge-network IP for every single request --
   confirmed directly, a real external test login showed up in
   `login_attempts.log` as `172.18.0.2`, not the real client. This would
   have made the jail either useless (every "attacker" looks identical)
   or actively dangerous (banning Traefik's own address would break
   every tenant at once). Fixed by adding `ProxyFix` unconditionally
   (not opt-in like `web.py`'s -- every tenant-admin container is
   *always* reached through the same local Traefik instance on both
   entrypoints it's ever routed on, so there's no legitimate zero-hop
   case here to guard against, unlike the operator UI which can
   genuinely run with no reverse proxy in front of it).

**Verified on vhsp2** against real traffic: after the `ProxyFix` fix, a
real external-origin failed login (same methodology as the operator
jail's own verification -- curled from outside the host, not via SSH
into it) landed in the real tenant's `login_attempts.log` with the
correct real IP. `fail2ban-regex` confirmed the filter matches (2/2).
Wrote a real allowlist entry directly to a live tenant's own file
(matching what the UI would write), confirmed a subsequent real failed
login from that now-allowlisted IP produced *no* new log line, then
confirmed a still-not-allowlisted test correctly still gets logged.
Confirmed the actual ban/unban path with the same safe `192.0.2.1`
method as the other jails. Both live tenants' sites and admin panels
confirmed healthy throughout.

### Per-tenant SFTP jails (genuine port-level isolation)

Unlike the two HTTP-layer jails above, SFTP genuinely has a distinct
port per tenant (`ssh_port`, the 2200-2299 range), so a ban here
actually stays scoped to just one tenant rather than being
platform-wide. New root-owned `deploy/vhsp-fail2ban-tenant-jail <slug>
<ssh_port> <install|remove>` (5th wrapper script, same
self-validating-arguments pattern as `vhsp-harden-hostdir` etc., new
`VHSP_FAIL2BAN_TENANT` `Cmnd_Alias` in `deploy/vhsp-sudoers`) writes or
removes `/etc/fail2ban/jail.d/vhsp-sftp-<slug>.conf` -- `port =
<ssh_port>` (that tenant's own specific port, not the whole range),
`logpath = TENANTS_DIR/<slug>/logs/sftp.log`, `ignorecommand` passed
**with** the tenant's slug (checks the operator allowlist OR that one
tenant's own `fail2ban_allowlist.txt` -- the same file already used by
the tenant-admin login jail, one list per tenant covering both of that
tenant's jails). `provisioner.create_tenant()`/`destroy_tenant()` call
this script as a lifecycle hook (install right after routing-table
regeneration on create; remove first thing on destroy, before any
container/volume teardown, so fail2ban stops referencing paths that are
about to disappear). Pre-touches `sftp.log` on install for the same
"config test hard-fails on a zero-file logpath" reason as the tenant-
admin-login jail's own placeholder fix, just per-tenant here instead of
via a wildcard.

**Two real bugs caught during rollout, not glossed over**:

1. The SFTP container's own log (`atmoz/sftp`'s entrypoint wrapper
   redirects raw OpenSSH stdout/stderr via `>>`, no syslog wrapper) has
   **no timestamp prefix at all** -- confirmed directly, real lines look
   like `Failed password for root from 113.44.174.240 port 59880 ssh2`
   with nothing before it. The stock `sshd` filter assumes a
   syslog-style prefix and can't be reused as-is. First tried `[INCLUDES]
   before = sshd.conf` to reuse its own well-tested failregex while only
   overriding date handling -- didn't work in practice (confirmed via a
   dry-run against a guaranteed-matching synthetic line: zero matches,
   even after date-parsing itself was confirmed fixed). The stock
   filter's failregex runs against a `prefregex`-extracted `<F-CONTENT>`
   group built from `common.conf`'s own prefix-stripping macros, which
   doesn't reliably compose through `[INCLUDES]` the way that first
   attempt assumed. Replaced with a small, fully self-contained
   `deploy/fail2ban/filter.d/vhsp-tenant-sftp.conf` (same shape as
   `vhsp-admin-login.conf`/`vhsp-tenant-admin-login.conf`), hand-written
   failregex matching the real line shapes directly, no dependency on
   the stock filter's macro system.
2. **A subtler one, found only by watching a *live* jail, not just
   offline `fail2ban-regex` output**: the first fix for the missing-
   timestamp problem was `[Init] datepattern = {NONE}`, meant to
   explicitly disable date-parsing. `fail2ban-regex` confirmed this
   "worked" -- real matches, a "Date template hits" count against `^`.
   But the *live*, pyinotify-watched jail never registered a single
   failure against the same file with the same filter, even though
   `fail2ban-client status` confirmed the watch was active and
   `fail2ban.log` showed the file's modify events actually arriving.
   Root cause: `{NONE}` doesn't mean "treat every line as now" the way
   it reads -- it produces an internal date-pattern object that the
   offline dry-run tool tolerates but the live filter's matching path
   does not, silently dropping every match instead of erroring. Neither
   `vhsp-admin-login.conf` nor `vhsp-tenant-admin-login.conf` (both also
   watching effectively-dateless content) ever set `[Init] datepattern`
   at all -- fail2ban's *default* date detector already fails-open to
   "use now" for a line with no discoverable date, which is exactly the
   desired behavior. Dropped the `[Init]` section entirely to match
   that already-proven shape; live jail then correctly logged `Found
   <ip> - <timestamp>` and incremented "Total failed" on the very next
   append.

**Verified on vhsp2** with a real disposable test tenant
(`f2bsftptest.vhsp2.dvce.us`, SSH port 2202): jail file appeared with
the right port/logpath/ignorecommand on create, `fail2ban-client
status` showed it active; destroyed the tenant, confirmed the jail file
was removed and the jail count dropped back down. Both pre-existing
live tenants (`smoketest-vhsp2-dvce-us` port 2200,
`testing-bigchimp-org` port 2201, both created before this code
shipped) backfilled with jails via the same script run manually once.
After the two bug fixes above, confirmed **live** (not just offline)
against `smoketest-vhsp2-dvce-us`'s real `sftp.log`: a freshly appended
synthetic failure line was picked up within seconds of the append,
`fail2ban-client status` showed `Currently failed: 1, Total failed: 1`.
Confirmed the operator allowlist correctly suppresses a matching
failure (added a scratch IP, appended a matching failure line, status
stayed unchanged; removed the scratch entry afterward). Confirmed
actual ban/unban with the same safe `192.0.2.1` method as every other
jail -- a real `nft` set element appeared and disappeared correctly.

### Operator log viewer: `/fail2ban`

New global nav page, `astjohn` (matching every other operator page --
`@require_auth`, no `@require_2fa` since it's read-only with no write
action, same shape as `/audit`). `/var/log/fail2ban.log` isn't
documented anywhere as readable by a non-root user, so rather than
loosen that file's permissions, a new root-owned wrapper script
(`deploy/vhsp-fail2ban-log-tail <n>`, validates `<n>` is a small
positive integer, `tail -n "$n" /var/log/fail2ban.log`) is the read
path -- same "one narrow script per concern" pattern as every other
sudoers grant here, new `VHSP_FAIL2BAN_LOG` `Cmnd_Alias`. Shows the
last 200 lines, every jail mixed together (host SSH, this admin UI's
own login jail, the shared tenant-admin-login jail, every tenant's own
SFTP jail) since that's what the log file itself does -- no per-jail
filtering in this pass. `provisioner.tail_fail2ban_log(n)` shells out
to the wrapper; `_run()` (the existing helper used for every other
sudo action here) deliberately discards output, so this is a small new
dedicated `subprocess.run(...)` call rather than a change to `_run()`'s
signature. Verified on vhsp2: real fail2ban.log content confirmed
returned through the wrapper (genuine SSH-scanning activity, not
synthetic), bad arguments (`abc`, `99999`) correctly rejected, the real
page renders it.

## Coraza WAF: per-tenant OWASP Core Rule Set, Phase 1 complete

Real request-content inspection (SQLi/XSS/RCE/LFI/RFI/etc, the piece
fail2ban's IP-banning doesn't cover) -- named as a follow-up since the
fail2ban work began, built once asked to go ahead.

**The obvious approach doesn't work, so this isn't a Traefik plugin.**
Traefik's only native, production-grade Coraza integration is Traefik
Hub -- a commercial product requiring an account/license, the same
category of dependency fail2ban was specifically chosen over CrowdSec
to avoid. The open-source Traefik path (`coraza-http-wasm-traefik`, a
WASM plugin) is real but early-stage and, critically, **cannot load the
OWASP Core Rule Set at all** -- WASM sandboxing blocks the filesystem
access CRS's `Include` directives need, leaving only a handful of
hand-written inline rules, nowhere near "a WAF." The path that actually
delivers real, free, self-hosted CRS coverage is running Coraza as its
own reverse-proxy container -- confirmed by pulling the image and
inspecting it directly (not trusting docs): `ghcr.io/coreruleset/coraza-crs:nginx`
genuinely bundles and activates the full CRS rule families
(`/opt/coraza/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf`
and siblings for XSS/RCE/LFI/RFI/etc), not a stub.

**One WAF container per tenant** (`vhsp-<slug>-waf`,
`provisioner._create_waf_container`), not one shared instance -- the
image only supports a single `BACKEND=host:port` target per instance
anyway (no multi-tenant routing of its own), and per-tenant containers
is the same "no shared daemon, isolation over density" shape
architecture.md already applies to DB/mail/SSH.

**Routing moved from the web container to the WAF container.**
`_create_web_container` no longer sets any `traefik.*` labels at all --
the WAF container owns the tenant's public `Host(<domain>)` router now
and reverse-proxies to the web container by name
(`BACKEND=vhsp-<slug>-web:80`). Traffic becomes Traefik → WAF → web
instead of Traefik → web directly. `_create_web_container` still joins
`GATEWAY_NETWORK` (so the WAF sidecar can reach it) and gained a new
`WAF_CONTAINER_NAME` env var (deterministic from `slug`, no new
coordination needed between the two container-create functions).

**Real-client-IP chain, the part most likely to have silently broken
something.** `images/web/entrypoint.sh` used to trust exactly one
dynamically-resolved hop (`traefik`, via `getent hosts`). With the WAF
container now the *actual* immediate peer this nginx sees, it gained a
second `getent hosts $WAF_CONTAINER_NAME` lookup, trusted alongside the
existing `traefik` one so `real_ip_recursive` can still walk WAF →
Traefik → real client correctly. Verified this wasn't just a hopeful
assumption two different ways: (1) pulled the WAF image and inspected
its actual `/templates/nginx.conf` directly -- confirmed
`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for` correctly
*appends* to the header rather than overwriting it; (2) built the
updated web image locally and ran it against a synthetic sibling
container on an isolated Docker network -- the generated
`vhsp-realip.conf` showed `set_real_ip_from <the sibling's real
IP>/32`, confirmed byte-for-byte against `docker inspect`'s own report
of that container's address, before ever touching vhsp2.

The WAF container's *own* real-IP settings needed a similar fix for a
different reason: the image defaults to trusting only `127.0.0.1` and
reading `X-Real-IP` (Traefik sends `X-Forwarded-For`, not
`X-Real-IP`, and isn't loopback relative to this container) -- without
correcting this, the WAF's own audit log would attribute every
detected/blocked request to Traefik's address instead of the real
attacker. Fixed by looking up `GATEWAY_NETWORK`'s actual subnet live via
the Docker API at WAF-container-creation time (`SET_REAL_IP_FROM`) --
not hardcoded, since the subnet is whatever was assigned when that
network was created, which genuinely differs across this project's own
deployments -- and setting `REAL_IP_HEADER=X-Forwarded-For` to match
what Traefik actually sends.

**Detection-only by default.** New `WAF_ENGINE_MODE` config
(`VHSP_WAF_ENGINE_MODE`, default `DetectionOnly`, wired into the
image's own `CORAZA_RULE_ENGINE` env var) -- logs would-be blocks
without actually blocking traffic. OWASP CRS is well known to
false-positive against real-world app traffic (rich HTML/form posts,
file uploads), and unlike a fail2ban false-positive ban (self-heals in
15-30 minutes), a WAF false positive in blocking mode just breaks a
legitimate request outright with no auto-recovery -- same "safe
default, escalate deliberately" posture as the PHP dangerous-functions
toggle. Also raised the image's own conservative request-body-size
defaults (`CORAZA_REQ_BODY_LIMIT` 12.5MB → 210MB,
`CORAZA_REQ_BODY_NOFILES_LIMIT` 512KB → 4MB, both confirmed via direct
image inspection, not docs) -- tenant sites do real file uploads
(WordPress media, etc.), and `TENANT_ADMIN_MEM_LIMIT`'s own 200MB
upload cap already establishes large uploads as normal, expected
traffic on this platform, not something to reflexively block.

**New cgroup limits, following the established pattern**:
`WAF_MEM_LIMIT`/`WAF_NANO_CPUS` (256MB/0.5 CPU -- a reverse-proxy
sidecar's baseline load, lighter than DB/web/mail/tenant-admin's 512MB
tier).

**Image pinned by digest**, not `:latest` or even a bare version tag --
per the still-open Finding #11 from the last security review, and
because this is genuinely load-bearing security infrastructure now, not
just a reproducibility nicety. `config.py`'s own comment on `WAF_IMAGE`
says exactly how to re-verify a future digest bump before trusting it
(pull it, inspect `/opt/coraza/owasp-crs/rules/` and
`/templates/nginx.conf` directly, the same way this one was verified).

### Verified on vhsp2 -- Phase 1 only, against a real disposable tenant

A real `vhsp tenant create` for a throwaway domain
(`coraza-test.vhsp2.dvce.us`), not a synthetic/local-only test:

- `docker inspect` confirmed the WAF container's labels/env exactly as
  designed (`BACKEND=vhsp-<slug>-web:80`, correct Traefik router rule,
  `SET_REAL_IP_FROM` showing the real, live-looked-up `172.18.0.0/16`
  gateway subnet) and confirmed the web container carries zero
  `traefik.*` labels.
- A real HTTPS request through Traefik → WAF → web returned the
  tenant's real placeholder page, 200.
- Real client IP confirmed correctly propagated through *both* proxy
  hops into the web container's own nginx access log -- not just via a
  planned test curl (`216.106.72.201`, this environment's own known
  outbound address), but incidentally via genuine background-scanner
  traffic that had already found the brand-new tenant within seconds of
  creation, real source IPs and all.
- In `DetectionOnly` mode: a real SQLi payload
  (`?id=1' OR '1'='1`) produced a `200` (not blocked) with the WAF's own
  audit log showing a genuine libinjection-based SQLi detection and an
  anomaly score of 5 -- confirmed via the actual JSON audit log entry,
  not just an HTTP status code. Separately, real live attack traffic
  unrelated to this test (a bot probing for `.sql` backup files) was
  independently caught by CRS's protocol-enforcement rules in the same
  log, unprompted -- further proof this is actively inspecting real
  traffic, not idling.
- Flipped `WAF_ENGINE_MODE` to `On` for that one test tenant only (via
  a scoped env override on `recreate_waf.py`, not the platform-wide
  default) -- confirmed via `docker inspect` the container's
  `CORAZA_RULE_ENGINE` actually changed. The same SQLi payload then
  produced a real `403`; a normal request to the same tenant still
  returned `200` -- blocking mode works without false-positiving on
  legitimate traffic.
- `vhsp tenant destroy` cleanly removed the WAF container and left no
  orphaned volumes.
- Confirmed both pre-existing live tenants
  (`smoketest.vhsp2.dvce.us`, `testing.bigchimp.org`) were completely
  unaffected throughout -- still on their original web containers with
  the original direct-routing labels, no WAF container, real `200`s the
  whole time. Phase 1 deliberately doesn't touch already-live tenants.

### Phase 2 done: retrofitting the two live tenants

Retrofitting an already-live tenant (`recreate_waf.py` then the
now-guarded `recreate_web.py`) isn't atomic across two separate
containers, so before ever running it against real traffic, the exact
overlap window was characterized directly rather than assumed safe:
two disposable throwaway containers were given the *identical* Traefik
router name and service name (matching exactly how the old web
container and new WAF container both use `vhsp-<slug>` for both) and
watched live. Confirmed Traefik doesn't error, drop the router, or pick
one arbitrarily -- it silently merges both containers into one
load-balanced service pool and round-robins between them (verified via
5 sequential requests alternating cleanly between the two backends).
Applied to the real retrofit sequence, this means the brief overlap
between creating the WAF container and stripping the old web
container's labels costs **zero dropped requests** -- some requests
briefly go direct-to-web (skipping WAF inspection) and some go via the
new WAF, but every single one still reaches the real site successfully.

Retrofitted both `smoketest.vhsp2.dvce.us` and `testing.bigchimp.org`
this way, `DetectionOnly` (the platform default, no override). Verified
per tenant, same depth as Phase 1's disposable-tenant testing: real
site + tenant-admin panel both still return `200` afterward, web
container labels confirmed stripped (`docker inspect`), WAF container's
`BACKEND` confirmed pointed at the right container, real client IP
confirmed still correctly propagating into the web container's own
access log (both a planned curl and genuine third-party visitor
traffic), and a real SQLi test payload against each live tenant
correctly detected by CRS and correctly *not* blocked (`DetectionOnly`
still active, as designed). Both tenants' fail2ban jails, SFTP access,
and every other existing feature confirmed untouched throughout.

**Still not done, by design**: neither live tenant has been flipped to
actual blocking mode -- that's a separate decision needing a real
observation period against real production traffic in `DetectionOnly`
first, not something to bundle into the retrofit itself. A per-tenant
WAF engine-mode toggle (platform-wide `WAF_ENGINE_MODE` only, for now,
matching how fail2ban's own thresholds are platform-wide) and an
operator/tenant IP allowlist bypass for the WAF layer (fail2ban has
one, Coraza doesn't yet) remain natural future follow-ups, not built.

### Operator log viewer: WAF section on the existing per-tenant Logs page

Coraza's audit log never touches the shared `logs_volume` this app
already tails for web/mail/sftp/php-error logs -- `_create_waf_container`
doesn't mount it, and `CORAZA_AUDIT_LOG=/dev/stdout` means the only
channel is the WAF container's own stdout, captured by the Docker
daemon. This codebase had never read a container's Docker-API logs
before (grepped for `.logs(` across the whole repo -- zero hits prior
to this), and the Docker socket proxy wasn't configured for that
endpoint either: `tecnativa/docker-socket-proxy` gates
`GET /containers/{id}/logs` behind its own `LOGS` flag, separate from
the general `CONTAINERS` flag every other Docker call here already
relies on. Added `-e LOGS=1` to `deploy/vhsp-docker-proxy.service` and
verified it with a direct `container.logs()` call through the real
running proxy against a real container *before* wiring it into any
route -- confirmed real content came back, not a 403 or empty response.

New `provisioner.tail_waf_log(slug, n)`:
`_client().containers.get(f"vhsp-{slug}-waf").logs(stdout=True,
stderr=True, tail=n)`, catching `docker.errors.NotFound` → `None` --
same "no entries yet" contract `toggles.tail_log` already uses for a
missing file, so a tenant with no WAF container yet (not retrofitted)
needs no special-casing in the template. Added as a 6th entry on the
existing `/tenants/<domain>/logs` page (`tenant_logs()`) alongside the
5 file-based logs, identical `<pre>` rendering -- raw JSON-lines, not
parsed/summarized (real parsing complexity for multiple event shapes;
deliberately deferred, raw is still readable enough for what was
asked). Jinja's default auto-escaping handles the JSON safely in the
`<pre>` block with no extra work -- confirmed via the real page source,
attacker-controlled content in a captured request (the earlier SQLi
test payload) renders as literal escaped text, not executable markup.

**Verified on vhsp2** against both live tenants: real authenticated
session (a disposable test operator, removed after), both
`/tenants/smoketest.vhsp2.dvce.us/logs` and
`/tenants/testing.bigchimp.org/logs` show a real "WAF (Coraza)"
section with genuine audit-log content, including the earlier SQLi
test's own detection event still visible in the tail. All 5 existing
log sections confirmed still rendering correctly alongside it -- no
regression.

## Audit log tamper-evidence and login events

`audit.py`'s local log was "append-only" by convention and file
permissions (0600, opened in `"a"` mode) only -- never actually
tamper-evident on-host, despite architecture.md calling it
"immutable/append-only." The real defense was always the off-host
shipping (`backup.ship_audit_log`, every minute), which stops a
compromise from retroactively erasing history that's already left the
host -- but it did nothing to reveal tampering with entries still sitting
in the local file waiting to be shipped. Separately: every existing
`audit.log_action()` call site was a tenant/operator *mutation* (create,
destroy, password reset, WebAuthn/TOTP change) -- there was no login,
logout, or failed-login event on the operator admin UI at all, which
matters for incident response ("who logged in, when, how many guesses
came first").

**Hash chain**: every new entry now carries a `prev_hash` field --
`sha256` of the previous line's exact JSON bytes, `""` for the first
entry ever written. `vhsp audit verify` (`cli.py`, backed by
`audit.verify_chain()`) walks the log and confirms each entry's
`prev_hash` matches the real hash of the line before it; a mismatch
means something between those two entries was edited or deleted, and
it's reported by index. This doesn't make the file immutable -- an
attacker with the file's owner privileges can still edit it -- but it
makes tampering *detectable*, closing the gap between "host compromised"
and "next successful ship" that unsigned shipping alone left open (see
`ship_audit_log`'s own docstring, which already named remote-side
tamper-detection as a separate not-yet-built increment; this is the
local-side half of the same concern). Entries written before this field
existed have no `prev_hash` key at all -- deliberately not treated as
"prev_hash was empty string" (every pre-existing log would otherwise
report a spurious break at its second entry); instead they're skipped
without asserting anything, and the first entry that does have the field
becomes a trusted fresh starting point for strict verification from
there on. `ship_audit_log`'s byte-offset shipping is untouched by any of
this -- it ships whatever bytes are new regardless of their content, so
a longer JSON line per entry doesn't change anything about how it
resumes progress.

**Login events**: `web.py` now logs `admin.login`/`admin.login_failed`/
`admin.logout` from every completion point on the operator side --
password-only login, the TOTP step, and the WebAuthn step, plus logout.
Scoped to the operator admin UI only for now: `images/tenant-admin/app.py`
has no audit-trail system to log into at all (it's a separate,
self-contained container with its own web-server-style logs, not an
`audit.py` equivalent) -- building one from scratch there is a
meaningfully bigger task than adding three event types to an existing
system, and is named here as a follow-up rather than silently skipped.

**Verified on vhsp2** against the real running log, not a local test:
`vhsp audit verify` against the 58 pre-existing (unchained) entries
correctly reported the chain intact rather than spuriously broken. A
real login/logout cycle (one failed attempt, then a successful login,
then a logout) against a disposable test operator produced exactly the
three new event types, correctly chained. Directly tampering with one
new entry's content (changing its `domain` field, leaving its own
`prev_hash` untouched) made `vhsp audit verify` correctly report a break
at the *next* entry -- the standard, expected way a hash chain reveals
tampering with the entry before it, not the tampered entry itself.
Restoring the original file made verification pass again. The real
`vhsp-audit-ship.timer`-triggered service run (not a manual invocation)
shipped the new entries successfully with no errors, confirming the
longer per-entry JSON didn't break anything downstream.

## Backup / restore

Two independent tiers, both real, neither optional in the way that matters:

- **Operator**: every tenant is backed up automatically to one
  operator-configured SFTP destination, always, with no per-tenant
  opt-out. Can restore even a fully-destroyed tenant/domain -- including
  onto a completely different vhsp deployment, which recreates it from
  scratch.
- **Tenant**: a tenant can *additionally* configure their own separate
  SFTP destination, in addition to the operator's copy, never instead of
  it. Client-side encryption is optional there (with a clear on-screen
  warning if skipped), but the operator's own copy is **always**
  encrypted -- a hard requirement, not a preference, given what's inside
  a backup (DB dump, mail, admin credentials).

### Three purpose-specific keypairs, never reused

Generated once via `vhsp backup init` (each shown exactly once in that
command's own output, with a hard warning to copy them to secure offline
storage -- the same "generated, shown once, never re-displayed" pattern
already used for the operator/tenant-admin passwords elsewhere in this
codebase):

1. **SSH transport** (`ssh-keygen -t ed25519`) -- authenticates the push
   to the operator's shared destination.
2. **`age` encryption** (`age-keygen`) -- encrypts every operator-
   destination snapshot; mandatory, no opt-out.
3. **Ed25519 signing**, verified via OpenSSH's own `ssh-keygen -Y sign`/
   `-Y verify` (the native "sshsig" format) rather than introducing a new
   signing tool -- every restore, operator- or tenant-triggered, verifies
   this signature first and refuses outright on a mismatch. This is the
   actual anti-tampering control: a compromised destination can hand back
   a byte-for-byte corrupted or edited snapshot, but it can't produce one
   that both decrypts and verifies.

Deliberately **not** Docker Swarm secrets (only mountable into Swarm
*services*, and tied to that swarm's own raft state -- a recoverability
trap if this host is lost) and **not** systemd-creds (TPM/host-bound, same
trap). Plain `0600` root-owned host files under `$VHSP_STATE_DIR/backup/`
instead, exactly like every other credential this codebase already manages
outside of Docker/systemd's own secret stores.

A tenant's own *additional* destination gets its own SSH transport
keypair (only the **public** half is ever shown, for the tenant to
install on their own destination -- the private half never leaves this
host) plus an optional `age` keypair, tenant-supplied or generated on
request. If vhsp generates it, it's shown exactly once in the tenant
admin page's Backups tab, then retained server-side (`0600`, never
re-displayed) so the recurring schedule and restore-time decryption keep
working unattended.

### What's actually in a snapshot

Webroot (tar), a **logical** DB dump (`mariadb-dump --single-transaction`,
not a raw datadir copy -- consistent under load, unlike a live copy), the
mail maildir (tar), and the `phpconf` volume (tar -- mailboxes, quotas,
toggles, admin credentials). Each component is compressed individually;
all four plus a manifest and its signature are bundled into one outer tar
per snapshot, which is what gets `age`-encrypted as a single unit when
encryption applies.

**WebAuthn is never in a backup.** A tenant recreated from scratch (its
domain didn't exist here, or existed on a different deployment entirely)
comes back password-only, with a clear warning that WebAuthn needs to be
re-registered. Restoring *content* into an already-existing tenant leaves
that tenant's current WebAuthn credentials completely untouched -- the
backup itself never touches that file either way. Every other credential
(DB/mail/tenant-admin passwords) is reused exactly as it was at backup
time, never regenerated.

Restoring re-provisions on the manifest's original SFTP port *unless it's
already taken*, in which case it falls through to the normal port
allocator for a fresh one -- backups are never allowed to collide with
whatever's actually running here now.

### Destination layout

`<dest>/<tenant-domain>/<timestamp>.tar[.age]` -- one directory per
domain, browsable directly over SFTP (`vhsp backup list-remote`) even for
a domain with zero rows in this deployment's own registry, which is what
makes "restore a fully-deleted tenant" and "restore onto a fresh
deployment" both work with no local bookkeeping required.

### Scheduling

A systemd `.timer`, not an in-process scheduler thread -- matches
`vhsp-admin` already being a standalone systemd unit rather than
embedding its own loop:

- `deploy/vhsp-backup.timer` + `.service`: daily, runs `vhsp backup
  run-all`, which only actually backs up tenants whose own retention/
  interval (default: keep 30, daily -- both platform defaults,
  per-tenant overridable, same shape as the existing per-tenant quota
  override) says they're due. One tenant's failure (e.g. its DB
  container is down) never aborts the sweep for everyone else.
- `deploy/vhsp-backup-reconcile.timer` + `.service`: every ~2 minutes,
  runs `vhsp backup process-requests`.

Both timers also back "back up now" from the admin UI (immediate) and
from tenant-admin (picked up on the reconciler's next ~2-minute pass).

### Why the tenant side needs a *second* timer, not just the admin UI

`images/tenant-admin/app.py` has no access to `docker.sock`, this
control plane's registry, or any other host-level tooling -- every
existing tenant self-service feature (PHP toggles, nginx config,
mailboxes) works by writing a small file to the shared `phpconf` volume
that something *outside* the tenant's own container watches and acts on.
Backup key generation, `mariadb-dump`, and SFTP push all need host/Docker
access no tenant container has or should gain, so tenant-configured
backup settings follow that exact same shape: tenant-admin's Backups tab
only ever writes `backup_request.json` (desired destination/encryption
choice) and touches `.vhsp-backup-now`, both on the shared `phpconf`
volume; `vhsp backup process-requests` (the reconciler timer above) is
the thing that actually reads those, generates keys, and pushes/restores.
`backup_status.json` -- written only by that reconciler -- is how
tenant-admin then displays the tenant's own public transport key (safe
to redisplay any time) and a one-time-only reveal of a freshly-generated
`age` private key. This means a tenant-side settings change takes effect
within about 2 minutes, not instantly -- a deliberate, documented
tradeoff given the alternative is granting a tenant-facing container
host-level access.

### CLI

```
vhsp backup init [--force]                       # generate operator keys (shown once)
vhsp backup create <domain>                      # back up now
vhsp backup run-all                              # the daily timer's own entry point
vhsp backup list <domain>                         # this deployment's own registry rows
vhsp backup list-remote [--domain X] [--source operator|tenant]
vhsp backup restore <domain> <snapshot> [--source operator|tenant] [--as-domain X]
vhsp backup process-requests                      # the reconciler timer's own entry point
vhsp backup ship-audit-log                        # the audit-ship timer's own entry point
```

### Audit log shipping

`audit.py`'s `log_action` (tenant create/destroy today) writes a local,
root-only, append-only `audit.log` -- but a trail that only exists on the
host it's recording actions against doesn't survive that host being the
thing that's compromised. `backup.ship_audit_log`, run every minute by
`deploy/vhsp-audit-ship.timer` + `.service`, ships new entries off-host
to close that gap:

- Reuses the **same operator SFTP destination and SSH key** tenant
  backups already push to (`VHSP_BACKUP_SFTP_*`) rather than standing up
  a second destination -- one thing to secure, not two.
- Ships only what's new since the last successful push, tracked via a
  byte-offset marker file (`AUDIT_SHIP_STATE_PATH`, next to the other
  plain-marker-file state like `auth.py`'s `SECRET_KEY_PATH` -- not a
  registry row, since there's nothing to look up by domain or slug
  here). Each run is therefore cheap (a handful of JSON lines, not a
  tenant snapshot), which is why the timer runs every minute rather than
  the backup reconciler's ~2 -- minimizing how much of the trail a fresh
  compromise could still erase before it's shipped out of reach.
- Lands as small timestamped chunk files (`<dest>/_operator-audit/
  <timestamp>.log`) rather than one continuously-appended remote file --
  SFTP has no native remote-append, and rewriting a growing remote file
  every run would mean re-uploading the whole history each time.
- **Deliberately not signed**, unlike backup snapshots. Signing exists
  for backups because a *restore* trusts the file's contents enough to
  recreate a tenant from it -- tampering there has to be caught before
  acting on it. Shipped audit chunks are never replayed into anything;
  they're read-only evidence for whoever's investigating an incident,
  who can already tell a forged chunk from a genuine one by cross-
  referencing timestamps/sequence against what's still on the host (if
  it survived) or other operators' independent knowledge. Signing every
  chunk would add real complexity for a threat model that doesn't apply
  here.
- Does **not** call `audit.log_action` on itself -- shipping the log
  isn't itself a privileged tenant-affecting action, and logging every
  minutely shipping run would just add noise to the thing being shipped.

Verified on vhsp2 against the real destination (vm2.dvce.us): first run
shipped the entire pre-existing history in one chunk; an immediate
re-run correctly reported nothing new; creating and destroying a real
throwaway tenant to generate fresh entries produced a second chunk with
exactly the new bytes, confirmed byte-for-byte correct and non-
duplicated by reading both chunks back over SSH. The timer itself was
also confirmed to fire on its own -- not just via manual `vhsp backup
ship-audit-log` -- via `systemctl list-timers` and its own unit's
journal showing repeated automatic runs a minute apart.

### Restore verified end-to-end, a real bug found and fixed doing it

Backup *creation* was verified early (see [[vhsp2-backup-destination-vm2]] in
project memory); restore -- especially `_restore_as_new_tenant`, the
disaster-recovery path that matters most, since it's what a domain that
doesn't exist on this deployment at all depends on -- had never actually
been exercised until this pass. It was worth doing: a real bug surfaced
immediately.

**The bug**: `_wait_for_db` (used only by this restore path -- normal
`tenant create` has no immediate hard DB dependency, so it never exercised
this) required two consecutive successful pings, one second apart, on the
theory that the official MariaDB image's temporary bootstrap-only mysqld
instance (spun up to run init scripts, then torn down before the real one
starts) would be gone by the second check. Verified directly against real
container logs that this isn't reliable: the bootstrap instance's own
window measured ~2 seconds end to end, easily long enough to land two
consecutive pings inside it, and there's a further multi-second gap after
it shuts down before the real instance is ready where *neither* answers --
landing the restore import there raised a confusing `Can't connect to
local server through socket` (one run) or a TLS-flavored broken-pipe from
the client library giving up mid-handshake (a different run) instead of
an obvious connection-refused. Fixed by requiring three consecutive
successes two seconds apart -- a ~4-6 second continuous-uptime bar the
~2-second bootstrap window can't clear, while adding negligible latency
to the common case.

**What got verified, all against real infrastructure, not just exit
codes**: restoring `smoketest.vhsp2.dvce.us`'s own snapshot under a
different domain (`--as-domain`) -- registry entry correct (fresh SSH
port allocated, containers correctly namespaced under the new slug, DB/
mail/tenant-admin credentials reused verbatim from the manifest exactly
as backed up, *not* the tenant's current live ones) -- all 5 containers
healthy, the site reachable over a **real Let's Encrypt certificate**
Traefik obtained for the new domain with zero manual DNS setup (this
deployment's `*.vhsp2.dvce.us` wildcard record made that automatic --
not something to assume for an arbitrary customer domain), and a real
login to the restored tenant-admin panel using the exact password from
backup time, not the live tenant's current one. Also verified the
**mandatory signature check actually rejects tampering**, not just in
theory: decrypted a real snapshot, edited a credential in `manifest.json`,
re-encrypted with the operator's (public) age key but deliberately did
*not* re-sign it (an attacker who only compromised the destination
wouldn't have the signing private key either, which never leaves this
host), pushed it back, and confirmed `vhsp backup restore` refused it
with `backup signature verification FAILED -- refusing to restore
(possible tampering)` -- and, just as importantly, created zero
containers or volumes in the process, since the check runs before a
single byte of tenant data is extracted.

**Separate, smaller finding along the way, fixed the same night**:
`tenant destroy` leaked the mail container's `dkim` volume
(`_create_hardened_volume(..., "dkim")` in `provisioner.py`) and its
host directory -- `dkim_volume` was never added to `registry.Tenant`'s
fields (a deliberate choice at the time, since the volume's name is
fully deterministic from `slug` alone, so nothing needed to look it up
to *reuse* it -- that reasoning just never got extended to *destroy*).
Affected every tenant destroy on this platform, not just a restored one.
Fixed in `destroy_tenant` by computing the same deterministic name
(`f"vhsp-{slug}-dkim"` / `TENANTS_DIR / slug / "dkim"`) rather than
adding a registry column for a value that never needed one -- verified
against a real throwaway tenant (create, confirm the volume/directory
exist, destroy, confirm both are gone).

## Operator API + MCP

Programmatic/AI-agent access to the same things the operator admin UI
already does -- see architecture.md's "API and MCP access for operators
and tenants" for why this exists and its two non-negotiable constraints
(opt-in, 2FA-gated). Operator-level only for now; a tenant-level
equivalent (mirroring `images/tenant-admin/`'s own self-service surface)
is a deliberately deferred follow-up, not started.

**Off by default, and independently toggleable.** `config.API_ENABLED`/
`config.MCP_ENABLED` gate their respective surfaces structurally, not
just behind a check: `API_ENABLED` false means the REST API's Flask
Blueprint is never registered onto `web.py`'s `app` (`/api/v1/*` 404s
like the routes don't exist, not 401); `MCP_ENABLED` false means
`mcp_server.py`'s own `main()` refuses to bind at all. The two flags are
deliberately decoupled (an earlier version of this feature had MCP piggyback
on `API_ENABLED`; see `config.py`'s own comment on why that no longer
holds) -- an operator can turn either on without the other.

### Turning it on: a UI toggle, not a host-level env var

Both flags are runtime-mutable from the admin UI itself (My account ->
API & MCP access, next to token management, `@require_2fa` like every
other consequential action here) -- no SSH access to the host needed for
routine on/off, a real gap fixed after a user tried to find a toggle and
correctly found none. `vhsp_ctl/platform_settings.py` is the write side:
`STATE_DIR/platform_settings.json` persists the flags across restarts,
and `config.py`'s own read of that file (falling back to the original
`VHSP_API_ENABLED`/`VHSP_MCP_ENABLED` env vars only if the file doesn't
exist yet or doesn't mention a key) is the only new "runtime-mutable
setting" pattern in a codebase where every other `config.py` value is a
pure env-var-read-once-at-import. A deployment that's never touched the
toggle keeps behaving exactly as before.

The REST API toggle reuses `deploy/vhsp-sudoers`'s existing `VHSP_RESTART`
grant (`systemctl restart vhsp-admin.service`, already there for
routine code deploys) -- flipping the flag and restarting the process is
all that's needed, since Blueprint registration only happens at process
startup. MCP needed genuinely new automation: two new wrapper scripts,
`deploy/vhsp-mcp-toggle` (install/enable or disable the
`vhsp-mcp.service` unit) and `deploy/vhsp-mcp-firewall` (open/close
exactly one `ufw` rule, port hardcoded rather than parameterized -- a
wrapper that opens whatever port it's told is a materially more
dangerous primitive than one that only ever opens this one), both
following the same "root-owned script, sudoers grants the fixed path
only, the script re-validates its own arguments" shape every wrapper
script here already uses (see `deploy/vhsp-harden-hostdir`'s own header
comment for the underlying reasoning). `provisioner.enable_mcp_server()`/
`disable_mcp_server()` call both scripts and also write/delete
`~/traefik/dynamic/vhsp-mcp.yml` directly (a plain, unprivileged file
write -- `astjohn` already owns that directory), discovering the
Traefik gateway's real IP and subnet live via the Docker API rather than
hardcoding them (`_traefik_gateway_info()`, same technique
`_create_waf_container` already established). Disabling MCP reverses all
three completely -- stopped/disabled unit, firewall rule removed, route
file deleted -- not just a stopped process left dangling behind an open
port and a live route.

Verified for real against vhsp2, not just read-only: toggled the REST
API off and back on (confirmed `/api/v1/*` genuinely 404s while off, and
the admin UI survives its own self-triggered restart -- gunicorn treats
`SIGTERM` as its own graceful-shutdown signal, so the in-flight toggle
request's own response completes before the process actually restarts),
and toggled MCP off and back on against infrastructure that had been
manually set up in an earlier session (tearing down the hand-built
systemd unit/firewall rule/Traefik route, then rebuilding all three via
the new automation) -- a real `fastmcp` client round-trip against the
freshly-automated MCP endpoint confirmed the rebuilt setup is
functionally identical to the original hand-built one.

**One real bug found by the user, not caught during that first
verification pass**: after toggling the REST API off, then trying to
toggle MCP off, the page reported success (and the underlying toggle
*had* genuinely succeeded -- settings file and live infrastructure were
both already correct) but kept showing MCP as "On" with a Turn-off
button. Cause: `config.API_ENABLED`/`MCP_ENABLED` are computed once, at
process import time, and the REST API toggle's own restart (needed
because Blueprint registration is a startup-time decision) happened to
mask the same staleness for that flag -- but MCP's toggle deliberately
never restarts `vhsp-admin.service` (no functional need to, since MCP is
a separate process), so the frozen `MCP_ENABLED` constant the toggle
page was displaying from never got a chance to catch up to the file it
had just written. Fixed with `config.current_api_enabled()`/
`current_mcp_enabled()` -- live re-reads of the same settings file, used
everywhere this state is *displayed* to an operator (`/account`,
`/account/api-tokens`, the Manual), while the frozen constants stay
correct for the one thing they actually need to gate (Blueprint
registration, `mcp_server.py`'s own startup check) -- a decision that
really is fixed until the next restart, unlike a status label.

**A second real bug, found by the user immediately after the first fix
was deployed, and directly caused by it**: enabling the REST API threw a
real `500` (`werkzeug.routing.exceptions.BuildError: Could not build url
for endpoint 'api.docs_view'`). The live-reread fix above made
`api_tokens_view()`'s `api_enabled` too live for one specific use inside
its own template: `{% if api_enabled %}<a href="{{ url_for('api.docs_view') }}">`.
Sequence that triggered it: clicking "Turn on" writes
`platform_settings.json` (now `true`) *before* triggering the restart;
the still-running *old* worker -- mid-shutdown, finishing this exact
request during its graceful-termination grace period -- re-renders the
page, `current_api_enabled()` correctly reads the file and says `true`,
the template's `{% if %}` therefore tries to build a URL for the `api`
Blueprint's `docs_view` endpoint -- except that Blueprint was only ever
registered on a worker whose *frozen* `API_ENABLED` was `true` at its own
startup, and this dying worker's was `false`. `url_for()` for a
genuinely unregistered endpoint always raises `BuildError`, live-file
state notwithstanding. (Confirmed underneath the crash: both toggle
actions the user had actually taken -- API and MCP -- had already fully
succeeded; the 500 was purely a rendering bug on the *next* page load,
not a failed toggle.) Fixed by splitting the one template use that needs
"is this Blueprint actually routable on the process handling this exact
request" from every other use of `api_enabled` (status text/badges/button
labels, which are fine to be live) -- a new `api_blueprint_live=API_ENABLED`
(the frozen constant, deliberately) feeds only that one `{% if %}`.
Verified by reproducing the exact race directly (forcing a worker's own
frozen `API_ENABLED` to `False` while the settings file said `True`):
no crash, the Swagger-UI link correctly stays hidden until a real
restart catches up, while the status badge still correctly reflects the
live, already-toggled state.

**A third real bug, found by the user right after the second fix**:
turning the REST API off (or on) returned a genuine `502 Bad Gateway`
from Traefik -- but reloading the page immediately afterward worked
fine. Different failure mode from the first two: a 502 means Traefik
couldn't reach *any* backend, not a Python-level crash with a real
response. Cause: the toggle route's redirect (302) response itself was
never the problem -- gunicorn's graceful SIGTERM handling means that
completes fine -- the problem is the *browser's own automatic follow* of
that redirect, a brand-new request with no timing guarantee at all
relative to `systemctl restart`, which briefly leaves nothing listening
on the port at all while it stops the old process and starts a new one.
If the redirect-follow request happened to land in that ~1s gap, Traefik
had no backend to proxy to. Fixed with `_restart_admin_service_deferred()`
-- `sh -c "sleep 2 && sudo systemctl restart vhsp-admin.service"` as a
detached child (no new sudo grant needed: the sleep runs as plain
`astjohn`, only the already-granted `systemctl` call inside needs
privilege) -- gives the redirect-follow request time to land on the
still-alive old worker instead, showing stale toggle state for a couple
seconds rather than a hard failure, consistent with the flash message's
own "reload in a few seconds" wording. Verified against the real public
HTTPS path, not just the test client: triggered a real toggle, hit
`https://vhsp2.dvce.us/account/api-tokens` ~0.3s later (well inside the
old immediate-restart's failure window) and got a clean `200`, not a
`502`, confirming the backend stayed reachable throughout the deferred
window; confirmed the restart still completed correctly a few seconds
later with the new state applied.

### One shared token mechanism, two front-ends

`vhsp_ctl/api_auth.py` is the framework-agnostic piece both
`vhsp_ctl/api.py` (a Flask Blueprint -- the first one in this codebase;
`web.py` is otherwise one flat ~2200-line module, split out here given
this feature's size and its genuinely different auth model) and
`vhsp_ctl/mcp_server.py` (a separate process, see below) import, same
"CLI and web.py both call the same provisioner.py functions
independently" pattern this codebase already uses everywhere else.
Tokens: `secrets.token_urlsafe(32)` generated, only a
`generate_password_hash` digest ever persisted, shown exactly once at
mint time -- identical idiom to every other generated credential here
(`auth.py`'s operator passwords, every `reset_tenant_*` function).

**Minting is the actual 2FA enforcement point.** A new
`/account/api-tokens` page is `@require_auth @require_2fa` (the
existing decorator, unmodified) -- resolving architecture.md's own open
question ("most likely a token mintable only from an
already-2FA-authenticated session") concretely rather than inventing a
new mechanism. Once minted, the token **is** the credential for every
subsequent API/MCP call, uniformly -- no per-request 2FA challenge,
since that isn't a natural fit for API calls. Removing an operator
doesn't cascade-delete their tokens automatically (`api_tokens.json` and
`operators.json` are separate stores, same as `totp_secrets.json`
already is) -- `api_auth.validate_token` checks
`auth.operator_exists(username)` on every call, not just the token
hash, so a removed operator's old tokens stop working immediately
rather than granting access forever. Found and fixed during
implementation, not part of the original design.

### v1 scope: read + lifecycle + backups, not the full operator catalog

Both the REST API and the MCP server expose the identical operation set
-- `list_tenants`, `get_tenant`, `create_tenant`, `destroy_tenant`,
`get_tenant_usage`, `list_tenant_backups`, `create_tenant_backup`,
`restore_tenant_backup`, `verify_audit`, `get_fail2ban_log` -- kept in
sync by construction (both call the same `provisioner.py`/`backup.py`/
`registry.py`/`audit.py` functions directly, no duplicated logic).
Deliberately excluded from v1: every secret-*revealing* incident-response
reset (`reset_tenant_db_password`, `reset_tenant_all_passwords`,
`reset_tenant_panel_access`, `reset_tenant_mailbox_passwords`,
`clear_tenant_webauthn_keys`, `set_tenant_admin_password`) -- real,
valuable operations, but high-blast-radius and plaintext-secret-
returning, deserving their own pass once this token model has been live
and proven. Also excluded: `secrets rotate` (its unenforced "stop the
services first" precondition has no safe API equivalent yet) and
scheduler-only entry points that aren't real interactive operator
actions today.

**Secrets redaction, stricter than the web UI itself.** `GET
/tenants/{domain}` (and the `get_tenant`/`create_tenant`/etc. MCP tools)
omit `db_password`/`db_root_password`/`mail_password`/
`tenant_admin_password` entirely -- no reveal escape hatch in this pass.
`registry.tenant_to_dict(tenant, include_secrets=False)` is the one
helper every handler calls rather than each remembering to redact by
hand. Deliberately stricter than the web UI (which already shows these
to any authenticated operator on the tenant detail page): a bearer
token is a meaningfully riskier thing to leak into a script, a log
line, or shell history than a session cookie tied to one browser.

### Why MCP is a genuinely separate process

The maintained Python MCP SDKs (`fastmcp`, and the official `mcp`
package) are ASGI/Starlette-based; `vhsp-admin.service` runs
gunicorn/Flask/WSGI. There's no clean way to mount one inside the other
without a translation shim that would itself be new, unproven
infrastructure -- so `vhsp_ctl/mcp_server.py` runs as its own process,
using the exact "bare host process + its own systemd unit
(`deploy/vhsp-mcp.service`) + its own Traefik dynamic route" pattern
`vhsp-admin.service` itself already established, not new architecture.
Auth is `ApiTokenVerifier`, a `fastmcp.server.auth.TokenVerifier`
subclass wrapping the exact same `api_auth.validate_token` the REST API
uses -- one token mechanism, two front-ends, verified via direct
`inspect`/`help()` against the actually-installed `fastmcp` package
before writing this rather than assumed from possibly-stale training
knowledge.

### Two real bugs found and fixed during end-to-end verification on vhsp2

Not part of the original design -- both surfaced only once the feature
was exercised against real infrastructure over its real deployed path,
not local unit tests:

1. **The platform-wide session-CSRF `before_request` hook
   (`web.py`'s `_enforce_csrf`) was rejecting every API POST/DELETE
   outright.** It checks the submitted CSRF token against
   `session["csrf_token"]` -- but bearer-token API requests carry no
   session at all, so `expected` is always `None` and the check fails
   unconditionally, 403-ing (in practice, redirecting to `/login` first
   via `require_auth`-shaped logic elsewhere) every `create_tenant`,
   `destroy_tenant`, backup, and restore call. CSRF exists specifically
   to defend session-cookie-authenticated requests from being forged by
   a third-party site; a bearer token in an `Authorization` header is
   immune to CSRF by construction (a forged cross-origin request has no
   way to attach a header value it was never given). Fixed by exempting
   `request.blueprint == "api"` from the check entirely, rather than
   trying to thread a session-based CSRF token through a stateless
   bearer-token client.
2. **gunicorn's default 30-second worker timeout silently killed
   `create_tenant` requests.** Full tenant provisioning (six
   containers -- web/waf/db/sftp/mail/tenant-admin -- plus volumes, DNS
   routing, and a fail2ban jail) is a single synchronous call that took
   ~33-90s in real testing on vhsp2. Without a longer timeout, gunicorn
   SIGKILLs the worker mid-request once it exceeds 30s; the HTTP client
   gets a bare 500 with no body, but the underlying `provisioner.create_tenant()`
   call keeps running to completion in the background regardless (Docker
   calls aren't cancelled just because the process that issued them is
   about to die) -- confirmed directly: a "failed" create left a fully
   healthy, registry-active tenant behind. This is a pre-existing bug in
   the web UI's own "New tenant" form too, not something the API
   introduced -- fixed platform-wide by adding `--timeout 180` to
   gunicorn's `ExecStart` in `deploy/vhsp-admin.service`.

### Verified end-to-end on vhsp2, against real infrastructure

A real operator token minted from a real 2FA-authenticated session
(`apitest`, a disposable test operator, TOTP-enrolled for the test);
every REST endpoint exercised with a real `curl -H "Authorization:
Bearer <token>"` over real HTTPS, including a real disposable-tenant
create → backup create → destroy round trip (`apiverify2.vhsp2.dvce.us`)
with containers confirmed gone from `docker ps -a` afterward and
secrets confirmed absent from every tenant-shaped JSON response; `GET
/api/v1/openapi.json` and an unauthenticated `GET /api/v1/tenants`
(confirmed `401`, not a crash); Swagger UI loading at `/api/v1/docs`
over the real public path. MCP verified with a real `fastmcp.Client`
(`StreamableHttpTransport`) against `https://vhsp2.dvce.us/mcp` --
`tools/list` returning the same 10-tool set the REST API exposes,
`verify_audit`/`list_tenants` tool calls, and a real disposable-tenant
create/destroy round trip (`mcpverify.vhsp2.dvce.us`) with no gunicorn-
style timeout risk (MCP is its own process, not behind gunicorn at
all). `vhsp audit verify` confirmed the hash chain stayed intact
throughout (117 → 119 entries) and every action taken through either
surface was attributed to the real operator (`api:apitest` /
`mcp:apitest`), not a generic actor. Token revocation confirmed to take
effect immediately (a revoked token gets a real `401` on its very next
call). The disposable `apitest` operator and its tokens were removed
after verification -- nothing test-related was left behind on the live
deployment.

A router-priority bug surfaced while wiring up the MCP Traefik route,
not in application code: Traefik auto-computes a router's priority from
its rule's string length when none is set explicitly, and
`vhsp-admin`'s plain `Host(...)` rule computes to roughly 21 -- higher
than an initially-tried explicit `priority: 10` for the new
`PathPrefix`-based `vhsp-mcp` router, so all `/mcp` traffic was silently
winning against the *shorter* explicit-priority rule and landing on the
admin UI instead (visible as gunicorn issuing a redirect to `/login`
for what should have been an MCP JSON-RPC response). Fixed by raising
the explicit priority to `100`; see `DEPLOYMENT.md`'s "Operator API +
MCP" step for the exact router config and how to check both routers'
resolved priorities via Traefik's own API.

## Tenant API + MCP

Same idea as the operator surface above, one layer down: programmatic/
AI-agent access to a *tenant's own* self-service operations (mailboxes,
PHP function toggles, redirects, backups, and the rest of what their
panel already exposes), not operator access. Off by default, gated by
two independent layers of consent -- an operator must explicitly allow
a given tenant, and that tenant must then separately turn it on
themselves -- described in full below.

### Architecture: one shared process, not per-tenant infrastructure

`architecture.md`'s original framing said this should stay "local to
each tenant's own container, not a new path into the shared control
plane." Two real technical obstacles made that impractical: tenant-admin
containers have zero Docker/sudo access by design (no way to restart
themselves or provision anything), and `fastmcp` is ASGI while that
container only runs WSGI/gunicorn -- true per-tenant MCP would have
needed a process supervisor added to the Docker image, a new per-tenant
port, and a way to create a Traefik route for a container that has no
way to trigger anything on the operator side when a tenant flips their
own toggle.

Resolved instead by reusing the *same* shared `vhsp_ctl/api.py`
(`/api/v1/self/*`, a new scope on the existing Blueprint) and
`vhsp_ctl/mcp_server.py` (new `self_*` tools, same process) the operator
surface already uses -- no new container, port, firewall rule, or
Traefik route. What keeps this safe is a genuinely separate token
namespace: `vhsp_ctl/tenant_api_auth.py` validates tokens minted by each
tenant's own `images/tenant-admin/app.py` (never the operator's
`api_auth.py` store), read directly from that tenant's own
`{phpconf_host_path}/api_tokens.json` by host path -- the same
"operator process already touches every tenant's self-service state
directly, without going through that tenant's own container" pattern
`toggles.py` already established for the web UI's own tenant-management
routes. A token is prefixed with its owning tenant's slug
(`f"{slug}.{secrets.token_urlsafe(32)}"`) so validation goes straight to
that one tenant's own file rather than scanning every tenant's tokens on
every request. No `/self/*` route or `self_*` tool ever accepts a domain
parameter -- the tenant is always resolved entirely from the token
itself, so a tenant token can never be used to address a different
tenant's data even by a caller's mistake.

### Two-layer permission model, both defaulting off

One new marker file per tenant, `{phpconf_host_path}/.vhsp-platform-access.json`,
shared and read by both sides but written by only one side each:

```json
{"api_allowed": false, "mcp_allowed": false, "api_enabled": false, "mcp_enabled": false}
```

`api_allowed`/`mcp_allowed` (**Layer 1**) are operator-only, set from a
new "API & MCP access" card on that tenant's own detail page
(`vhsp_ctl/provisioner.py`'s `set_tenant_api_allowed`/
`set_tenant_mcp_allowed`, mirroring `set_tenant_maintenance_mode`'s
exact marker-file shape). `api_enabled`/`mcp_enabled` (**Layer 2**) are
tenant-only, set from a new "API & MCP access" page in
`images/tenant-admin/app.py` (owner + 2FA required, same tier as that
panel's Files/Database pages) -- which re-checks Layer 1 server-side
before honoring any enable, never trusting that the UI simply hid the
control.

**Every actual call re-checks both flags live**, on every single
request/tool-call, not at any process-startup or Blueprint-registration
decision point -- there isn't one here, unlike the operator toggle's own
three-bug restart history (`README.md`'s "Operator API + MCP" section
above). An operator revoking Layer 1 takes effect on that tenant's very
next call; there's nothing to restart, nothing that can go stale.
Verified directly: disallowed a live tenant's REST API access mid-session
and confirmed the very next call 403'd immediately, with Layer 2
(`api_enabled`) provably untouched by that change.

### v1 scope, deliberately conservative

Mirrors the exact functions `web.py`'s own operator-side tenant routes
already call through `toggles.py`: overview/usage, PHP function toggles,
404 handling, password protection, error pages, redirects, no-exec
dirs, IP restrictions, mailbox management (owner-only for reset/delete,
matching the existing web-UI gating), backups against the tenant's own
operator-destination snapshots, logs. **Excluded from v1**, same posture
the operator API's own v1 used for its own excluded actions: Files
(direct webroot read/write) and Database (raw SQL console) -- the two
highest-trust actions even inside a tenant's own web UI -- and Team
management. Restoring a backup via a tenant token is always in-place,
same domain only; unlike the operator-level restore tool, there's no
`target_domain` option, so a tenant token can never be used to create or
overwrite a different tenant.

### A real privilege-escalation bug, found and fixed during this feature's own verification

Not part of the original design -- caught only because verification
included a real, adversarial cross-scope check rather than just testing
the happy path. `vhsp_ctl/api.py`'s REST routes were safe by
construction: `require_api_token` (operator) and the new
`require_tenant_api_token` (tenant) are two separate decorators backed
by two separate validation functions, so a tenant token simply fails
operator token validation outright and never reaches an operator route.

MCP's single shared `ApiTokenVerifier` doesn't have that structural
separation -- one token namespace check, with `scopes` (`["operator"]`
or `["tenant"]`) distinguishing kind afterward. The new tenant-scoped
tools were correctly built to reject operator tokens
(`_require_tenant_access()` checking `"tenant" not in scopes`) -- but
the *existing* operator tools were never updated with the complementary
check, meaning a valid tenant token, once authenticated at the transport
level, could call `list_tenants`, and -- confirmed directly, this wasn't
theoretical -- `destroy_tenant` on an *arbitrary other tenant*. A full
privilege escalation from "this tenant's own self-service" to
"cross-tenant control," live on the deployment for the short window
between deploying the tenant-scoped tools and this fix.

Fixed with the mirror-image check, `_require_operator_access()`
(`"operator" not in access_token.scopes`), added to all 10 existing
operator tools. Verified by reproducing the exact failure directly
(a real tenant token calling `list_tenants` and `destroy_tenant`, both
now correctly rejected with "this tool requires an operator token, not
a tenant token") and confirming zero regression on the operator side (a
real operator token still listing tenants normally, and now correctly
rejected from calling `self_overview`).

### Verified end-to-end on vhsp2, against real infrastructure

Allowed a real live tenant (`testing.bigchimp.org`) for both surfaces
from the operator side, enabled both from that tenant's own panel,
minted a real token from inside that tenant's own container. Exercised
real REST calls (`GET /api/v1/self`, `GET /api/v1/self/mailboxes`)
returning that tenant's actual live data. Confirmed bidirectional
isolation with real tokens in both directions: the tenant token 401's
against every operator-only REST route (`/api/v1/tenants`,
`/api/v1/audit/verify`), and a real operator token 401's against
`/api/v1/self`. Confirmed the same isolation over MCP with a real
`fastmcp` client, including the privilege-escalation bug above (found
*during* this exact pass) and its fix. Confirmed live Layer-1 revocation
immediately blocks a tenant's calls without touching Layer 2. Cleaned up
completely afterward -- both tokens revoked, all four flags back to
their original `false`, confirmed via `vhsp audit verify` (chain intact,
157 entries) and by re-reading the marker file directly.
