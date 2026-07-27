# Deploying vhsp to a single-public-IP host

This is the step-by-step install/setup process for the topology
`architecture.md`'s "Single public IP on the target host" section
describes: a standalone host with **one public IP and no separate
management network** -- vhsp's own local Traefik is the only
routing/TLS layer end to end, and admin-UI access control comes
entirely from application-layer auth (password + a second factor --
WebAuthn and/or TOTP), not network position.

This is distinct from the original two-network dev VM setup (a separate
`vhsp-mgmt` interface, an upstream swarm Traefik doing cert issuance) --
don't mix the two guides. Everything below was carried out and verified
end to end on a real host (a $6/mo DigitalOcean droplet, `vhsp2.dvce.us`,
206.189.190.194, Ubuntu 24.04+/26.04, ~1GB RAM) as the first real test of
this topology.

## Prerequisites

**Hardware/hosting:**
- A single public IPv4 (and optionally IPv6). No NAT/firewall is assumed
  in front of the host -- this guide sets up `ufw` itself, since nothing
  else will.
- At least ~1GB RAM. A budget droplet this small has **no swap by
  default** -- add one (see "Swap" below) or expect OOM kills once more
  than a tenant or two is running.
- Enough disk for Docker images/tenant data -- 20GB+ is comfortable for
  a handful of tenants.

**DNS**, decided *before* provisioning anything:
- The host's own hostname (e.g. `vhsp2.dvce.us`) needs a real A record
  pointing at the host -- this becomes both the operator admin UI's
  hostname and (by default) the mail gateway's HELO/`myhostname`
  identity.
- Every tenant domain needs its own A records once created (the
  platform generates the suggested set -- see "DNS records" below); a
  wildcard on a *parent* domain does not help a specific tenant
  hostname and can actively mislead you if it happens to point
  somewhere else entirely -- check with `dig` before assuming a fresh
  subdomain "just works".
- Ideally, set reverse DNS (PTR) for the host's IP to match its
  hostname too (mail deliverability) -- many hosts, including
  DigitalOcean, do this automatically from the droplet's own hostname;
  verify with `dig -x <ip>` rather than assuming.

**OS packages** (apt-based; adjust for other distros):
```
sudo apt-get install -y age ufw ca-certificates curl rsync python3-venv python3-pip
```
`age`/`age-keygen` are for the backup feature's encryption keys, not
optional if backups will ever be configured.

**Docker Engine** -- install from Docker's own apt repo, not the distro's
bundled package (too old/missing compose plugin). If the host's release
codename isn't yet listed at `download.docker.com/linux/ubuntu/dists/`,
substitute the nearest older LTS codename; the packages themselves are
compatible across adjacent releases.
```
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

## 1. Create the operating user

Don't run the control plane as root day-to-day. The provisioner shells
out to `sudo` itself for mount-hardening (`noexec`/`nosuid`/`nodev`
bind remounts, `/etc/fstab` edits, and tenant-directory teardown) --
so this user needs *some* sudo access, but **not** a blanket grant. A
blanket `NOPASSWD:ALL` here would mean any RCE in `vhsp-admin.service`
(which runs as this user, internet-facing) is equivalent to root,
which quietly defeats the Docker-socket-proxy scoping done elsewhere
in this setup.

Instead, sudo is scoped to exactly two root-owned wrapper scripts
(`deploy/vhsp-harden-hostdir` / `deploy/vhsp-remove-hostdir`) that do
their own argument validation internally -- sudoers itself can't
safely wildcard the tenant-specific paths these operate on (modern
`sudo` refuses wildcards in command arguments), so the validation
lives in the scripts instead, which is the standard pattern for this
situation. Install the scripts first, then the sudoers grant:
```
sudo adduser --disabled-password --gecos "" astjohn
sudo usermod -aG docker astjohn   # removed again in step 6, once the docker-socket-proxy is up
sudo install -o root -g root -m 0755 deploy/vhsp-harden-hostdir deploy/vhsp-remove-hostdir /usr/local/sbin/
sudo cp deploy/vhsp-sudoers /etc/sudoers.d/astjohn
sudo chmod 440 /etc/sudoers.d/astjohn
sudo visudo -cf /etc/sudoers.d/astjohn   # verify before trusting it -- ALWAYS do this for sudoers.d edits
```
If `TENANTS_DIR` isn't the default `/srv/vhsp/tenants` on this
deployment (i.e. `VHSP_STATE_DIR` is overridden), edit the
`TENANTS_DIR=` line in both `deploy/vhsp-harden-hostdir` and
`deploy/vhsp-remove-hostdir` to match before installing them.

Copy your own `authorized_keys` in so key-based SSH still works as this
user, then do everything from here on as that user, not root.

## 2. Firewall

Docker's own iptables rules for **published container ports bypass
ufw's INPUT-chain filtering entirely** -- a real, easy-to-miss gotcha,
not specific to this deployment. Decide the full port list up front:
```
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp        # SSH
sudo ufw allow 80/tcp        # ACME HTTP-01 challenge
sudo ufw allow 443/tcp       # everything web/tenant-admin/webmail
sudo ufw allow 993/tcp       # IMAPS (SNI-routed per tenant)
sudo ufw allow 465/tcp       # SMTPS (SNI-routed per tenant)
sudo ufw allow 25/tcp        # inbound SMTP gateway
sudo ufw allow 2200:2299/tcp # per-tenant SFTP
sudo ufw --force enable
```
Anything published by Docker that *isn't* in this list (e.g. Traefik's
own dashboard, see below) must be bound to `127.0.0.1` in its own
`ports:` mapping -- ufw alone will not stop it.

## 3. Swap (small hosts)

A ~1GB host with zero swap risks OOM kills as tenants accumulate:
```
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab
```

## 4. Get the repo onto the host, build images, install the CLI

This repo isn't git-hosted -- `rsync` a local checkout over:
```
rsync -az --delete --exclude '.venv' --exclude '__pycache__' --exclude '*.egg-info' \
  ./control-plane/ astjohn@<host>:/home/astjohn/vhsp-control-plane/
```
Then, on the host:
```
cd ~/vhsp-control-plane
docker build -t vhsp-web:latest images/web
docker build -t vhsp-mail:latest images/mail
docker build -t vhsp-mailgw:latest images/mailgw
docker build -t vhsp-tenant-admin:latest images/tenant-admin

python3 -m venv .venv
# requirements-lock.txt pins exact versions verified working on a real
# deployment -- pyproject.toml's own `>=` floors would otherwise let a
# fresh install silently pull newer, untested transitive dependencies.
.venv/bin/pip install -r requirements-lock.txt
.venv/bin/pip install -e .

sudo mkdir -p /srv/vhsp && sudo chown "$USER:$USER" /srv/vhsp
docker network create traefik
```

## 5. Traefik: the sole TLS/routing layer

Unlike the two-network dev setup (which has an *upstream* Traefik doing
TLS termination), this host's local Traefik has to obtain and terminate
real certificates itself. The trick that avoids touching any
control-plane Python code: every existing Traefik label in
`provisioner.py` already says `entrypoints=web` (tenant web containers,
mail's admin router, tenant-admin's public router) -- so make **`web`
itself the TLS-terminating entrypoint on `:443`**, with a *separate*
entrypoint used only for the ACME HTTP-01 challenge on `:80`.

`~/traefik/docker-compose.yml`:
```yaml
services:
  traefik:
    image: traefik:latest
    container_name: traefik
    restart: unless-stopped
    extra_hosts:
      - "host.docker.internal:host-gateway"   # unreliable, see note below
    command:
      - --api.dashboard=true
      - --api.insecure=true
      - --providers.docker=true
      - --providers.docker.exposedbydefault=false
      - --providers.docker.network=traefik
      - --providers.file.directory=/etc/traefik/dynamic
      - --providers.file.watch=true
      - --entrypoints.acme-http.address=:80
      - --entrypoints.web.address=:443
      - --entrypoints.web.http.tls=true
      - --entrypoints.web.http.tls.certresolver=letsencrypt
      - --entrypoints.imaps.address=:993
      - --entrypoints.smtps.address=:465
      - --certificatesresolvers.letsencrypt.acme.email=<your-email>
      - --certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json
      - --certificatesresolvers.letsencrypt.acme.httpchallenge=true
      - --certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=acme-http
    ports:
      - "80:80"
      - "443:443"
      - "127.0.0.1:8080:8080"   # dashboard: loopback ONLY, see step 2
      - "993:993"
      - "465:465"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ~/traefik/dynamic:/etc/traefik/dynamic:ro
      - ~/traefik/letsencrypt:/letsencrypt
    networks:
      - traefik
networks:
  traefik:
    external: true
```
```
mkdir -p ~/traefik/dynamic ~/traefik/letsencrypt
cd ~/traefik && docker compose up -d
```

**`host.docker.internal` via `extra_hosts: host-gateway` can resolve to
the wrong bridge** if Traefik only joins a *custom* network (here,
`traefik`) rather than the default bridge -- verified directly, it
resolved to the default bridge's gateway (typically `172.17.0.1`)
instead of the `traefik` network's own gateway. Get the real one and
use it explicitly instead of trusting the magic hostname:
```
docker network inspect traefik --format '{{json .IPAM.Config}}'
```

## 6. Operator admin UI

A bare systemd process (not a container), so it needs its own Traefik
route via the file provider -- `~/traefik/dynamic/vhsp-admin.yml`
(substitute the real gateway IP from step 5 and the host's own
hostname):
```yaml
http:
  routers:
    vhsp-admin:
      rule: "Host(`<host-hostname>`)"
      entryPoints: [web]
      service: vhsp-admin
  services:
    vhsp-admin:
      loadBalancer:
        servers:
          - url: "http://<traefik-network-gateway-ip>:8000"
```
Generate the operator credential:
```
cd ~/vhsp-control-plane
VHSP_STATE_DIR=/srv/vhsp .venv/bin/vhsp admin init   # shown once, save it now
```
`/etc/systemd/system/vhsp-admin.service` (copy `deploy/vhsp-admin.service`
as a starting point, then override these -- see each variable's comment
in `vhsp_ctl/config.py` for why):
```ini
Environment=VHSP_ADMIN_BIND_HOST=0.0.0.0
Environment=VHSP_ADMIN_BIND_PORT=8000
Environment=VHSP_ADMIN_TRUST_PROXY=1
Environment=VHSP_ADMIN_RP_ID=<host-hostname>
Environment=VHSP_PLATFORM_PUBLIC_IP=<host-public-ip>
Environment=VHSP_MAILGW_HOSTNAME=<host-hostname>
Environment=VHSP_TENANT_ADMIN_MGMTWEB_EXISTS=0
```
Then a *non-Docker* firewall rule scoped to just the `traefik` network's
subnet (from step 5's `docker network inspect`) -- `0.0.0.0` bind is
required (a container can't reach a loopback-only host process at all),
but this rule keeps it off the public interface:
```
sudo ufw allow from <traefik-network-subnet> to any port 8000 proto tcp
```
```
sudo systemctl daemon-reload
sudo systemctl enable --now vhsp-admin.service
```
Each variable matters and has a real failure mode if skipped:
- `VHSP_ADMIN_RP_ID` -- WebAuthn is tied to one fixed origin; wrong
  value means registration/login silently fails with an origin
  mismatch.
- `VHSP_PLATFORM_PUBLIC_IP` -- unset, and the `/dns` suggested-records
  feature refuses to run at all (deliberately, rather than guess wrong).
- `VHSP_MAILGW_HOSTNAME` -- unset defaults to `mail-gateway.vhsp.local`,
  not a real hostname; mail deliverability needs a real one here,
  matching forward DNS/PTR.
- `VHSP_TENANT_ADMIN_MGMTWEB_EXISTS=0` -- this host has no separate
  management network/Traefik entrypoint at all; without this flag the
  CLI and admin UI both advertise a "mgmt-network-only" fallback path
  that doesn't actually work here.

## 7. Backup timers

Easy to forget since nothing fails loudly if they're missing -- install
them even before a real backup destination is configured (`vhsp backup
run-all` safely no-ops with a clear message until it is):
```
sudo cp ~/vhsp-control-plane/deploy/vhsp-backup*.service ~/vhsp-control-plane/deploy/vhsp-backup*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vhsp-backup.timer vhsp-backup-reconcile.timer
```
Configure the actual destination later with `vhsp backup init` plus
`VHSP_BACKUP_SFTP_*` (see `control-plane/README.md`'s "Backup / restore"
section) -- out of scope for initial bring-up.

## 8. Verify

```
# operator admin UI, real cert, login works
curl -sv https://<host-hostname>/login 2>&1 | grep -E "subject=|issuer=|Verify"

# create a throwaway tenant on a domain you've already pointed at this host
VHSP_STATE_DIR=/srv/vhsp .venv/bin/vhsp tenant create <test-domain>

# confirm real TLS + PHP on the tenant site
curl -s https://<test-domain>/  # after dropping an index.php via the host path
                                 # (the web container's own webroot mount is read-only;
                                 #  write to /srv/vhsp/tenants/<slug>/webroot/ directly, or use SFTP)

# IMAPS/SMTPS SNI passthrough (self-signed cert inside the mail container, by design)
openssl s_client -connect <host-public-ip>:993 -servername mail.<test-domain>

# suggested DNS records include admin.<domain> now (fixed -- previously missing)
.venv/bin/vhsp dns records <test-domain>
```
Tear the test tenant down once satisfied: `vhsp tenant destroy <test-domain>`.

## 9. fail2ban (intrusion prevention)

Zero-account, zero-external-service alternative to CrowdSec -- see the
control-plane README's fail2ban section for the full design (why, and
the operator/tenant allowlist mechanism). Real regression caught during
initial rollout, worth knowing before installing elsewhere: this OS's
actual firewall backend is nftables, and fail2ban's `iptables-multiport`
action's `actionstart` silently creates no chain at all here (no error
logged) -- use `banaction = nftables-multiport` instead, confirmed
working via a real ban/unban test against a safe RFC 5737 test-only IP
(`192.0.2.1`, never a real client) rather than anything live.
```
sudo apt-get install -y fail2ban
sudo install -o root -g root -m 0755 deploy/vhsp-fail2ban-allowlist-check /usr/local/sbin/
sudo cp deploy/fail2ban/jail.local /etc/fail2ban/jail.local
sudo cp deploy/fail2ban/filter.d/*.conf /etc/fail2ban/filter.d/
sudo fail2ban-client -t                 # validate config before trusting it
sudo systemctl enable --now fail2ban
```
**Before enabling**, check for recent failed-login activity near your
own current SSH session in `/var/log/auth.log` (`tail -50 | grep -E
"Failed password|Invalid user"`) -- starting fresh is safe if there's
none, since fail2ban only considers the `findtime` window (10 minutes
by default here), not historical log entries from hours/days earlier.

**Verify** (dry-run only, no live-fire ban testing against a real
connection):
```
sudo fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf   # confirms the filter matches real lines
sudo fail2ban-client status sshd                                          # confirms the jail loaded and is watching
sudo fail2ban-client set sshd banip 192.0.2.1                            # safe: RFC 5737, never a real client
sudo fail2ban-client status sshd                                          # confirms it's actually in the banned list
sudo fail2ban-client set sshd unbanip 192.0.2.1                          # confirms unban works too
```
`jail.local` also enables `[vhsp-admin-login]` (watches `/srv/vhsp/audit.log`
for failed operator logins -- needs `vhsp_ctl/web.py`'s `ip`-capturing
change already deployed as part of the normal control-plane rsync, not
a separate step here). Same verification shape:
`fail2ban-regex /srv/vhsp/audit.log /etc/fail2ban/filter.d/vhsp-admin-login.conf`,
then `fail2ban-client status vhsp-admin-login`. This jail only watches
forward from whenever it (re)loads, unlike the journal-backed `sshd`
jail -- trigger one real failed login against the admin UI afterward if
you want to see it actually catch something live.

`jail.local` also enables `[vhsp-tenant-admin-login]`, wildcarded
across every tenant (`/srv/vhsp/tenants/*/phpconf/login_attempts.log`).
**A wildcarded `logpath` matching zero files fails `fail2ban-client -t`
outright** -- before enabling on a deployment with no tenants yet
(or before `images/tenant-admin:latest` has been rebuilt with the
version of `app.py` that touches this file into existence on
container start), create the permanent placeholder once so the glob
always has something to match:
```
sudo mkdir -p /srv/vhsp/tenants/_f2b-placeholder/phpconf
sudo touch /srv/vhsp/tenants/_f2b-placeholder/phpconf/login_attempts.log
```
(the `_f2b-placeholder` name is deliberate -- `slugify()` never produces
underscores, so this can never collide with a real tenant). Real
tenants' own `login_attempts.log` files are created automatically the
next time their tenant-admin container starts. This jail's log format
depends on `images/tenant-admin/app.py` having a working `ProxyFix`
setup -- confirmed necessary the hard way during initial rollout (see
the control-plane README's fail2ban section for the real bug this
caught: without it, every entry recorded Traefik's own IP, not the real
client). If rebuilding `vhsp-tenant-admin:latest` from an older
checkout, recreate every existing tenant's container afterward
(`recreate_tenant_admin.py <domain>` per tenant) so they pick up both
fixes.

Per-tenant SFTP jails (genuinely isolated -- distinct ports per tenant,
unlike the two shared HTTP jails above, which are platform-wide
regardless of allowlisting) are generated/torn down automatically by
`provisioner.create_tenant()`/`destroy_tenant()`; nothing manual is
needed per tenant. Install the wrapper script and its sudoers grant
once per host:
```
sudo install -o root -g root -m 0755 deploy/vhsp-fail2ban-tenant-jail /usr/local/sbin/
# stage, validate, then swap in deploy/vhsp-sudoers (adds the
# VHSP_FAIL2BAN_TENANT Cmnd_Alias) -- same visudo -cf discipline as
# every other sudoers change in this file, never edit the live file
# directly:
sudo cp deploy/vhsp-sudoers /etc/sudoers.d/astjohn.new
sudo visudo -cf /etc/sudoers.d/astjohn.new
sudo mv /etc/sudoers.d/astjohn.new /etc/sudoers.d/astjohn
```
Any tenants that existed before this rolled out won't have a jail
until backfilled once, manually:
```
sudo /usr/local/sbin/vhsp-fail2ban-tenant-jail <slug> <ssh_port> install
```
(`ssh_port` is that tenant's own value from `tenant.ssh_port`, visible
in the operator UI or `vhsp tenant list`.)

**Real regression worth knowing before relying on this filter
elsewhere**: `deploy/fail2ban/filter.d/vhsp-tenant-sftp.conf` does
*not* set `[Init] datepattern` (an earlier `= {NONE}` version looked
correct under offline `fail2ban-regex` testing but silently dropped
every match in the *live*, pyinotify-watched jail -- see the
control-plane README's fail2ban section for the full diagnosis). If a
future edit reintroduces an explicit `datepattern` override on an
undated log, re-verify against a genuinely live jail (append a real
line, check `fail2ban-client status <jail>` actually increments), not
just `fail2ban-regex` -- the two did not agree here.

**Verify**, same safe-IP discipline as every other jail:
```
sudo fail2ban-client status vhsp-sftp-<slug>                              # confirms it's loaded and watching the right port/logpath
sudo fail2ban-client set vhsp-sftp-<slug> banip 192.0.2.1                 # safe: RFC 5737, never a real client
sudo fail2ban-client status vhsp-sftp-<slug>                              # confirms it's actually in the banned list
sudo fail2ban-client set vhsp-sftp-<slug> unbanip 192.0.2.1               # confirms unban works too
```

`vhsp-fail2ban-allowlist-check` and `vhsp-fail2ban-tenant-jail` both
hardcode the `/srv/vhsp` paths they need (they run outside this
codebase's own process -- fail2ban's own root service, or sudo -- so
they can't just import `config.py`), kept in sync with `config.py`'s
`STATE_DIR`/`VHSP_STATE_DIR` by convention, not enforcement. If this
deployment ever sets `VHSP_STATE_DIR` to something other than the
default, reinstall both scripts afterward and run `vhsp doctor` to
confirm they still agree with `config.py`:
```
vhsp doctor
```

## 10. Coraza WAF (OWASP Core Rule Set)

Zero-account, zero-external-service, self-hosted WAF -- see the
control-plane README's "Coraza WAF" section for the full design (why
this is a per-tenant sidecar container and not a Traefik plugin: the
open-source Traefik plugin can't load the real OWASP CRS at all).
Nothing to install on the host itself -- the WAF image is pulled once
and a sidecar container is created automatically per tenant by
`provisioner.create_tenant()`, no separate step needed for new tenants:
```
docker pull ghcr.io/coreruleset/coraza-crs@sha256:8e55eca37e42003a00f4f0d9cd5eac3dc5f9945ec1ffd57f3438346a2db7ebdf
```
(matches `config.py`'s `WAF_IMAGE` default -- only needed explicitly if
this deployment is offline-provisioned or you want to warm the cache
before the first `vhsp tenant create`; a normal `docker run` pulls it
automatically otherwise.)

Ships in `DetectionOnly` mode by default (`VHSP_WAF_ENGINE_MODE`,
unset = `DetectionOnly`) -- logs would-be blocks without actually
blocking traffic. Don't set this to `On` platform-wide without a real
observation period against real tenant traffic first; OWASP CRS is
known to false-positive against rich HTML/form-post/file-upload
traffic, and a WAF false positive in blocking mode has no
auto-recovery the way a fail2ban ban does.

**Retrofitting tenants that existed before this feature shipped** (no
`waf_container` on record) is a *separate, deliberate* step, not
automatic -- the cutover isn't atomic across two containers. Before
ever running this against real traffic, the exact overlap window was
characterized with disposable throwaway containers sharing an
identical router/service name (matching how the old web container and
new WAF container both do): confirmed Traefik round-robins between
both rather than erroring or dropping the router, so the real cost is
zero dropped requests, just a few seconds of some requests skipping WAF
inspection. Already applied for real to both tenants that predated this
feature (`smoketest.vhsp2.dvce.us`, `testing.bigchimp.org`) -- these
steps are for any *future* tenant found without a `waf_container` (e.g.
one restored from an old backup). Per tenant, in this exact order:
```
sudo -u astjohn env VHSP_DOCKER_HOST=tcp://127.0.0.1:2375 \
  .venv/bin/python3 recreate_waf.py <domain>
sudo -u astjohn env VHSP_DOCKER_HOST=tcp://127.0.0.1:2375 \
  .venv/bin/python3 recreate_web.py <domain>
```
`recreate_web.py` now refuses to run at all for a tenant with no live
`waf_container` on record, specifically to prevent running these out of
order and dropping that tenant's only public Traefik routing -- run
`recreate_waf.py` first, always.

**Verify** per tenant, same safe-payload discipline as every other
security feature here (real SQLi test string, not a live attack):
```
curl -sk "https://<domain>/?id=1%27%20OR%20%271%27%3D%271"   # in DetectionOnly: 200, logged not blocked
docker logs <tenant>-waf 2>&1 | tail -20                      # confirms a real detection event, not silence
```
To test blocking mode against one tenant only, without touching the
platform-wide default:
```
sudo -u astjohn env VHSP_DOCKER_HOST=tcp://127.0.0.1:2375 VHSP_WAF_ENGINE_MODE=On \
  .venv/bin/python3 recreate_waf.py <domain>
```
then repeat the same SQLi curl and confirm a real `403`, and confirm a
normal request to the same tenant still returns `200`.

**Operator UI log viewers** (`/fail2ban` global page, and a "WAF
(Coraza)" section on each tenant's existing `/tenants/<domain>/logs`
page) need two things this codebase never needed before:

1. `deploy/vhsp-docker-proxy.service` needs `-e LOGS=1` (already in the
   file if deployed from this repo's current version -- if upgrading an
   older install, re-copy the unit file and restart):
   ```
   sudo systemctl daemon-reload
   sudo systemctl restart vhsp-docker-proxy.service
   ```
   Verify before trusting it -- this is the first time this codebase
   has ever called the Docker logs endpoint through the proxy:
   ```
   sudo -u astjohn env VHSP_DOCKER_HOST=tcp://127.0.0.1:2375 .venv/bin/python3 -c \
     "import docker; c=docker.DockerClient(base_url='tcp://127.0.0.1:2375'); \
      print(len(c.containers.get('vhsp-<any-live-tenant-slug>-waf').logs(tail=5)))"
   ```
   should print a real, non-zero byte count, not a permission error.
2. `deploy/vhsp-fail2ban-log-tail` (a new root-owned wrapper script,
   same pattern as `vhsp-fail2ban-tenant-jail`) needs installing, and
   `deploy/vhsp-sudoers` needs redeploying for its new
   `VHSP_FAIL2BAN_LOG` `Cmnd_Alias`:
   ```
   sudo install -o root -g root -m 0755 deploy/vhsp-fail2ban-log-tail /usr/local/sbin/
   sudo cp deploy/vhsp-sudoers /etc/sudoers.d/astjohn.new
   sudo visudo -cf /etc/sudoers.d/astjohn.new
   sudo mv /etc/sudoers.d/astjohn.new /etc/sudoers.d/astjohn
   ```
   Verify: `sudo -u astjohn sudo -n /usr/local/sbin/vhsp-fail2ban-log-tail 5`
   returns real recent fail2ban.log lines.

## 11. Operator API + MCP (optional, opt-in)

Off by default -- skip this section entirely if this deployment doesn't
need programmatic/AI-agent access. See the control-plane README's
"Operator API + MCP" section and architecture.md's "API and MCP access
for operators and tenants" for the full design (why this needs a
separate MCP process, why tokens are 2FA-gated at mint time rather than
per-request, why secrets are redacted more strictly than the web UI).

**Both surfaces are turned on and off from the admin UI itself** (My
account -> API & MCP access, once a second factor is registered) --
there's no env var to hand-edit for routine on/off. What follows here is
the one-time, per-host groundwork that toggle needs already in place;
after that, use the UI.

**gunicorn's default 30s worker timeout is too short for `create_tenant`**
(a single synchronous request provisioning six containers, ~60-90s in
practice) -- without raising it, the worker gets SIGKILLed mid-request,
the caller sees a 500, and the tenant is left half-provisioned-looking
even though the backend call actually finishes. This affects the web
UI's own "New tenant" form too, not just the API, so it's worth doing
even on a deployment that skips the rest of this section:
```
ExecStart=/bin/sh -c 'exec /home/astjohn/vhsp-control-plane/.venv/bin/gunicorn --workers 2 --timeout 180 --bind ${VHSP_ADMIN_BIND_HOST}:${VHSP_ADMIN_BIND_PORT} vhsp_ctl.web:app'
```
(already the default in `deploy/vhsp-admin.service` as of this repo's
current version -- if upgrading an older install, re-copy the unit file
or add `--timeout 180` by hand, then `daemon-reload` + restart).

**The REST API toggle needs one existing sudo grant, already covered by
step 2's `deploy/vhsp-sudoers`** -- `VHSP_RESTART` includes `systemctl
restart vhsp-admin.service`, which is all the toggle needs (the Flask
Blueprint serving `/api/v1/*` is only registered at process startup, so
turning the flag on or off restarts the process to apply it). Nothing
further to install for this half.

**MCP needs its own systemd unit, a firewall rule, and a Traefik route --
the toggle now installs/removes all three itself**, but needs two things
in place first:

1. `deploy/vhsp-mcp.service` present in this deployment's own checkout at
   the path `deploy/vhsp-mcp-toggle` expects (`/home/<user>/vhsp-control-plane/deploy/vhsp-mcp.service`
   by default -- open that wrapper script and update the hardcoded
   `UNIT_SRC` constant if this deployment's checkout lives somewhere
   else, same "hardcoded path constant, kept in sync by convention" note
   every wrapper script under `deploy/` already carries).
2. The two new wrapper scripts and their sudoers grant, installed the
   same way as every other wrapper script here (see step 2's own
   pattern):
   ```
   sudo install -o root -g root -m 0755 deploy/vhsp-mcp-toggle deploy/vhsp-mcp-firewall /usr/local/sbin/
   sudo cp deploy/vhsp-sudoers /etc/sudoers.d/astjohn.new
   sudo visudo -cf /etc/sudoers.d/astjohn.new
   sudo mv /etc/sudoers.d/astjohn.new /etc/sudoers.d/astjohn
   ```
   Verify before trusting it: `sudo -u astjohn sudo -n /usr/local/sbin/vhsp-mcp-toggle`
   should print that script's own usage error (proving sudo let the call
   through), not a password prompt or permission denial.

With both of those in place, use the toggle at
`https://<host-hostname>/account/api-tokens` (2FA required first, same
as minting a token) to turn REST API and MCP on or off independently.
Turning MCP on: installs and starts `vhsp-mcp.service`, opens
`ufw allow from <traefik-network-subnet> to any port 8001 proto tcp`
(the subnet is discovered live via the Docker API, not typed in), and
writes `~/traefik/dynamic/vhsp-mcp.yml` (`Host(...) && PathPrefix(`/mcp`)`,
**explicit `priority: 100`** -- Traefik auto-computes a router's priority
from its rule's string length when none is set, and `vhsp-admin`'s plain
`Host(...)` rule computes to roughly 21, which would silently beat a
lower or unset priority here and route all `/mcp` traffic into the admin
UI instead; this exact bug was hit and fixed once already building this
feature). Turning it off reverses all three completely, not just
stopping the process. Check via Traefik's own API if anything ever seems
misrouted:
```
curl -s http://127.0.0.1:8080/api/http/routers/vhsp-admin@file | python3 -c "import json,sys; print(json.load(sys.stdin)['priority'])"
curl -s http://127.0.0.1:8080/api/http/routers/vhsp-mcp@file | python3 -c "import json,sys; print(json.load(sys.stdin)['priority'])"
```
the second number must be higher than the first.

**Verify**: mint a real token from an already-2FA-authenticated session
on the same page, then:
```
curl -H "Authorization: Bearer <token>" https://<host-hostname>/api/v1/tenants
curl -s -X POST https://<host-hostname>/mcp \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"verify","version":"0"}}}'
```
both should return real data, not a 401 or a redirect to `/login`.
`vhsp audit verify` afterward should show `api:<username>` /
`mcp:<username>` actor entries for whatever was just exercised (plus
`admin.api_enable`/`admin.mcp_enable` entries for the toggle actions
themselves), not a generic actor.

## Known gaps / deliberately out of scope for initial bring-up

- Operator backup destination (`vhsp backup init` + SFTP creds) --
  timers are installed and harmless without it, but no backups actually
  run until configured.
- HTTP-layer request-content inspection (an actual WAF, not just IP
  banning) -- fail2ban (above) covers IP-based banning for
  SSH/SFTP/admin-login abuse; SQLi/XSS/path-traversal-style request
  inspection is Coraza (see step 10 above), **both phases done**: every
  tenant, new or pre-existing, now has a per-tenant Coraza+OWASP-CRS
  sidecar container in `DetectionOnly` mode. **Not yet done**: deciding
  when/whether to flip any tenant to actual blocking mode -- needs a
  real observation period against real traffic first.
- Mail TLS certs are self-signed (Dovecot/Postfix terminate TLS
  themselves for the SNI-passthrough IMAPS/SMTPS ports, not Traefik) --
  expected, not a bug, but worth knowing before a mail client warns
  about it.
