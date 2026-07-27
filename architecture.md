# VHSP — Virtual Hosting Service Platform

Planning notes for a self-hosted, multi-tenant cPanel replacement. Captures the architecture discussed so far. This has since become a working build (`control-plane/`) rather than pure planning — most sections below are implemented; where a section is still aspirational or the build deliberately diverged from it, that's called out inline rather than assumed.

## Motivation

- Evaluating alternatives to cPanel for a multi-tenant hosting product at work (customers self-serve their own web + mail, not just internal company sites).
- Primary driver is **security**, not licensing cost — informed in part by CyberPanel's 2024 unauthenticated RCE / ransomware incident.
- Strong preference for **tenant isolation** beyond the classic shared-daemon model.

## Alternatives considered

| Option | Notes |
|---|---|
| DirectAdmin / Plesk | Commercial, cheaper than cPanel, have cPanel migration tooling. Classic Unix-user isolation (shared Postfix/Dovecot/PHP-FPM host) — not the isolation model we want. |
| Virtualmin / ISPConfig | Mature open source, reseller/package support. ISPConfig can split web/mail/DNS across separate physical servers. Same classic isolation limits. |
| CyberPanel | Flagged as a security risk (2024 RCE/ransomware wave) — not recommended without serious scrutiny. |
| CloudPanel | Container-per-site isolation for web (stronger than classic panels). Mail-hosting support unclear/limited — would need verification. |
| Modoboa | Existing open-source multi-domain mail panel with an API. Useful reference for how much control-plane work is being taken on, but still a shared-daemon model, not per-tenant containers. |

Conclusion: none of the off-the-shelf panels give per-tenant container isolation for both web and mail, so this is being scoped as a custom build.

## High-level architecture

A single Docker host with a front-end control plane that provisions tenant containers on demand (web + mail per tenant). The front-end's job is routing by domain; per-tenant administration lives inside each tenant's own container.

```
                     ┌─────────────────────────┐
   Internet ────────▶│  Traefik (web + TLS-SNI) │───▶ tenant web containers
                     │  Postfix gateway (SMTP:25)───▶ tenant mail containers
                     └─────────────────────────┘
                                  │
                         domain → container
                           routing table
                        (control plane owns this)
```

### Web layer — mostly off-the-shelf

- Traefik's Docker provider auto-discovers new containers via labels — no custom code needed to register a new tenant's site.
- Per-domain ACME/Let's Encrypt certs handled natively via Traefik labels.
- Control plane's job here is just: run the container with the right labels.

### Mail layer — the custom part

Two very different cases depending on whether the protocol exposes the tenant's hostname before authentication:

- **Inbound SMTP (port 25)**: MX records point at one shared address, and the recipient's domain is only revealed inside the `RCPT TO` envelope — there's no TLS SNI to route on. This needs a genuine mail-aware gateway: a front-end Postfix using `transport_maps` keyed by recipient domain, relaying to the correct tenant's backend container. This is the one piece that can't be solved with routing tricks — it's real custom software.
- **IMAP / POP3 / authenticated submission (993/995/587/465)**: clients are configured with a tenant-specific hostname (e.g. `mail.tenant1.com`) rather than relying on a shared MX, so the TLS ClientHello carries SNI at connection time. This means **Traefik's existing TCP router can SNI-route these straight to the correct tenant container**, with no mail-protocol-aware proxy required. Authentication happens entirely inside each tenant's own Postfix/Dovecot.

### Tenant self-service

- Each tenant container ships its own admin page for managing mail users locally.
- Consequence: the front-end gateway never needs a shared user database — only a domain → container routing table (used by the SMTP gateway's transport_maps).

### Getting files onto tenant websites

SSH/SFTP has no SNI equivalent — the hostname isn't revealed until after the TCP connection is already open, so it can't be routed the way HTTPS/IMAPS/submission are.

- **Primary path**: bundle a web-based file manager into the same per-tenant admin container used for mail-user management. Pure HTTPS, routes through Traefik like everything else — no new plumbing. **Implemented** — `images/tenant-admin/app.py`'s `/files`, `/files/edit`, `/files/download` routes (upload/delete/move/edit/download over the webroot), owner-only and gated behind 2FA to encourage adoption.
- **Real SFTP for developer tenants**: give each tenant a **dedicated external SSH port** (e.g. a reserved range like 2200–2299) mapped to their container. Chosen over a single shared SSH gateway specifically to avoid introducing one more common daemon all tenants would depend on — consistent with the "no common env" isolation goal. **Implemented** (`provisioner.py`'s SSH port allocator, `registry.py`'s per-tenant `ssh_port` column) and is currently the *only* way a tenant gets files onto their site.
- **Plain FTP ruled out** — cleartext auth and passive-port/NAT complexity conflict with the security priority.

### Database isolation

Consistent with the rest of the platform, a shared multi-tenant DB engine (one MySQL/Postgres instance, one database per tenant) was ruled out in favor of a **separate DB container per tenant** — the same "no common env" reasoning already applied to mail and SSH.

- **One DB container per tenant**, part of that tenant's own stack alongside its web/mail containers, not a shared engine serving everyone.
- **Private per-tenant network**: the DB container sits on a network reachable only by that tenant's own web/app container — not on the shared network Traefik/the mail gateway use to reach tenant web/mail containers, and not reachable by any other tenant's containers. This refines the earlier "one shared network for simplicity" idea: the shared network is only for what the gateway genuinely needs to reach (web, mail); anything backend-only, like a DB, has no business being on it.
- **Unique credentials per tenant**, generated (and rotatable) by the control plane at provisioning time, injected via env vars/secrets rather than baked into images. **DB rotation implemented** as an operator-only incident-response lever (`provisioner.reset_tenant_db_password`, control-plane README's "Incident response" section) — live `ALTER USER` plus recreating the web/tenant-admin containers to pick up the new value, not self-service and not automatic/scheduled.
- **Per-tenant resource limits** (cgroup CPU/memory) on the DB container — a security/isolation measure but also a noisy-neighbor mitigation, since one tenant's heavy query load can't starve another's separate DB engine.
- Side benefit: since each tenant's DB is its own container, tenants could in principle pick their own engine/version — not a requirement, just a natural side effect of the isolation model.
- Tradeoff, same shape as the mail/SSH decisions: N separate DB engine processes cost more baseline memory/CPU than one shared multi-tenant server. Accepted deliberately, consistent with prioritizing isolation over density.
- Backups: per-tenant DB backups should be covered by the same per-tenant backup strategy already tracked as an open question below, not solved separately.

### Backups per tenant

Implemented (`vhsp_ctl/backup.py`; see the control plane's own README for the CLI/systemd-unit reference). What gets backed up per tenant: the webroot volume, a **logical** DB dump (`mariadb-dump --single-transaction`, not a raw datadir copy — a live copy can be inconsistent or corrupt while the DB is being written to), mail storage (Dovecot maildir), and the `phpconf` volume (mailboxes, quotas, toggles, admin credentials). **Shipped off-host over SFTP** — never left alongside the tenant containers on the same box, so a compromised host doesn't take its own backups down with it — and **encrypted at rest** (see below), namespaced per tenant as `<dest>/<tenant-domain>/<timestamp>.tar[.age]`.

**Two tiers, not one, and not symmetric:**

- **Operator**: every tenant is backed up automatically to one operator-configured SFTP destination, always, with no per-tenant opt-out. This tier alone has to survive the tenant/domain being deleted here entirely, and even work across deployments — restoring a domain that never existed on *this* vhsp instance recreates it from scratch, reusing every credential (DB/mail/tenant-admin passwords) exactly as it was at backup time, on the original SFTP port unless that port's already taken here (falls through to the normal allocator rather than colliding).
- **Tenant**: a tenant can *additionally* configure their own separate SFTP destination — in addition to the operator's copy, never instead of it. Client-side encryption there is optional, with a clear warning in the tenant admin UI if skipped; the operator's own copy is encrypted unconditionally, a hard requirement given what a snapshot contains, not a configurable preference.

**`WebAuthn credentials are never in a backup`, deliberately.** A tenant recreated from nothing comes back password-only with an explicit warning that WebAuthn needs re-registering. Restoring *content* into an already-existing tenant leaves that tenant's current WebAuthn credentials completely untouched — the backup format simply never includes that file either way, so there's no restore-time logic that could get this wrong by forgetting to exclude it.

**Three purpose-specific keypairs, never reused across roles** — SSH transport (authenticates the push to a destination), `age` encryption, and Ed25519 signing (verified via OpenSSH's own `ssh-keygen -Y sign`/`-Y verify` rather than a new signing tool). The operator's three are generated once (`vhsp backup init`), each shown exactly once in that command's own output with a hard warning to copy it to secure offline storage — the same "generated, shown once, never re-displayed" pattern this codebase already uses for the operator/tenant-admin login passwords. Deliberately **not** Docker Swarm secrets (only mountable into Swarm *services*, and tied to that swarm's own raft state — a recoverability trap if this host is ever lost) and **not** systemd-creds (TPM/host-bound, the same trap): plain `0600` root-owned host files instead, consistent with how every other credential here is already kept outside of Docker/systemd's own secret stores. A tenant's own additional destination gets its own SSH transport keypair (only the *public* half is ever shown, for the tenant to install on their destination — the private half never leaves this host) plus an optional `age` keypair, tenant-supplied or generated on request and, if generated, shown once then retained server-side so the schedule and restore-time decryption keep working unattended.

**Mandatory signature verification before any restore, operator- or tenant-triggered, with no weaker path for self-service.** This is the actual anti-tampering control: a compromised destination can hand back a byte-for-byte corrupted or edited snapshot, but it can't produce one that both decrypts correctly *and* verifies against the signing key, which never leaves this host. Tenant self-service restore is allowed specifically *because* this check exists and applies identically regardless of who's restoring — without it, a tenant's own (possibly less-trusted, tenant-controlled) destination would be a route to smuggle tampered content back into their own tenant.

**Scheduling is a systemd `.timer`, not an in-process scheduler thread** — matches `vhsp-admin` already being a standalone systemd unit rather than embedding its own loop. Retention (default 30 snapshots) and interval (default daily; daily/weekly/monthly) are platform-wide defaults, per-tenant overridable, the same "platform default + per-tenant override" shape already used for per-tenant disk quotas.

**Why tenant-configured backup settings need a *second*, host-side timer, not just a UI form:** `images/tenant-admin/app.py` has no access to `docker.sock`, the control plane's registry, or any host-level tooling at all — exactly the same constraint that already shapes the PHP-toggle/nginx-config/mailbox features (self-service stays local to the tenant's own containers, writing a file to a shared volume that something *outside* the container watches and acts on). Backup key generation, `mariadb-dump`, and SFTP push all need host/Docker access no tenant container has or should gain, so tenant-admin's Backups page only ever writes a small request file (desired destination/encryption choice) and touches an on-demand marker on the shared `phpconf` volume; a new host-side reconciler timer (~2 minutes, separate from the daily backup sweep) is what actually reads those and acts on them. A tenant's settings or on-demand-backup request therefore takes effect within about 2 minutes, not instantly — a deliberate, documented tradeoff given the alternative is granting a tenant-facing container host-level access.

### DNS automation for new tenants

**Records needed per tenant**, all triggered at provisioning time:

- `A`/`AAAA` for the domain (and `www`) → the shared platform IP.
- `A` for the tenant's dedicated mail hostname (e.g. `mail.tenant1.com`) → the same shared IP — this is the hostname the SNI-routed IMAP/POP3/submission connections rely on.
- `MX` → the shared mail gateway's hostname (inbound SMTP is the one path that isn't per-tenant-hostname-based, per the mail layer design above).
- `SPF` (TXT) authorizing the platform's outbound sending IP.
- `DKIM` (TXT) — the tenant's mail container needs to generate its own DKIM keypair, and the public half has to be pushed into DNS automatically. This makes DNS automation **downstream of container provisioning**, not independent of it — the record can't be created until the container that generates the key exists.
- `DMARC` (TXT) with a sane default policy.

**Two models for who hosts the zone**, not yet decided between:

- **Platform-hosted authoritative DNS (preferred)**: tenant delegates nameservers to the platform; the control plane manages the zone directly via a DNS server with an API (e.g. PowerDNS) and can push every record above automatically. Also enables **DNS-01 ACME challenges** for cert issuance, which avoids depending on the `A` record having already propagated the way an HTTP-01 challenge would.
- **Tenant-hosted DNS (fallback)**: tenant keeps DNS at their existing registrar/provider. Provisioning can only hand them the records to add (manually, or via an API integration with the more common providers) — activation then needs a verification step that polls DNS until the records match before proceeding, and the tenant is responsible for keeping their own SPF/DKIM/DMARC correct.

**Shared-IP deliverability risk worth naming**: since every tenant sends outbound mail from the same shared IP (per the single-IP premise this whole design started from), one tenant's spam or compromised account can damage sending reputation for every tenant on the platform. DNS automation itself doesn't solve this — it's a separate open concern around abuse monitoring/throttling, and possibly dedicated IPs for tenants who need their own reputation isolated.

## Security posture

- Distinguishing **panel software attack surface** (what got CyberPanel hit) from **tenant-to-tenant isolation** (what classic panels get right via Unix users, but only up to a shared kernel/daemons). This build targets container-level isolation as a middle ground between classic shared-hosting isolation and full VM-per-tenant — acknowledged as not VM-grade (shared kernel), but decided sufficient for now.
- **fail2ban** (not CrowdSec — swapped before ever deploying it) does intrusion detection/prevention on the real production host (vhsp2), enforced at shared chokepoints rather than per-tenant so isolation between tenants stays intact while detection/enforcement is centralized. CrowdSec's community-blocklist/console features want an account with a company that can change what's gated behind that at any time; fail2ban is zero-account, zero-external-service, pure local log-watching + local firewall banning — same enforcement shape, no external dependency. **Fully implemented**: an `[sshd]` jail (host SSH), an operator admin-login jail, a shared tenant-admin-login jail with app-layer per-tenant allowlisting, genuinely tenant-isolated per-tenant SFTP jails (dynamically created/destroyed alongside each tenant, since SFTP's distinct per-tenant ports are the one case where a firewall-level ban can actually stay scoped to one tenant), and both a platform-wide operator allowlist and per-tenant allowlists are all live — each verified with real external-origin traffic, not just localhost (this caught two real bugs: `images/tenant-admin/app.py` had no `ProxyFix`/`X-Forwarded-For` handling at all, so every login-failure log line was recording Traefik's own bridge IP instead of the real client until fixed; and the SFTP jails' filter needed a live-jail-only bug fix around date-pattern handling that offline `fail2ban-regex` testing alone didn't surface). Every other tenant-facing surface (site + admin panel + the operator UI) shares port 443 through one Traefik instance, so a firewall-level ban there is inherently platform-wide regardless of which tenant triggered it — the app-layer per-tenant allowlist is what gives a tenant real control over their own exposure in that shared case. See the control-plane README's fail2ban section for the full design and verification.
- Non-standard per-tenant SSH ports mainly reduce volume from automated mass-scanning/credential-stuffing bots; not a substitute for fail2ban/key-based auth against a targeted attacker.
- **Coraza (OWASP Core Rule Set) WAF** — the piece fail2ban's IP-banning doesn't cover: actual HTTP request-content inspection (SQLi/XSS/RCE/LFI/RFI/etc), regardless of source IP. Traefik's only native Coraza path is Traefik Hub, a commercial product — same category of dependency fail2ban was chosen over CrowdSec to avoid — and the open-source Traefik WASM plugin can't load the real OWASP CRS at all (WASM sandboxing blocks the filesystem access CRS's `Include` directives need). **Phase 1 implemented**: one Coraza+CRS reverse-proxy container per tenant (`ghcr.io/coreruleset/coraza-crs:nginx`, pinned by digest, confirmed via direct image inspection to genuinely bundle and activate the full CRS rule families, not a stub), same "no shared daemon, isolation over density" shape as DB/mail/SSH — the image only supports one `BACKEND` target per instance anyway. Traefik's public router moved from the tenant web container to this new sidecar, which reverse-proxies to the web container by name; the real-client-IP chain (`images/web/entrypoint.sh`) was extended to trust this new immediate hop the same way it already trusted Traefik, verified both via direct inspection of the WAF image's own nginx template (confirms `X-Forwarded-For` is correctly appended, not overwritten) and a live test on vhsp2 against a real disposable tenant, including a real SQLi payload correctly detected then correctly blocked once switched from the default `DetectionOnly` mode to `On`. Ships `DetectionOnly` by default, not blocking — OWASP CRS is known to false-positive on real app traffic, and unlike a fail2ban ban (self-heals in 15-30 minutes) a WAF false positive in blocking mode has no auto-recovery. **Phase 2 also done**: both tenants that predated this feature (`smoketest.vhsp2.dvce.us`, `testing.bigchimp.org`) retrofitted with a WAF sidecar — the non-atomic cutover's exact overlap window was characterized first with disposable containers (confirmed Traefik round-robins between both containers sharing a router name rather than erroring or dropping traffic, so the retrofit costs zero dropped requests), then applied for real with full verification per tenant. Every tenant on the platform now has WAF coverage in `DetectionOnly` mode. **Not yet done**: flipping any tenant to actual blocking mode (needs a real observation period against real traffic first), a per-tenant engine-mode toggle, and a WAF-layer IP allowlist bypass (fail2ban has one). See the control-plane README's "Coraza WAF" section for the full design and verification.
- **Every writable path in a tenant container mounted `noexec`** (plus `nosuid`, `nodev`) — not just the webroot, but any location the tenant/web process can write to (uploads dir, `/tmp`, home dir, etc.). Via the Docker `local` volume driver's bind options (`--opt type=none --opt o=bind,noexec,nosuid,nodev --opt device=...`), since plain `-v`/bind-mount syntax doesn't expose this directly. Only the read-only base image layer (the actual interpreter/binaries meant to run) stays executable.
  - Motivated by a real-world case the user observed: attacker uploaded a binary, then modified cron to execute it for persistence. `noexec` blocks the exec regardless of what triggers it (cron, shell, anything) — the restriction is enforced by the kernel on the mount itself. Broadening beyond just the webroot matters because the drop point doesn't have to be the doc root — any writable path works for this technique.
  - Still doesn't stop interpreter-based webshells (e.g. malicious PHP executed via PHP-FPM) since the interpreter itself, not the payload file, is what's being exec'd — pair with disabling dangerous PHP functions per tenant (below).
- **Dangerous PHP functions (`exec`, `shell_exec`, `system`, `proc_open`, etc.) disabled by default per tenant** via `disable_functions` in that tenant's PHP-FPM pool config, with a **self-service toggle in the tenant admin panel** to re-enable specific functions if a tenant's app genuinely needs them — shown with a clear warning about the tradeoff. Keeps the secure default while leaving the decision (and risk) with the tenant, consistent with the self-service model already used for mail users.

### Abuse monitoring and throttling

Different threat model from fail2ban above: fail2ban watches for **external attackers** hitting the platform from outside. This is about a **tenant's own container misbehaving** — a compromised site sending spam, a hijacked mailbox blasting bulk mail, a cryptominer or botnet participant saturating CPU/network. Same "shared enforcement, isolated tenants" shape as everything else, just pointed the other direction.

- **Outbound mail should relay through a shared outbound relay/smarthost**, mirroring the inbound gateway pattern rather than letting each tenant's container send directly to the internet. This is what makes centralized rate limiting and monitoring possible at all, and it's the concrete mechanism that addresses the shared-IP reputation risk flagged in the DNS automation section — without a shared relay chokepoint, there's nowhere to enforce a per-tenant sending limit.
- **Per-tenant sending limits** (max messages/hour, max distinct recipients/hour) enforced at that relay, with thresholds tripping automatic throttling rather than requiring someone to notice manually.
- **Detection signals worth watching**: bounce-rate or spam-complaint spikes (via provider feedback loops where available), sudden volume spikes against a tenant's own baseline, and a sudden jump in distinct recipient domains — all more indicative of abuse than any single absolute threshold.
- **General resource/network abuse isn't mail-specific** — a tenant's container generating outbound scanning traffic, DDoS participation, or just pegging CPU needs the same per-tenant cgroup limits already used for DB isolation, extended to every other container type, plus egress rate limiting at the network layer (`tc`/cgroup net_cls, or a CNI plugin with bandwidth support — Docker has no first-class per-container bandwidth cap built in). **CPU/memory now implemented on every tenant container type**: `DB_MEM_LIMIT`/`WEB_MEM_LIMIT`/`MAIL_MEM_LIMIT`/`TENANT_ADMIN_MEM_LIMIT`/`SFTP_MEM_LIMIT` (and matching `*_NANO_CPUS`, `config.py`) apply cgroup caps to every container `provisioner.py` creates for a tenant — the last two (tenant-admin, SFTP) were added by a follow-up security review after being flagged as the only remaining containers with no cap, tenant-admin's kept at the same 512MB/1 CPU tier as DB/web/mail rather than lighter specifically because of its 200MB upload endpoint. Egress rate limiting at the network layer is still **not built** — a compromised tenant's container can still saturate outbound bandwidth even with CPU/memory capped.
- **Escalation should be tiered and visible, not a silent black box**: warn → throttle → suspend, surfaced to the tenant in their admin panel rather than just failing mysteriously — consistent with the transparency already built into the PHP-function opt-in warning.

## Observability: bandwidth and resource usage

- **Per-tenant containers make this mostly fall out of the isolation model already chosen** — cgroup boundaries that provide isolation and resource limits are the same boundaries standard container-metrics tooling reports on. A stack like **cAdvisor + Prometheus + Grafana** gets per-tenant CPU, memory, disk I/O, and network metrics with labels by container/tenant, without needing separate instrumentation built into each tenant's stack.
- **What to track per tenant**: CPU and memory usage, disk space consumed (webroot, DB, and mail storage counted separately, since they're separate volumes), and network egress/ingress.
- **Under Swarm**, this needs centralized aggregation across nodes (Prometheus scraping multiple node-exporter/cAdvisor targets) rather than per-host dashboards — ties back to the deployment-topology decision on how nodes are discovered.
- **Feeds directly into two other sections**: a sudden resource spike is itself a signal for abuse detection above (cryptomining, DDoS participation), and ongoing usage approaching a tenant's cgroup limits is worth alerting on proactively rather than just letting the hard cap silently throttle them.
- **Natural extension, not a stated requirement yet**: the same metrics pipeline would be what enforces/reports on tiered plans (bandwidth/storage caps) if the product ever needs that, and could feed a "your usage" view into the tenant admin panel — self-service, consistent with the pattern used everywhere else, but not something this doc is committing to yet.

## Control plane responsibilities (the "cPanel" being replaced)

- Provision tenant containers, volumes, and Docker network entries on demand.
- Maintain the domain → container routing table consumed by the SMTP gateway.
- Allocate and track per-tenant SSH port assignments.
- Trigger DNS setup for new tenants. **Implemented as suggest-only, not automated push**: `vhsp dns records <domain>` (`dns_records.py`) computes and displays the records a human pastes into whatever actually hosts the zone, and can check whether they're already live — no API integration to an actual DNS host exists yet (neither of the two models below is built), so nothing here runs automatically at provisioning time.

## Deployment topology: single host vs. Docker Swarm

Goal: run on a single Docker host for smaller/early deployments, with a path to Docker Swarm for multi-node maintenance and HA, without redesigning the core model.

### Single public IP on the target host

Real production hosts are expected to eventually have only **one public IP** — no spare address to split tenant-facing traffic from a separate management network the way the current dev environment does. That dev environment (a distinct mgmt-network interface the admin UI binds to exclusively) reflects the *original* plan of network position as the admin-access isolation boundary; the single-IP constraint is a departure from that original plan, discovered later, not the intended end state. Concretely, on a single-IP host: vhsp's own local Traefik instance has to be the only routing/TLS layer (no external upstream Traefik fronting it the way the current dev VM has), and admin-UI access control can no longer lean on network position at all — it has to come entirely from application-layer auth. This is a real part of why MFA/hardware-key auth (WebAuthn/FIDO2, see "Control plane authentication and access control" below) was prioritized and actually built rather than left as a someday item, and it's also why the CrowdSec coverage this dev environment currently benefits from (an external swarm's Traefik + bouncer, upstream of this VM and out of this project's scope) can't be assumed on a real production host — that host will need its own edge intrusion detection/prevention, not an inherited one.

**First real single-public-IP test host:** the current dev environment's swarm Traefik (upstream of the VM entirely, and out of this project's control) can't provision TLS certs or route a brand-new domain without manual intervention, which surfaced concretely when adding `testing.bigchimp.org` — the swarm couldn't be made to issue a cert or route to it without hand-holding outside vhsp itself. Rather than keep fighting that upstream layer, the plan is to stand up a small budget VPS (a $6/mo DigitalOcean droplet — one public IPv4 plus one auto-configured IPv6 from its allotted /124, no NAT/firewall in front) for `testing.bigchimp.org` and let vhsp's own local Traefik be the only routing/TLS layer end to end, exactly as this section describes for eventual production. This also doubles as the first real test of cross-host tenant migration via the operator backup/restore feature (see "Backups per tenant" below) — taking a backup on the existing dev VM and restoring it onto the new droplet, rather than only having validated restore against a same-network test target.

### What carries over cleanly

- **Traefik** has a native Swarm-aware provider — same label-based auto-discovery, just reading the service list instead of individual containers.
- **Networking**: overlay networks preserve the same isolation properties as the bridge networks used on a single host — the per-tenant private DB network / shared gateway network model doesn't need rethinking.
- **Service addressing**: Swarm's internal service DNS handles the backend addressing the SMTP gateway's transport_maps and the SNI-routed mail protocols rely on, the same way single-host Docker DNS does.
- **CrowdSec**'s centralized-enforcement pattern still works — it becomes one bouncer per physical node, all reporting to a shared Local API, instead of a single host-level bouncer. Normal supported CrowdSec topology.

### The real fork: stateful data placement

Every tenant's mail/DB/webroot volume is a singleton holding that tenant's actual data, using the `local` volume driver's bind-mount trick (also how the `noexec`/`nosuid` hardening works). That's fine on one host. In Swarm, a service can be rescheduled to any node, but a `local`-driver bind mount is tied to wherever that host path actually lives — a rescheduled tenant stack would land on the wrong node and find no data.

Two paths, not yet decided between:

- **Placement constraints** pinning each tenant's stack to the node holding its volumes — minimal change from the single-host design, but loses Swarm's "reschedule anywhere" resilience for stateful services. Reasonable for a first Swarm-capable version.
- **Shared/distributed storage backend** (NFS, Ceph, cloud block storage) so any node can mount a tenant's volume — genuinely Swarm-native, but need to verify per-backend whether `noexec`/`nosuid` mount options are still honored the same way local bind mounts are — not something to assume.

  **Candidate: NAS over iSCSI.** Rather than a true multi-writer distributed filesystem, this uses a **single-writer failover** pattern: iSCSI is block-level, so a node attaches a tenant's LUN and puts a normal filesystem (ext4/xfs) on top, same as local disk — only one node has a given tenant's LUN attached at a time, and on failover a different node attaches the same LUN and mounts it, so the volume "follows" the container. This is the classic pattern behind traditional HA clustering (Pacemaker-style shared storage), not a distributed FS like Ceph.
  - Because the filesystem ends up mounted locally on whichever node holds the LUN, the `noexec`/`nosuid`/`nodev` hardening applies exactly as it does on local disk — no need to trust a remote export's settings the way NFS requires.
  - Databases generally prefer block storage over file-level network storage, which fits the per-tenant DB isolation piece well.
  - Docker/Swarm doesn't manage iSCSI attach/detach as part of scheduling — needs either an iSCSI-aware volume plugin or the control plane itself doing login/mount before starting a container and logout/unmount after.
  - Split-brain risk is the sharp edge: two nodes mounting the same LUN at once corrupts it, so this needs real fencing, not just an assumption that a failed node is actually dead.
  - The NAS itself becomes a new single point of failure unless it's redundant (dual-controller, its own HA) — trades "one Docker host dying" for "the NAS dying" as the new SPOF if unaddressed.
  - Adds a storage network as new infrastructure to size/monitor, typically wanting its own NICs/VLAN separate from tenant traffic.

### Maintenance and HA — different guarantees for different layers

- **Shared/gateway layer** (Traefik, SMTP gateway, CrowdSec, control plane) gets real maintenance and HA benefits nearly for free: it holds no tenant data, so multiple replicas across nodes plus rolling updates (`docker service update`) plus node draining (`docker node update --availability drain`) work exactly as Swarm is designed for.
- **Tenant data does not get HA just from running under Swarm.** Rescheduling a stateful service to a new node after a failure doesn't recreate its data — if a tenant's volume lived only on the failed node's local disk, it's gone regardless of placement constraints. Real HA for tenant data needs actual data replication (DB streaming replication, Dovecot's `dsync` replication for mail, a distributed filesystem for web files), not just the orchestrator.
- Placement-constrained local-disk volumes buy easier *maintenance* (predictable placement, planned draining) but not *failure* HA — worth not conflating the two.

### Control plane implication

Provisioning has so far been described as "run a container." Targeting both modes means building the control plane against Docker's API in a way that can create either plain containers (single host) or Swarm services (multi-node) — worth designing that abstraction in now rather than retrofitting later.

## Control plane authentication and access control

The control plane can create/destroy tenant containers, rewrite the domain → container routing table, manage DNS, and hold sensitive credentials — a compromise here undermines every isolation boundary described elsewhere in this doc. It deserves the strongest authentication requirements anywhere in the design.

- **The problem is narrower than it first looks.** Tenant self-service (mail users, PHP function toggles, file manager) is deliberately designed to be local to each tenant's own container, not a call back into a shared control-plane API — so the control plane's auth surface is really about **operator/staff access and any automated signup pipeline**, not individual tenants. Worth deliberately keeping it that way rather than letting tenant admin panels grow a path into privileged control-plane actions over time.
- **Operator access**: MFA/hardware-key auth, not just a password, given the blast radius. **Implemented** — per-operator identity plus WebAuthn/FIDO2 (`auth.py`, `webauthn.py`), live on both the operator and tenant admin UIs. **TOTP (authenticator app) also implemented as an alternative second factor** (`totp.py` on the operator side, an independent copy inline in `images/tenant-admin/app.py`, per this codebase's usual cross-trust-boundary duplication) — a user can register either, both, or neither; login accepts whichever they have. Not a replacement for WebAuthn's phishing resistance, just a lower-friction option for anyone without a hardware key. **RBAC with least privilege** — e.g. a support role limited to viewing tenant status or triggering an abuse throttle, versus a full-admin role that can rewrite routing table entries or pull credentials. Not every operator needs the same reach. **Not built, deliberately**: `auth.py`'s own docstring records this as a confirmed decision, not an oversight — operators are flat/equal-privilege for now, RBAC deferred as a separate later gap.
- **Automated pipeline access** (e.g. a signup flow that triggers provisioning) scoped just as tightly as human roles — a service account that can create a new tenant shouldn't also be able to read or modify other tenants, or delete arbitrary ones. **Not built** — no signup/automated-provisioning pipeline exists yet; only human operators via the CLI/admin UI.
- **Login throttling and password strength**, for the window before an account has registered 2FA (2FA above is opt-in, not enforced from account creation) — nothing stopped unlimited password/TOTP-code guessing, and self-chosen passwords had no minimum length. **Implemented**: `vhsp_ctl/login_throttle.py` (independently duplicated in `images/tenant-admin/app.py`) locks a username out for 15 minutes after 5 failed attempts within 15 minutes, checked before the credential itself is verified; a 12-character minimum applies to both self-service password-change paths. See the control-plane README's "Login throttling and password requirements" section for the full design and verification.
- **The Docker/Swarm API itself is the sharpest edge** — it's root-equivalent on the host. Prefer a scoped remote API endpoint over mounting the raw `/var/run/docker.sock` directly, so a compromised control-plane process doesn't automatically mean root on the host. **Implemented**: `deploy/vhsp-docker-proxy.service` runs `tecnativa/docker-socket-proxy` as the only process with raw socket access, re-exposing a curated allow-list (containers/volumes/networks/exec/images; swarm/secrets/configs/plugins/build/etc. denied) on loopback-only `127.0.0.1:2375`. `provisioner._client()` (the single Docker-client constructor in the codebase, per `vhsp_ctl.config.DOCKER_HOST_URL`) talks to the proxy instead of the socket, and the the control-plane user user running the control-plane services is removed from the host's `docker` group so it has no direct path to the raw socket regardless of client URL. TLS client-cert auth on the proxy endpoint was considered and deliberately skipped for now — it's loopback-only, so there's no network hop for a cert to protect against; worth revisiting only if the control plane ever splits across hosts. See the control-plane README's "Docker socket exposure" section for the full design and verification.
- **The the control-plane user sudoers grant was the same edge in a different costume.** The provisioner needs root for mount-hardening (`noexec`/`nosuid`/`nodev` remounts, `/etc/fstab` edits, tenant-directory teardown) — but a blanket `NOPASSWD:ALL` grant on the same user running the internet-facing admin process meant any RCE there was equivalent to root, independent of whatever the Docker proxy above restricted. **Implemented**: sudo is now scoped to four root-owned wrapper scripts (`deploy/vhsp-harden-hostdir`/`deploy/vhsp-remove-hostdir` for mount hardening/teardown, `deploy/vhsp-backup-tar`/`deploy/vhsp-restore-clean` for backup creation and restore-into-existing-tenant — the latter two added after a real regression surfaced: they were missing from the initial scoped grant, silently breaking backup creation until caught and fixed), all installed to `/usr/local/sbin`, all validating their own arguments internally, since modern `sudo` refuses to let a `Cmnd_Alias` wildcard the dynamic tenant paths directly. the control-plane user stays in the `sudo` group for the human operator's own interactive administration (password + TTY required, neither available to an unattended compromise) — only the passwordless, unattended grant was the actual problem, and that's gone. See the control-plane README's "Sudo scoping" section for the full design and verification.
- **Audit logging**, immutable/append-only and shipped off-host (same principle already used for backups) for every privileged action — tenant create/destroy, routing table changes, DNS changes, credential rotation, abuse actions. This is the one layer where a single action has platform-wide blast radius, so the trail needs to survive even if the control plane itself is later compromised. **Implemented**: `audit.py` provides the local half (root-only `audit.log`, tenant/operator mutations plus operator login/logout/failed-login events) and `backup.ship_audit_log` (in `backup.py`, run every minute by `vhsp-audit-ship.timer`) ships new entries off-host to the same operator SFTP destination tenant backups use. **"Immutable" was aspirational until now** — the local file was append-only by convention/permissions only, not a real filesystem guarantee; every entry now carries a `prev_hash` chain (`vhsp audit verify` detects tampering by index, even though the file itself still isn't OS-level immutable) closing the gap between a host compromise and the next successful off-host ship. Login events are operator-admin-UI-only for now — the tenant-admin container has no audit-trail system of its own to log into at all, a separate not-yet-built increment. See the control-plane README's "Audit log tamper-evidence and login events" and "Backup / restore" sections for the mechanism.
- **Network exposure**: the control-plane admin API/UI stays off the same public-facing surface as tenant traffic entirely — reachable only via VPN/bastion, not exposed through the internet-facing gateway — consistent with the "shared tooling at a layer tenants can't reach" pattern already used for CrowdSec and backups.
  - **Departure from this assumption**: this was the original plan — a genuinely separate management IP/network isolating admin access from tenant traffic, which the current dev environment still reflects (a distinct mgmt-network interface the admin UI binds to exclusively, unreachable from the tenant-facing side). Real target production hosts are expected to eventually have only a **single public IP** (see "Single public IP on the target host" under Deployment topology, above), which removes network position as an available isolation boundary for admin access. That's a large part of *why* MFA/hardware-key auth (the bullet above) was prioritized and actually built (WebAuthn/FIDO2, live on both the operator and tenant admin UIs) rather than left as a someday item: once a separate network can't be assumed, strong auth has to carry more of the weight that network isolation was originally going to carry. Don't treat the current dev VM's mgmt-network split as the intended end-state topology when designing new admin-facing features — it's what a two-IP dev box happens to support, not a decision being preserved going forward.
- **Secrets management**: DNS provider API keys, Docker/Swarm join tokens, backup encryption keys, and similar belong in a real secrets manager (Vault, Docker secrets, cloud KMS) with rotation, not plaintext config. **Implemented**: `vhsp_ctl/secretbox.py` adds envelope encryption (a single locally-held master key, `vhsp secrets init`/`vhsp secrets migrate`) for `registry.py`'s tenant credential columns, `totp.py`'s operator TOTP secrets, and — as of the most recent pass — `backup.py`'s SSH transport/age-encryption/Ed25519-signing private keys too (previously the one named gap in this coverage; those keys are now encrypted at rest the same way, decrypted only into a short-lived temp file for the exact duration of each `ssh`/`scp`/`age`/`ssh-keygen` subprocess call that needs a real path on disk). A leaked SQLite file, stray backup, or narrow file-read bug no longer hands over plaintext on its own for any of these. Deliberately not a full external secrets manager (Vault/cloud KMS) — considered and skipped for this single-host, non-permanent deployment; the master key still lives on the same host as what it protects, so a full host compromise remains uncovered. **Rotation implemented for the master key** — `vhsp secrets rotate` re-encrypts every credential/TOTP secret under a fresh key, for when the current one is known or suspected to have leaked. Backup keypair rotation (SSH transport/age/signing) is manual, not code — `vhsp backup init --force` regenerates them, but only protects *future* backups; there's no retroactive re-encryption of existing snapshots, a disclosed tradeoff. See the control-plane README's "Secrets management", "Key rotation", and "Backup private keys at rest" sections for the full design and verification.

## API and MCP access for operators and tenants

Two new access surfaces, mirroring the existing web-UI split rather than
adding a third, unrelated one:

- **Operator-level API + MCP**: programmatic/AI-agent access to the same
  things the operator admin UI does today (tenant management, incident
  response, backups, etc.). This is the same control-plane-level
  privileged surface described in "Control plane authentication and
  access control" above, just a second transport onto it — everything in
  that section (audit logging, the Docker-socket concern, secrets
  management) applies here too, not a separate problem. **Implemented**
  (2026-07-25) — see below.
- **Tenant-level API + MCP**: same idea at the tenant self-service layer
  (PHP toggles, mailboxes, backups, etc. — Files and Database
  deliberately excluded from v1, same conservative posture the operator
  API's own v1 used). **Implemented** (2026-07-25), with a real
  departure from this section's original "not a new path into the
  shared control plane" framing: true per-tenant MCP was explored and
  found impractical (tenant-admin containers have zero Docker/sudo
  access by design, and MCP's SDK is ASGI while that container only
  runs WSGI/gunicorn), so tenant API + MCP instead reuse the *same*
  shared `vhsp_ctl/api.py`/`mcp_server.py` process the operator surface
  uses, reached through a completely separate, narrower-scoped token
  namespace (`vhsp_ctl/tenant_api_auth.py`) rather than a new per-tenant
  process. A tenant's own token can only ever reach that tenant's own
  `/api/v1/self/*` routes or `self_*` MCP tools — verified directly, not
  assumed, including a real bug caught during that verification (see
  below). Gated by a two-layer permission model, both defaulting off:
  an operator must explicitly allow a given tenant (Layer 1, the
  tenant's own detail page), and the tenant must then separately turn
  it on themselves (Layer 2, their own panel) — allowing doesn't enable,
  and disallowing takes effect immediately, live, on every call, with no
  restart anywhere in this half of the design (unlike the operator
  toggle's own three-bug restart history). See the control-plane
  README's "Tenant API + MCP" section for the full design and the real
  privilege-escalation bug found and fixed while verifying it.

Both, non-negotiably:

- **Explicitly opt-in** — off by default; enabling either is a deliberate
  action, not something that comes for free alongside the existing web UI.
  **Implemented** for the operator surface: `config.API_ENABLED` and
  `config.MCP_ENABLED` (independently toggleable, default off) gate the
  REST API Blueprint's registration in `web.py` (when off, `/api/v1/*`
  routes don't exist at all, not just 401) and `mcp_server.py`'s own
  `main()` (refuses to bind if unset, even if the systemd unit is
  installed), respectively. **Turned into a real UI toggle**, not just a
  host-level env var, after a user tried to find one and correctly found
  none — `vhsp_ctl/platform_settings.py` persists the flags at runtime
  (`STATE_DIR/platform_settings.json`, overriding the original env vars
  once it exists), and My account → API & MCP access flips them:
  REST API by restarting `vhsp-admin.service` (an already-existing sudo
  grant), MCP by installing/removing its systemd unit, a scoped firewall
  rule, and its Traefik route — new, narrowly-scoped sudo automation
  (`deploy/vhsp-mcp-toggle`, `deploy/vhsp-mcp-firewall`) for work that
  was previously a manual SSH walkthrough. See the control-plane README's
  "Operator API + MCP" section, "Turning it on: a UI toggle" for the
  full design.
- **Gated behind 2FA**, same principle as the `require_2fa` work already
  built for the web UIs' own destructive actions (see the control plane's
  README, "Gating destructive/high-blast-radius actions behind 2FA").
  **Implemented**: the open design question here ("most likely a token
  mintable only from an already-2FA-authenticated session") is exactly
  what got built — a new `/account/api-tokens` page, `@require_auth
  @require_2fa` (the existing decorator, unmodified), mints an opaque
  bearer token (`secrets.token_urlsafe(32)`, only a `generate_password_hash`
  digest ever persisted, shown once). The token itself is what
  authenticates every subsequent API/MCP call uniformly after that — no
  per-request 2FA challenge, since that isn't a natural fit for API calls,
  same reasoning this section originally anticipated.

**What's actually built**: `vhsp_ctl/api_auth.py` (shared token store,
imported by both front-ends), `vhsp_ctl/api.py` (a Flask Blueprint —
the first one in this codebase, `web.py` otherwise being one flat
module — registered at `/api/v1` only when `API_ENABLED`), and
`vhsp_ctl/mcp_server.py` (a separate `fastmcp`-based process, since the
maintained Python MCP SDKs are ASGI and `web.py` is WSGI/gunicorn; no
clean way to mount one inside the other). Both expose the same v1
operation set — tenant list/get/create/destroy/usage, backups
list/create/restore, audit verify, fail2ban log tail — deliberately
excluding the secret-revealing incident-response resets
(`reset_tenant_db_password` and siblings), which stay web-UI/CLI-only
for now. `GET /tenants/{domain}` redacts every credential field by
default (`registry.tenant_to_dict(tenant, include_secrets=False)`) — a
deliberately *stricter* default than the web UI itself (which already
shows these to any authenticated operator), since a bearer token is a
meaningfully riskier thing to leak (script, log line, shell history)
than a session cookie tied to one browser. Every API/MCP-triggered
action is attributed in the audit trail to the real minting operator
(`api:<username>` / `mcp:<username>`, not a generic actor), and a
removed operator's tokens stop working immediately (`api_auth.validate_token`
checks `auth.operator_exists`, not just the token hash). Swagger UI is
vendored locally (`vhsp_ctl/static/`, pulled from `swagger-ui-dist`, no
CDN) and served at `/api/v1/docs`, same "vendor the built bundle, no
build step in the image" pattern the CodeMirror file editor already
established. The MCP server runs as its own systemd unit
(`deploy/vhsp-mcp.service`), reachable through Traefik at
`https://<host>/mcp` (fastmcp's own default Streamable HTTP path) via a
path-based route on the existing admin-UI host+cert — see the control
plane's DEPLOYMENT.md for the exact dynamic-route file and firewall
rule this needs. Verified end-to-end on the live vhsp2 deployment: a
real 2FA-authenticated token mint, every REST endpoint over real HTTPS,
Swagger UI actually driving a request, a real `fastmcp` client
round-trip (including a disposable-tenant create/destroy) over the real
public MCP route, and `vhsp audit verify` showing the correct actor for
both surfaces. Two real bugs were found and fixed during this pass, not
part of the original design: the platform-wide session-CSRF
`before_request` hook was rejecting every API POST/DELETE outright
(bearer-token requests have no session-stored CSRF token to check
against — fixed by exempting the `api` Blueprint, which is immune to
CSRF by construction since it never uses cookies), and gunicorn's
default 30s worker timeout was silently killing the HTTP response for
`create_tenant` (a ~60-90s synchronous call) even though the tenant
finished provisioning anyway — fixed by raising `--timeout` to 180s,
which also fixes the identical latent risk in the web UI's own
"New tenant" form.

## Open questions

- Orchestration technology for the control plane — plain Docker API (dockerode/docker-py) assumed sufficient for a single-host MVP; Swarm/Kubernetes not yet justified.
- Certificate handling specifics for SNI-routed per-tenant mail hostnames.
- Whether container-level isolation will need to be hardened further later (e.g. gVisor/Kata, VM-per-tenant) if the threat model demands it.
