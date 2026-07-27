# VHSP — Virtual Hosting Service Platform

A self-hosted, multi-tenant hosting platform built as a security-focused
alternative to cPanel/CyberPanel-style control panels. Tenants get their own
isolated web, mail, database, and SSH/SFTP containers instead of sharing a
single daemon per service — the goal is real tenant-to-tenant isolation, not
just Unix-user separation.

See [`architecture.md`](architecture.md) for the full design rationale
(why this exists, alternatives considered, and the isolation model), and
[`control-plane/README.md`](control-plane/README.md) for what's actually
implemented, how to run it, and detailed feature documentation.

## Why

- Evaluating alternatives to cPanel for a multi-tenant hosting product,
  where customers self-serve their own web + mail, not just internal
  company sites.
- Primary driver is **security**, not licensing cost — informed in part by
  CyberPanel's 2024 unauthenticated RCE/ransomware incident.
- Strong preference for **tenant isolation** beyond the classic
  shared-daemon model used by DirectAdmin/Plesk/Virtualmin/ISPConfig.

## How it works

A single Docker host runs a front-end control plane that provisions
per-tenant containers on demand:

- **Web**: Traefik routes by domain/SNI to each tenant's own nginx +
  PHP-FPM container; per-domain TLS via Let's Encrypt.
- **Mail**: a shared inbound SMTP gateway relays by recipient domain to
  each tenant's own Postfix/Dovecot container; IMAPS/SMTPS are SNI-routed
  directly to the tenant container.
- **Database**: one MariaDB container per tenant, on a private
  per-tenant network unreachable by anyone else.
- **Files**: a web-based file manager in each tenant's admin panel, plus
  dedicated per-tenant SSH/SFTP (key-only, no shared gateway).
- **Tenant self-service**: each tenant gets its own admin panel (mail
  users, PHP function toggles, redirects, backups, logs, WebAuthn/TOTP
  2FA) without needing access back into the shared control plane.

Hardening includes per-tenant `noexec`/`nosuid`/`nodev` volumes, disabled
dangerous PHP functions by default, fail2ban, a per-tenant Coraza/OWASP
CRS WAF, per-tenant cgroup resource limits, encrypted/signed off-host
backups, and WebAuthn/TOTP-gated operator and tenant access.

## Getting started

The control plane lives in [`control-plane/`](control-plane). To install
it:

```
cd control-plane
python3 -m venv .venv
.venv/bin/pip install -e .

.venv/bin/vhsp admin init            # bootstrap the first operator
.venv/bin/vhsp tenant create example.local
```

For a full install runbook on a fresh single-public-IP host, see
[`control-plane/DEPLOYMENT.md`](control-plane/DEPLOYMENT.md).

## Repository layout

- [`architecture.md`](architecture.md) — design notes: motivation,
  alternatives considered, architecture, security posture, and open
  questions.
- [`control-plane/`](control-plane) — the implementation: `vhsp_ctl` (CLI +
  admin web UI + API/MCP server), per-tenant container images
  (`images/web`, `images/mail`, `images/mailgw`, `images/tenant-admin`),
  and deployment units (`deploy/`).
- [`control-plane/README.md`](control-plane/README.md) — feature-by-feature
  documentation of what's implemented.
- [`control-plane/DEPLOYMENT.md`](control-plane/DEPLOYMENT.md) — step-by-step
  install guide for a fresh host.
- [`nginx-tenant-hardening.md`](nginx-tenant-hardening.md) — notes from
  dogfooding a real tenant and the nginx-level hardening gaps it surfaced.

## Status

This started as planning notes and has since become a working build. Most
of `architecture.md` is implemented; sections that are still aspirational
or where the build diverged are called out inline there. See
`control-plane/README.md`'s "Open questions" and "Known gaps" for what's
still outstanding.
