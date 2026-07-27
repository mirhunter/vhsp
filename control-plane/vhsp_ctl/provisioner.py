"""Docker-backed tenant provisioning.

Implements the control-plane responsibilities from architecture.md:
  - Provision tenant containers, volumes, and Docker network entries
    (web + DB + SFTP + mail containers, each with a hardened volume where
    relevant).
  - Maintain the domain -> container routing table.
  - Allocate and track per-tenant SSH port assignments.
  - Own the shared inbound SMTP gateway's transport_maps.

DNS automation is separate, not-yet-built (see architecture.md).
"""

import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import docker
from docker.errors import NotFound
from werkzeug.security import generate_password_hash

from vhsp_ctl import audit, dns_records, registry, toggles, waf
from vhsp_ctl.config import (
    ADMIN_RP_ID,
    DB_INTERNAL_PORT,
    DB_MEM_LIMIT,
    DB_NANO_CPUS,
    DEFAULT_DB_IMAGE,
    DEFAULT_TENANT_QUOTA_BYTES,
    DEFAULT_WEB_IMAGE,
    DKIM_SELECTOR,
    DOCKER_HOST_URL,
    GATEWAY_NETWORK,
    MAIL_DEFAULT_USER,
    MAIL_IMAGE,
    MAIL_IMAPS_PORT,
    MAIL_MEM_LIMIT,
    MAIL_NANO_CPUS,
    MAIL_SMTPS_PORT,
    MAILGW_CONTAINER,
    MAILGW_HOSTNAME,
    MAILGW_IMAGE,
    MAILGW_MAPS_DIR,
    MCP_BIND_PORT,
    ROUNDCUBE_CONTAINER,
    ROUNDCUBE_DATA_DIR,
    ROUNDCUBE_IMAGE,
    ROUTING_TABLE_PATH,
    SFTP_IMAGE,
    SFTP_MEM_LIMIT,
    SFTP_NANO_CPUS,
    SSH_PORT_RANGE,
    TENANT_ADMIN_ENTRYPOINT,
    TENANT_ADMIN_IMAGE,
    TENANT_ADMIN_MEM_LIMIT,
    TENANT_ADMIN_MGMTWEB_EXISTS,
    TENANT_ADMIN_NANO_CPUS,
    TENANTS_DIR,
    TRAEFIK_DYNAMIC_DIR,
    WAF_ENGINE_MODE,
    WAF_IMAGE,
    WAF_INTERNAL_PORT,
    WAF_MEM_LIMIT,
    WAF_NANO_CPUS,
    WAF_REQ_BODY_LIMIT_BYTES,
    WAF_REQ_BODY_NOFILES_LIMIT_BYTES,
    WEB_DOCUMENT_ROOT,
    WEB_MEM_LIMIT,
    WEB_NANO_CPUS,
    WEB_TRUSTED_PROXY_CIDRS,
)


class ProvisioningError(Exception):
    pass


def slugify(domain: str) -> str:
    slug = re.sub(r"[^a-z0-9-]+", "-", domain.lower()).strip("-")
    if not slug:
        raise ProvisioningError(f"domain {domain!r} produced an empty slug")
    return slug


def _allocate_ssh_port() -> int:
    used = registry.used_ssh_ports()
    for port in range(SSH_PORT_RANGE[0], SSH_PORT_RANGE[1] + 1):
        if port not in used:
            return port
    raise ProvisioningError("no free SSH ports left in reserved range")


def _client() -> docker.DockerClient:
    return docker.DockerClient(base_url=DOCKER_HOST_URL)


def _ensure_gateway_network(client: docker.DockerClient) -> None:
    try:
        client.networks.get(GATEWAY_NETWORK)
    except NotFound:
        raise ProvisioningError(
            f"gateway network {GATEWAY_NETWORK!r} does not exist -- "
            "it's expected to be created once, out of band (see Traefik setup)"
        )


def _run(*args: str) -> None:
    subprocess.run(args, check=True, capture_output=True, text=True)


def tail_fail2ban_log(n: int) -> str:
    """For the operator UI's /fail2ban page. The control-plane user can't read
    /var/log/fail2ban.log directly (not documented anywhere as
    non-root-readable, so not assumed to be) -- goes through the same
    root-owned-wrapper-script pattern as every other sudo action here,
    via deploy/vhsp-fail2ban-log-tail. Unlike _run(), this needs the
    actual output back, not just success/failure, so it's a separate
    small subprocess.run() rather than a change to _run()'s own
    signature (which every other call site relies on staying void)."""
    result = subprocess.run(
        ["sudo", "/usr/local/sbin/vhsp-fail2ban-log-tail", str(n)],
        check=True, capture_output=True, text=True,
    )
    return result.stdout


def _split_tenant_host_path(host_path: str) -> tuple[str, str]:
    """host_path is always TENANTS_DIR/slug/purpose (see
    _create_hardened_volume) -- recovers the two path components the
    root-owned deploy/vhsp-harden-hostdir / vhsp-remove-hostdir wrapper
    scripts need as separate, individually-validated arguments, rather
    than handing a full path to something running as root."""
    slug, purpose = Path(host_path).relative_to(TENANTS_DIR).parts
    return slug, purpose


def _harden_host_dir(host_path: str) -> None:
    """Make host_path itself a noexec,nosuid,nodev mountpoint.

    Docker's local volume driver bind-mounts host_path into the container
    with a single raw mount(2) syscall; the kernel silently drops
    noexec/nosuid/nodev on a bind mount unless applied via a *separate*
    remount pass (the `mount` CLI does this transparently, Docker's driver
    does not -- verified by exec-testing a script placed in a volume
    created with `o=bind,noexec,nosuid,nodev` and having it run anyway).

    Fix: hardening happens here, once, at the host level, before Docker
    ever touches the directory. Docker's subsequent bind mount inherits
    noexec/nosuid/nodev from its source (a plain bind cannot relax those
    flags), so the volume ends up hardened without Docker's driver needing
    to cooperate. An /etc/fstab entry (using the same single-line
    bind+flags form, which -- unlike a bare `mount --bind ... -o noexec`
    CLI invocation -- util-linux applies as a real two-pass mount) makes
    this survive a host reboot.

    The actual fstab-editing and mount(8) work happens inside
    deploy/vhsp-harden-hostdir, a root-owned script invoked via a single
    scoped sudo call -- not inline `sudo tee`/`sudo mount` calls -- so the
    control-plane user's sudoers grant can be narrow (see the control-plane
    README's "Docker socket exposure" section for why a blanket sudo
    grant on the same user running the internet-facing admin process was
    a real problem). The wrapper script is itself idempotent (checks
    fstab membership / mount state before acting), so this is safe to
    call unconditionally.
    """
    slug, purpose = _split_tenant_host_path(host_path)
    _run("sudo", "/usr/local/sbin/vhsp-harden-hostdir", slug, purpose)


def _remove_host_dir(host_path: str) -> None:
    """Unmount, drop the fstab entry, and delete host_path outright.

    Full deletion (not just unmount) is deliberate: containers like
    MariaDB chown their data directory to an internal uid on startup
    (verified: it ends up owned by uid 999 on the host, not the user the
    control plane runs as), so a "destroy" that left the
    directory behind would leave it unwritable/unchmoddable by the control
    plane on the next `mkdir`+`chmod` for that same tenant slug. Tenant
    data recovery after a destroy is what the (not yet built) backup
    system is for, not an implicitly-kept host directory.

    Same wrapper-script reasoning as _harden_host_dir above -- the
    unmount/fstab-edit/rm-rf sequence runs inside the root-owned
    deploy/vhsp-remove-hostdir script via one scoped sudo call.
    """
    slug, purpose = _split_tenant_host_path(host_path)
    _run("sudo", "/usr/local/sbin/vhsp-remove-hostdir", slug, purpose)


def _create_hardened_volume(client: docker.DockerClient, slug: str, purpose: str) -> tuple[str, str]:
    """Create a `purpose` volume (e.g. "webroot", "db") backed by a host
    directory hardened noexec,nosuid,nodev at the host mount level (see
    _harden_host_dir), per architecture.md's mount-hardening section.

    Applies equally to the DB data directory: MariaDB never executes
    anything out of its datadir, so noexec costs it nothing while still
    closing off the same "drop a binary, get it to run somehow" path the
    hardening targets for the webroot.
    """
    host_path = TENANTS_DIR / slug / purpose
    volume_name = f"vhsp-{slug}-{purpose}"
    # Idempotent: every existing caller only ever calls this once per
    # tenant+purpose (fresh provisioning), but the new dkim volume below
    # gets (re-)ensured on every mail-container recreation, not just the
    # first. Init steps (mkdir/chmod/harden) only run on the branch that
    # actually creates the volume for the first time -- deliberately NOT
    # unconditional every call: a container that owns this path can chown
    # it to its own internal uid after first boot (opendkim does exactly
    # this for the dkim purpose, same class of issue as mail's vmail
    # chown), which then makes host_path.chmod() below fail with
    # PermissionError on a second call since this unprivileged process is
    # no longer the owner -- verified directly, re-running recreate_mail.py
    # hit exactly that. Skipping re-init on reuse sidesteps it entirely
    # rather than needing sudo here too.
    try:
        client.volumes.get(volume_name)
    except NotFound:
        host_path.mkdir(parents=True, exist_ok=True)
        host_path.chmod(0o755)
        _harden_host_dir(str(host_path))
        client.volumes.create(
            name=volume_name,
            driver="local",
            driver_opts={
                "type": "none",
                "o": "bind",
                "device": str(host_path),
            },
        )
    return volume_name, str(host_path)


def _create_db_network(client: docker.DockerClient, slug: str) -> str:
    """Private per-tenant network -- only this tenant's own containers will
    ever join it; not reachable from the gateway network or other tenants."""
    network_name = f"vhsp-{slug}-db"
    client.networks.create(network_name, driver="bridge", internal=True)
    return network_name


def _generate_db_credentials(slug: str) -> tuple[str, str, str, str]:
    """db_name, db_user, db_password, db_root_password -- unique per tenant,
    generated at provisioning time per architecture.md's DB isolation
    section. Stored in the registry (see registry.py's note on that) rather
    than baked into any image."""
    db_name = re.sub(r"-", "_", slug)[:32]
    db_user = db_name[:16]
    return db_name, db_user, secrets.token_urlsafe(24), secrets.token_urlsafe(24)


def _create_db_container(
    client: docker.DockerClient,
    slug: str,
    db_network: str,
    db_name: str,
    db_user: str,
    db_password: str,
    db_root_password: str,
) -> tuple[str, str, str]:
    """The tenant's own DB container -- joined ONLY to its private
    db_network, never the shared gateway network, so nothing but that
    tenant's own web/app container can reach it. Per-tenant cgroup limits
    guard against one tenant's DB load starving another's."""
    volume_name, host_path = _create_hardened_volume(client, slug, "db")

    container_name = f"vhsp-{slug}-db"
    client.containers.run(
        DEFAULT_DB_IMAGE,
        name=container_name,
        detach=True,
        restart_policy={"Name": "unless-stopped"},
        network=db_network,
        mem_limit=DB_MEM_LIMIT,
        nano_cpus=DB_NANO_CPUS,
        environment={
            "MARIADB_ROOT_PASSWORD": db_root_password,
            "MARIADB_DATABASE": db_name,
            "MARIADB_USER": db_user,
            "MARIADB_PASSWORD": db_password,
        },
        volumes={volume_name: {"bind": "/var/lib/mysql", "mode": "rw"}},
        labels={
            "vhsp.tenant.slug": slug,
        },
    )
    return container_name, volume_name, host_path


def _create_web_container(
    client: docker.DockerClient,
    slug: str,
    domain: str,
    volume_name: str,
    phpconf_volume: str,
    logs_volume: str,
    db_network: str,
    db_container_name: str,
    db_name: str,
    db_user: str,
    db_password: str,
) -> str:
    """Factored out of create_tenant() so a DB password rotation
    (reset_tenant_db_password) can recreate this container with a fresh
    DB_PASSWORD without duplicating its volumes/labels/network wiring --
    env vars are baked in at container-create time, not hot-reloadable,
    same reason _create_tenant_admin_container already needed its own
    reusable form for recreate_tenant_admin.py. Returns the container
    name.

    No `traefik.*` labels here -- this container is deliberately not
    directly publicly routable. The Coraza WAF sidecar
    (_create_waf_container) owns the public Host(<domain>) router now
    and reverse-proxies to this container by name; this one only needs
    to stay on GATEWAY_NETWORK so that sidecar can reach it. See the
    control-plane README's "Coraza WAF" section.
    """
    container_name = f"vhsp-{slug}-web"
    container = client.containers.run(
        DEFAULT_WEB_IMAGE,
        name=container_name,
        detach=True,
        restart_policy={"Name": "unless-stopped"},
        network=GATEWAY_NETWORK,
        mem_limit=WEB_MEM_LIMIT,
        nano_cpus=WEB_NANO_CPUS,
        volumes={
            volume_name: {"bind": WEB_DOCUMENT_ROOT, "mode": "ro"},
            # Only ever read by the web container's watcher loop -- the
            # tenant-admin container is what writes to this.
            phpconf_volume: {"bind": "/data", "mode": "ro"},
            logs_volume: {"bind": "/var/log/vhsp", "mode": "rw"},
        },
        environment={
            # Not consumed by the static placeholder page -- available to
            # whatever real PHP app a tenant puts in their webroot.
            "DB_HOST": db_container_name,
            "DB_PORT": str(DB_INTERNAL_PORT),
            "DB_NAME": db_name,
            "DB_USER": db_user,
            "DB_PASSWORD": db_password,
            # See config.py's WEB_TRUSTED_PROXY_CIDRS docstring -- consumed by
            # entrypoint.sh to recover the real client IP in nginx access
            # logs instead of always showing the local Traefik hop's own
            # address.
            "VHSP_TRUSTED_PROXY_CIDRS": WEB_TRUSTED_PROXY_CIDRS,
            # entrypoint.sh resolves this by name (same dynamic
            # getent-hosts pattern already used for `traefik` -- a plain
            # IP would go stale the moment this sibling container is
            # ever recreated) and trusts it as a second real-IP hop,
            # since the WAF container -- not Traefik -- is now the
            # immediate peer this nginx actually sees. Fully
            # deterministic from `slug`, so this needs no coordination
            # with _create_waf_container beyond both deriving the same
            # name from the same slug.
            "WAF_CONTAINER_NAME": f"vhsp-{slug}-waf",
        },
        labels={
            "vhsp.tenant.slug": slug,
            "vhsp.tenant.domain": domain,
        },
    )
    # Second network joined post-create; docker-py's `network=` kwarg on
    # run() only accepts one network at container-create time.
    client.networks.get(db_network).connect(container)
    return container_name


# Traefik's `web` entrypoint sets `http.tls.certresolver=letsencrypt`, so
# any router landing there with no TLS config of its own inherits it and
# an ACME order fires the moment Traefik discovers the router -- at
# container start, before anyone has had a chance to point DNS here. Those
# orders fail and never retry (issue #18), and each one spends part of the
# five failed validations Let's Encrypt allows per hostname per hour.
#
# A router that declares its OWN `tls` does not inherit the entrypoint's
# resolver. Verified directly on a live host: `tls=true` alone produced
# zero ACME orders and served Traefik's self-signed fallback; adding
# `tls.certresolver=letsencrypt` to the same router produced an order
# immediately. That is the whole mechanism behind provisioning without
# burning validations.
#
# Note this is deliberately still TLS, not plain HTTP. Serving a tenant --
# and especially their admin panel, which takes a password -- over :80
# while waiting for DNS was considered and rejected: the panel should never
# be reachable unencrypted, a self-signed warning is the honest signal that
# setup is incomplete, and the platform-wide HTTP->HTTPS redirect (issue
# #20) would defeat a :80 router anyway, since it matches HostRegexp(`^.+$`)
# at priority MaxInt64-1 and outranks any Host() rule.
def _tls_labels(router: str, with_certresolver: bool) -> dict:
    """TLS labels for one router. Without `with_certresolver` the router
    serves the self-signed fallback and asks Let's Encrypt for nothing."""
    labels = {f"traefik.http.routers.{router}.tls": "true"}
    if with_certresolver:
        labels[f"traefik.http.routers.{router}.tls.certresolver"] = "letsencrypt"
    return labels


def should_request_cert_for(hostname: str) -> bool:
    """Is this one hostname's DNS already pointing here, i.e. could an
    ACME challenge for it actually succeed right now?

    Per hostname, not per tenant, and that distinction matters. An
    earlier version required every hostname to be live before issuing
    anything, which meant a tenant who simply never created a webmail or
    www record left their main site on a self-signed certificate
    permanently -- blocked by a record they had no intention of making.
    Certificates are ordered per router anyway, so there is no reason for
    one hostname's absence to hold another's back.

    False when the platform IP isn't configured: with nothing to compare
    against there is no evidence DNS is right, and the safe reading of no
    evidence is "don't order yet".
    """
    if not dns_records.PLATFORM_PUBLIC_IP:
        return False
    return dns_records.is_record_live("A", hostname, dns_records.PLATFORM_PUBLIC_IP)


def tenant_cert_hostnames(domain: str) -> list[str]:
    """Every hostname this platform requests a certificate for.

    Single source of truth for the reconciler and the reissue action, so
    adding a router with a certresolver means adding it here too rather
    than discovering later that nothing ever checks it.

    mail.<domain> is absent on purpose: its IMAPS/SMTPS routers use TLS
    passthrough to the tenant's own mail container, so Traefik never
    terminates or requests anything for it.
    """
    return [domain, f"www.{domain}", f"admin.{domain}", f"webmail.{domain}"]

def _create_waf_container(
    client: docker.DockerClient, slug: str, domain: str, phpconf_host_path: str,
) -> str:
    """Coraza WAF (OWASP Core Rule Set) reverse-proxy sidecar -- owns the
    public Traefik router _create_web_container used to hold directly,
    and reverse-proxies to that container by name
    (`vhsp-<slug>-web:80`, matching WEB_DOCUMENT_ROOT's own container
    naming). One per tenant rather than one shared instance, same "no
    shared daemon, isolation over density" reasoning architecture.md
    already applies to DB/mail/SSH -- also the only shape this
    particular image actually supports (BACKEND is a single host:port,
    no multi-tenant routing of its own). See the control-plane README's
    "Coraza WAF" section for why this is a real container rather than a
    Traefik plugin (the open-source Traefik-native path can't load the
    actual OWASP CRS at all).

    No second network join needed -- unlike the web container, this one
    has no DB access and no reason to leave GATEWAY_NETWORK.
    """
    container_name = f"vhsp-{slug}-waf"
    router_id = f"vhsp-{slug}"
    # The image's own real-IP handling defaults to trusting only
    # 127.0.0.1 and reading X-Real-IP -- neither matches this platform
    # (Traefik sits in front, sends X-Forwarded-For, not X-Real-IP, and
    # isn't loopback relative to this container). Confirmed via direct
    # inspection of the image's own /templates/nginx.conf, not assumed:
    # `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`
    # correctly *appends* rather than overwrites, so trusting the
    # GATEWAY_NETWORK subnet here (not a single IP -- Traefik's own
    # container can be recreated, and Docker doesn't guarantee it keeps
    # the same address) is enough for this container's own audit log to
    # attribute detected/blocked requests to the real source IP rather
    # than always showing Traefik's address. Looked up live rather than
    # hardcoded -- the subnet is whatever was assigned when
    # GATEWAY_NETWORK was created, which varies by deployment (verified
    # this actually differs across this project's own dev VM vs vhsp2).
    gateway_subnet = client.networks.get(GATEWAY_NETWORK).attrs["IPAM"]["Config"][0]["Subnet"]
    # Per-tenant engine mode + allowlist bypass, as a generated file rather
    # than more environment variables -- see vhsp_ctl/waf.py's module
    # docstring. config.d/ is included after the base coraza.conf (so
    # SecRuleEngine here wins over CORAZA_RULE_ENGINE below) but before the
    # CRS rules (so the allowlist's phase-1 rule runs first). Read-only:
    # nothing inside the container has any business rewriting it.
    waf_conf_host_path = Path(phpconf_host_path) / waf.WAF_CONF_FILENAME
    if not waf_conf_host_path.exists():
        # First boot for this tenant -- render defaults now so the mount
        # target exists before the container starts. Written directly
        # rather than via waf.write_tenant_conf() because the registry row
        # this tenant needs may not exist yet during provisioning.
        waf_conf_host_path.write_text(waf.render_conf(WAF_ENGINE_MODE, waf.read_allowlist()))
        os.chmod(waf_conf_host_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    container = client.containers.run(
        WAF_IMAGE,
        name=container_name,
        detach=True,
        restart_policy={"Name": "unless-stopped"},
        network=GATEWAY_NETWORK,
        mem_limit=WAF_MEM_LIMIT,
        nano_cpus=WAF_NANO_CPUS,
        volumes={
            str(waf_conf_host_path): {
                "bind": "/opt/coraza/config.d/99-vhsp.conf", "mode": "ro",
            },
        },
        environment={
            "BACKEND": f"vhsp-{slug}-web:80",
            "PORT": str(WAF_INTERNAL_PORT),
            "CORAZA_RULE_ENGINE": WAF_ENGINE_MODE,
            "CORAZA_REQ_BODY_LIMIT": str(WAF_REQ_BODY_LIMIT_BYTES),
            "CORAZA_REQ_BODY_NOFILES_LIMIT": str(WAF_REQ_BODY_NOFILES_LIMIT_BYTES),
            "REAL_IP_HEADER": "X-Forwarded-For",
            "SET_REAL_IP_FROM": gateway_subnet,
            "SERVER_NAME": domain,
        },
        labels={
            "traefik.enable": "true",
            f"traefik.http.routers.{router_id}.rule": f"Host(`{domain}`)",
            f"traefik.http.routers.{router_id}.entrypoints": "web",
            f"traefik.http.services.{router_id}.loadbalancer.server.port": str(WAF_INTERNAL_PORT),
            **_tls_labels(router_id, should_request_cert_for(domain)),
            # www.<domain> redirects to the apex. dns_records has always
            # suggested an A record for it, tenants create it, and until
            # now nothing routed it -- it returned 404 behind the
            # self-signed fallback on every tenant.
            #
            # A separate router with its own certificate, not www folded
            # into the apex rule. Folding them makes one ACME order cover
            # both names, so a tenant who never points www here would
            # block their own apex certificate. Separate keeps each
            # hostname's fate its own.
            f"traefik.http.routers.{router_id}.service": router_id,
            f"traefik.http.routers.{router_id}-www.rule": f"Host(`www.{domain}`)",
            f"traefik.http.routers.{router_id}-www.entrypoints": "web",
            f"traefik.http.routers.{router_id}-www.service": router_id,
            f"traefik.http.routers.{router_id}-www.middlewares": f"{router_id}-www-redirect",
            **_tls_labels(f"{router_id}-www", should_request_cert_for(f"www.{domain}")),
            # Preserves path and query. Anchored on the leading "www." so
            # it can't rewrite a host that merely contains it.
            f"traefik.http.middlewares.{router_id}-www-redirect.redirectregex.regex":
                rf"^https?://www\.{re.escape(domain)}/(.*)",
            f"traefik.http.middlewares.{router_id}-www-redirect.redirectregex.replacement":
                f"https://{domain}/$1",
            f"traefik.http.middlewares.{router_id}-www-redirect.redirectregex.permanent": "true",
            "vhsp.tenant.slug": slug,
            "vhsp.tenant.domain": domain,
        },
    )
    return container_name


def tail_waf_log(slug: str, n: int) -> str | None:
    """For the operator UI's per-tenant /tenants/<domain>/logs page.
    Unlike the web/mail/sftp logs (plain files on the shared logs_volume,
    read via toggles.tail_log), Coraza's audit log only ever goes to
    this container's own stdout (CORAZA_AUDIT_LOG=/dev/stdout, no file
    mount) -- the only way to read it is the Docker Engine API's
    container-logs endpoint, which this codebase had never used before
    (confirmed via a real end-to-end test against the proxy before
    trusting it: deploy/vhsp-docker-proxy.service needed a new LOGS=1
    flag, since tecnativa/docker-socket-proxy gates this endpoint
    separately from the general CONTAINERS flag every other Docker call
    here already relies on).

    Returns None -- same "no entries yet" contract as toggles.tail_log
    -- if the tenant has no WAF container (a tenant that predates the
    Coraza feature and hasn't been retrofitted via recreate_waf.py yet),
    not an error; the template doesn't need to special-case this."""
    try:
        container = _client().containers.get(f"vhsp-{slug}-waf")
    except NotFound:
        return None
    raw = container.logs(stdout=True, stderr=True, tail=n)
    return raw.decode("utf-8", errors="replace") or None


def _generate_sftp_user(slug: str) -> str:
    """Unlike the DB username (shared truncation risk noted in
    _generate_db_credentials), this only needs to be unique *within* the
    tenant's own single-user SFTP container, so no collision risk across
    tenants regardless of truncation. Prefixed to guarantee a valid unix
    username even when the domain-derived slug starts with a digit (bare
    slugs are allowed to)."""
    return f"t-{slug}"[:32]


def _create_sftp_container(
    client: docker.DockerClient,
    slug: str,
    ssh_port: int,
    webroot_volume: str,
    sftp_user: str,
    logs_volume: str,
    keys_volume: str | None = None,
) -> tuple[str, str, str]:
    """Dedicated per-tenant SFTP-only container -- architecture.md's
    "Getting files onto tenant websites" section explicitly chose this over
    a shared SSH gateway, for the same "no common daemon all tenants
    depend on" reasoning as everything else. atmoz/sftp forces
    `internal-sftp` with no shell, so there's no exec surface to worry
    about here the way there is for the webroot itself.

    Published directly on the tenant's reserved host port -> container
    port 22, per the doc: SSH/SFTP has no SNI equivalent to route on the
    way HTTPS/IMAPS do, so this can't go through Traefik like the web
    traffic does -- it's a real 1:1 host-port-to-container mapping instead.

    Mounts the *same* webroot volume the web container serves from
    (already noexec/nosuid/nodev-hardened at the host level), under
    /home/<user>/www -- upload here, it's live on the site immediately,
    same volume, no sync step.

    Also mounts a per-tenant keys volume at /home/<user>/.ssh/keys --
    atmoz/sftp's entrypoint scans that directory for *.pub files and
    builds authorized_keys from them, but ONLY on the user's first-ever
    boot (verified: a later `docker restart` with a new key already
    present does not rebuild authorized_keys). Pass an existing
    `keys_volume` to reuse one across a set_ssh_public_key-triggered
    recreation instead of creating (and re-seeding) a new one; omit it to
    create fresh, as at initial provisioning.

    A freshly-created keys volume has to be seeded with a placeholder file
    before the container's first boot: verified atmoz/sftp's entrypoint
    runs `cat /home/<user>/.ssh/keys/*` unconditionally, and with a
    genuinely empty directory the glob doesn't expand, so `cat` fails on
    the literal string "*" -- which crashes the entrypoint before it
    reaches host-key generation at all, and the container crash-loops with
    "no hostkeys available" (a confusing error miles from the actual
    cause). Any file matching *.pub, including an empty one, is enough for
    the glob to match and `cat` to succeed. (Also verified: the file can't
    have a leading dot -- a bare `*` glob doesn't match dotfiles.)

    atmoz/sftp is a third-party image, so its own connection/auth logging
    (verified: sshd inside it already writes to stdout, not silently lost
    -- it's just that "stdout" only means `docker logs`, unreachable from
    the tenant-admin container without docker.sock) can't be redirected by
    editing its Dockerfile. Instead the entrypoint is overridden here to a
    shell wrapper that `exec`s the image's real /entrypoint with stdout
    and stderr redirected into the shared logs volume -- a plain `exec`
    redirect, not a pipe through `tee`, so the replaced process keeps PID
    1 and receives docker's stop signal directly rather than a wrapper
    shell swallowing it.
    """
    keys_host_path = str(TENANTS_DIR / slug / "ssh_keys")
    if keys_volume is None:
        keys_volume, keys_host_path = _create_hardened_volume(client, slug, "ssh_keys")
        (Path(keys_host_path) / "placeholder.pub").write_text("")

    container_name = f"vhsp-{slug}-sftp"
    client.containers.run(
        SFTP_IMAGE,
        name=container_name,
        detach=True,
        restart_policy={"Name": "unless-stopped"},
        entrypoint=[
            "sh", "-c",
            "mkdir -p /var/log/vhsp && touch /var/log/vhsp/sftp.log && "
            "chmod 666 /var/log/vhsp/sftp.log && "
            'exec /entrypoint "$@" >> /var/log/vhsp/sftp.log 2>&1',
            "sh",
        ],
        # Trailing colon, no password: atmoz/sftp's create-sftp-user sets
        # the account's password hash to `*` when the password field is
        # empty (verified directly), which can never match any input --
        # password auth is unmatchable, not just "not offered". Key-only,
        # by request: no bootstrap password exists at any point, so a
        # tenant has no SFTP access at all until an operator installs a
        # public key via set_ssh_public_key.
        command=[f"{sftp_user}:"],
        ports={"22/tcp": ssh_port},
        mem_limit=SFTP_MEM_LIMIT,
        nano_cpus=SFTP_NANO_CPUS,
        volumes={
            webroot_volume: {"bind": f"/home/{sftp_user}/www", "mode": "rw"},
            keys_volume: {"bind": f"/home/{sftp_user}/.ssh/keys", "mode": "ro"},
            logs_volume: {"bind": "/var/log/vhsp", "mode": "rw"},
        },
        labels={
            "vhsp.tenant.slug": slug,
        },
    )
    return container_name, keys_volume, keys_host_path


def _generate_mail_credentials() -> tuple[str, str]:
    """MAIL_DEFAULT_USER ("postmaster") is the RFC 5321-mandated address
    every domain must accept -- doubles as the tenant's one starter
    mailbox, seeded into mailboxes.txt (see _create_mail_container) at
    provisioning time. Self-service mailbox management beyond this one
    starter account lives in images/tenant-admin/'s Email page."""
    return MAIL_DEFAULT_USER, secrets.token_urlsafe(24)


def _hash_mail_password(password: str) -> str:
    """SHA-512-crypt ($6$...), the exact scheme images/mail/'s dovecot.conf
    passdb declares (`scheme=SHA512-CRYPT`). Shelled out to openssl rather
    than reimplemented in Python -- same reasoning as
    _fingerprint_public_key's use of ssh-keygen: it's the actual authority
    on the format the consuming system (dovecot, via libc crypt()) will
    later need to match. -stdin avoids the password ever appearing in this
    process's argv (briefly visible to anything reading /proc or `ps` on
    this host otherwise).
    """
    result = subprocess.run(
        ["openssl", "passwd", "-6", "-stdin"],
        input=password, capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def _create_mail_container(
    client: docker.DockerClient,
    slug: str,
    domain: str,
    mail_user: str,
    mail_password: str,
    logs_volume: str,
    phpconf_volume: str,
    phpconf_host_path: str,
    mail_volume: str | None = None,
    mail_host_path: str | None = None,
) -> tuple[str, str, str, str]:
    """Per-tenant mail container (hand-rolled Postfix+Dovecot -- see
    images/mail/). Joins the shared gateway network only, same as the web
    container: the inbound SMTP gateway relays to it there, and Traefik
    reaches it there for SNI-routed IMAPS/SMTPS (architecture.md: these
    protocols carry the tenant hostname in the TLS ClientHello, unlike
    inbound SMTP on port 25, so Traefik's existing TCP router can route
    them directly with no mail-aware proxy involved).

    Deliberately NOT joined to the tenant's private db_network -- mail has
    no need to reach the tenant's DB, consistent with only putting
    containers on networks they genuinely need per the doc's isolation
    model. Maildir volume gets the same noexec/nosuid/nodev hardening as
    every other tenant data volume.

    Seeds phpconf's mailboxes.txt with the one starter mailbox (postmaster)
    before the container ever starts, rather than having the container's
    own entrypoint do it from MAIL_USER/MAIL_PASSWORD env vars the way it
    used to -- this makes the file the single source of truth for every
    mailbox from the very first boot, including postmaster, instead of
    postmaster being a special env-var-driven case layered underneath
    whatever the tenant-admin Email page later manages. Mounted read-only
    here: this container only ever reads it, images/tenant-admin/ is what
    writes it (same split as every other self-service toggle).

    Given a network alias equal to the bare domain (e.g. "example.com",
    not "mail.example.com") on GATEWAY_NETWORK, on top of the usual
    container-name DNS entry -- this is what lets the shared Roundcube
    container resolve each tenant's IMAP/SMTP server via its own plain
    %d host templating (`ssl://%d`) with zero custom code, instead of
    depending on public DNS + hairpinning back through the firewall
    (fragile, and doesn't even work today for tenants with no public mail
    routing set up). run()'s simple network= kwarg has no way to pass
    aliases, so this connects to GATEWAY_NETWORK at creation (default
    alias only) and then disconnects/reconnects that same network with
    the real alias -- NOT network_mode="none" followed by a first-ever
    .connect() the way this used to work: verified directly that this
    Docker Engine now rejects that specific pattern ("container cannot be
    connected to multiple networks with one of the networks in private
    (none) mode"), even though nothing here ever asked for a second
    network -- a none-mode container apparently can't be connected to
    anything real at all on this engine version. Re-attaching an
    already-attached network with a new alias is allowed; attaching any
    network at all to a none-mode container is not.

    Pass an existing mail_volume/mail_host_path (matching
    _create_sftp_container's own keys_volume=None precedent) to reuse an
    already-populated volume instead of creating a fresh empty one --
    backup.py's restore path needs this, since it has to extract a
    backed-up maildir into the host path *before* this container's own
    entrypoint runs and chowns everything to its internal vmail uid,
    which would otherwise lock the control plane's own unprivileged
    process out of writing there afterward (verified: this is exactly
    the same class of "container chowns its data dir on startup" gotcha
    _remove_host_dir's docstring already flags for the DB directory).
    """
    if mail_volume is None:
        mail_volume, mail_host_path = _create_hardened_volume(client, slug, "mail")
    volume_name, host_path = mail_volume, mail_host_path
    mail_hostname = f"mail.{domain}"

    # Own hardened volume, not a subdirectory of mail_volume: that one is
    # /var/mail/vhosts, which the container's entrypoint chowns entirely to
    # its internal vmail uid on every start (see _relocate_mail_domain_dir's
    # docstring) -- key material has no reason to live inside a tree that
    # gets recursively re-owned like that. Not tracked in the registry
    # (unlike mail_volume/mail_host_path) since nothing outside this
    # function needs to look it up later -- the volume NAME alone
    # (deterministic from slug) is enough for _create_hardened_volume to
    # find and reuse it on every future recreation, same as how
    # _ensure_mail_gateway re-finds the gateway container by name.
    dkim_volume, _dkim_host_path = _create_hardened_volume(client, slug, "dkim")

    mailboxes_file = Path(phpconf_host_path) / "mailboxes.txt"
    if not mailboxes_file.exists():
        # Trailing empty third field = no per-mailbox quota (unlimited) --
        # see toggles.py's read/write_mailboxes for the username:hash:quota_bytes format.
        mailboxes_file.write_text(f"{mail_user}:{_hash_mail_password(mail_password)}:\n")

    container_name = f"vhsp-{slug}-mail"
    router_id = f"vhsp-{slug}-mail"
    container = client.containers.run(
        MAIL_IMAGE,
        name=container_name,
        detach=True,
        restart_policy={"Name": "unless-stopped"},
        network=GATEWAY_NETWORK,
        mem_limit=MAIL_MEM_LIMIT,
        nano_cpus=MAIL_NANO_CPUS,
        environment={
            "MAIL_DOMAIN": domain,
            "DKIM_SELECTOR": DKIM_SELECTOR,
        },
        volumes={
            volume_name: {"bind": "/var/mail/vhosts", "mode": "rw"},
            logs_volume: {"bind": "/var/log/vhsp", "mode": "rw"},
            phpconf_volume: {"bind": "/data", "mode": "ro"},
            dkim_volume: {"bind": "/etc/opendkim/keys", "mode": "rw"},
        },
        labels={
            "traefik.enable": "true",
            # Explicit `.service=` on each router is required, not optional,
            # once a single container defines more than one TCP router --
            # verified Traefik silently drops BOTH routers ("cannot be
            # linked automatically with multiple Services") when it has to
            # guess which of two same-container services a router should
            # use, rather than picking one or erroring loudly.
            f"traefik.tcp.routers.{router_id}-imaps.rule": f"HostSNI(`{mail_hostname}`)",
            f"traefik.tcp.routers.{router_id}-imaps.entrypoints": "imaps",
            f"traefik.tcp.routers.{router_id}-imaps.tls.passthrough": "true",
            f"traefik.tcp.routers.{router_id}-imaps.service": f"{router_id}-imaps",
            f"traefik.tcp.services.{router_id}-imaps.loadbalancer.server.port": str(MAIL_IMAPS_PORT),
            f"traefik.tcp.routers.{router_id}-smtps.rule": f"HostSNI(`{mail_hostname}`)",
            f"traefik.tcp.routers.{router_id}-smtps.entrypoints": "smtps",
            f"traefik.tcp.routers.{router_id}-smtps.tls.passthrough": "true",
            f"traefik.tcp.routers.{router_id}-smtps.service": f"{router_id}-smtps",
            f"traefik.tcp.services.{router_id}-smtps.loadbalancer.server.port": str(MAIL_SMTPS_PORT),
            "vhsp.tenant.slug": slug,
            "vhsp.tenant.domain": domain,
        },
    )
    gateway_net = client.networks.get(GATEWAY_NETWORK)
    gateway_net.disconnect(container)
    gateway_net.connect(container, aliases=[domain])

    _write_dns_records_status(client, domain, container_name, mail_hostname, phpconf_host_path)
    return container_name, volume_name, host_path, mail_hostname


def _write_dns_records_status(
    client: docker.DockerClient, domain: str, mail_container: str, mail_hostname: str, phpconf_host_path: str,
) -> None:
    """Writes dns_records.json onto the tenant's own phpconf volume so
    images/tenant-admin/'s Email page can display the suggested DNS
    records read-only, the same "host computes it, container just reads
    the file" split as backup.py's _write_backup_status. Best-effort: the
    container's own entrypoint generates the DKIM keypair asynchronously
    on first boot (opendkim-genkey takes a couple seconds), so this polls
    briefly for that file to appear rather than failing provisioning
    outright if DNS records aren't visible for a few seconds after
    tenant creation -- a missing/stale dns_records.json just means the
    Email page's DNS section is briefly empty, never something that
    should block or fail tenant creation itself.
    """
    deadline = time.time() + 30
    dkim_path = f"/etc/opendkim/keys/{domain}/{DKIM_SELECTOR}.txt"
    while time.time() < deadline:
        exit_code, _ = client.containers.get(mail_container).exec_run(["test", "-f", dkim_path])
        if exit_code == 0:
            break
        time.sleep(1)
    else:
        return

    try:
        records = dns_records.compute_records(client, domain, mail_container, mail_hostname)
    except dns_records.DnsRecordsError:
        return
    (Path(phpconf_host_path) / "dns_records.json").write_text(dns_records.records_as_json(records))


def _create_tenant_admin_container(
    client: docker.DockerClient,
    slug: str,
    domain: str,
    phpconf_volume: str,
    phpconf_host_path: str,
    logs_volume: str,
    webroot_volume: str,
    db_network: str,
    db_container: str,
    db_name: str,
    db_user: str,
    db_password: str,
    mail_volume: str,
    ssh_port: int,
    sftp_user: str,
) -> tuple[str, str, str]:
    """Per-tenant self-service admin page (hand-rolled Flask -- see
    images/tenant-admin/). Toggles PHP functions, the 404-fallback
    front-controller behavior, password protection, error pages,
    redirects, IP restrictions, and mailboxes; also a web/mail/sftp log
    viewer.

    Routed through Traefik on TWO entrypoints: TENANT_ADMIN_ENTRYPOINT
    (bound only to the management interface, see the KVM/Traefik setup
    notes) for direct on-network access, and the public `web` entrypoint
    for real internet reachability via the swarm's Traefik + Let's
    Encrypt (needed for WebAuthn's secure-context requirement -- per the
    user's own choice to go public now rather than wait for WebAuthn to
    land first). Both point at admin.<domain>; login (see app.py) is now
    the actual access control for the public path, not network position.

    Form-based login, not HTTP Basic -- the user's own requirement, to
    leave room for a 2FA step between password and session
    establishment later (see app.py). Credential generated here, once,
    before the container ever starts (same "provisioner seeds the file,
    the container's own code only ever reads/consumes it" pattern as
    mailboxes.txt in _create_mail_container) -- stored hashed
    (admin_credentials.json in phpconf, matching auth.py's own
    operator-credential format exactly) and in the registry, encrypted at
    rest (registry.py's secretbox-backed columns), so `vhsp tenant show`
    can still display it back on request without it being a second
    plaintext copy sitting next to the hashed one.

    Shares phpconf_volume with the web container: this container writes
    the tenant's enabled-function list, the web container's own entrypoint
    watches it and reloads PHP-FPM -- see images/web/entrypoint.sh's
    docstring for why it's built this way (no docker.sock, no signal
    across containers, nothing that isn't "write a file to a volume both
    containers already have mounted"). Mounts logs_volume read-only for
    the same reason: the web/mail/sftp containers are the ones that write
    to it, this container only ever reads.

    Also mounts webroot_volume read-write, for the 404-fallback toggle --
    it just creates/removes a marker file nginx checks directly (see
    nginx.conf), no watcher/reload involved. Read-write here isn't a new
    privilege boundary: the tenant already has full read-write access to
    this exact same volume via their own SFTP container.

    Joins the tenant's private db_network too (previously only the web
    container did) and gets the same DB_HOST/DB_NAME/DB_USER/DB_PASSWORD
    env vars the web container already has, for the Database page's SQL
    console. Deliberately the same non-root credential the tenant's own
    app already connects with, not db_root_password -- whatever the
    console can do is exactly what the tenant's own code could always do,
    no more. The real access boundary is MariaDB's own per-database
    grant on that user (already scoped to just this tenant's database at
    container creation), not anything enforced in this Flask app -- same
    "trust the underlying system's own guarantees" reasoning as the rest
    of this codebase.

    Also mounts mail_volume read-only, purely so the Database/quota
    display can `du` it directly for the mail half of the combined
    web+db+mail soft quota (see get_tenant_disk_usage) -- this container
    never writes mail data, images/mail/'s own entrypoint owns that.
    """
    admin_hostname = f"admin.{domain}"
    admin_password = secrets.token_urlsafe(18)
    # tenant_users.json -- images/tenant-admin/app.py's multi-user store
    # (one tenant-admin login per team member, not just a single shared
    # "admin" account). Seeded directly in that format here since this is
    # a brand-new tenant; only already-provisioned tenants from before
    # multi-user support go through that file's own lazy migration from
    # the old single-credential admin_credentials.json.
    #
    # Checks BOTH the new and legacy filenames for "already provisioned" --
    # checking only tenant_users.json would look unprovisioned for every
    # already-existing tenant (which only ever has the legacy file until
    # its own tenant-admin container's first request lazily migrates it),
    # silently generating and discarding a fresh password on every
    # container recreate (verified this actually happening: recreate_tenant_admin.py
    # generated a brand-new tenant_users.json with a real tenant's
    # existing password thrown away, breaking their login, before this
    # check was fixed).
    users_file = Path(phpconf_host_path) / "tenant_users.json"
    legacy_creds_file = Path(phpconf_host_path) / "admin_credentials.json"
    if not users_file.exists() and not legacy_creds_file.exists():
        users_file.write_text(json.dumps({
            "admin": {
                "password_hash": generate_password_hash(admin_password),
                "created_at": datetime.now(timezone.utc).isoformat(),
                # First-ever user on a brand-new tenant, so it has to be
                # owner -- otherwise nothing could reach the owner-only
                # surfaces (Team, restore, SQL console) without the
                # operator's own tenant_set_admin_password recovery lever.
                "role": "owner",
            }
        }))
    else:
        admin_password = ""  # already provisioned, don't overwrite or re-display

    container_name = f"vhsp-{slug}-tenant-admin"
    router_id = f"vhsp-{slug}-tenant-admin"
    container = client.containers.run(
        TENANT_ADMIN_IMAGE,
        name=container_name,
        detach=True,
        restart_policy={"Name": "unless-stopped"},
        network=GATEWAY_NETWORK,
        mem_limit=TENANT_ADMIN_MEM_LIMIT,
        nano_cpus=TENANT_ADMIN_NANO_CPUS,
        environment={
            "TENANT_DOMAIN": domain,
            "DB_HOST": db_container,
            "DB_PORT": str(DB_INTERNAL_PORT),
            "DB_NAME": db_name,
            "DB_USER": db_user,
            "DB_PASSWORD": db_password,
            # For the Overview page's SFTP connect line -- this container
            # has no registry access, same reasoning as every other env
            # var here.
            "SSH_PORT": str(ssh_port),
            "SFTP_USER": sftp_user,
            # This container always runs as root (no USER in its Dockerfile),
            # so a handful of 0600 credential files it writes on the phpconf
            # bind mount (webauthn/TOTP/tenant_users/login_attempts state --
            # see app.py's own _chown_to_host docstring) would otherwise end
            # up owned by root on the host, unreadable by whatever OS user
            # runs vhsp-admin.service, the moment this container is the one
            # that (re)writes them. Passing this process's own real UID/GID
            # through lets app.py chown those files back after writing them,
            # so the host-side code in this module that reads a couple of
            # them directly (count_tenant_webauthn_keys,
            # reset_tenant_admin_password) keeps working no matter which
            # side wrote the file most recently.
            "VHSP_HOST_UID": str(os.getuid()),
            "VHSP_HOST_GID": str(os.getgid()),
            # Whether the mgmtweb-entrypoint router below is actually
            # reachable over plain HTTP on this deployment (a real
            # interface Traefik binds it to) or just an inert router
            # object Traefik never matches (vhsp2's single-public-IP
            # setup -- see config.py's own docstring). Determines whether
            # this container's session cookie can safely be marked
            # Secure: True is wrong wherever the mgmtweb path is real,
            # since that traffic is plain HTTP by design.
            "TENANT_ADMIN_MGMTWEB_EXISTS": "1" if TENANT_ADMIN_MGMTWEB_EXISTS else "0",
            # The tenant-scoped REST API/MCP surface (vhsp_ctl/api.py's
            # /self/* routes, mcp_server.py's self_* tools) lives on the
            # SAME shared host the operator admin UI does, not this
            # tenant's own subdomain -- this container has no other way
            # to know that hostname. Used only for the example curl
            # command shown on the API & MCP access page's token-minting
            # panel -- found missing during a real usability pass (a
            # tester guessed their own subdomain first and got it wrong).
            "PLATFORM_API_HOST": ADMIN_RP_ID,
        },
        volumes={
            phpconf_volume: {"bind": "/data", "mode": "rw"},
            logs_volume: {"bind": "/logs", "mode": "ro"},
            webroot_volume: {"bind": "/webroot", "mode": "rw"},
            mail_volume: {"bind": "/mail", "mode": "ro"},
        },
        labels={
            "traefik.enable": "true",
            f"traefik.http.routers.{router_id}.rule": f"Host(`{admin_hostname}`)",
            f"traefik.http.routers.{router_id}.entrypoints": TENANT_ADMIN_ENTRYPOINT,
            f"traefik.http.routers.{router_id}.service": router_id,
            f"traefik.http.services.{router_id}.loadbalancer.server.port": "80",
            # Second router, same service, on the public "web" entrypoint --
            # per the user's explicit choice to make the admin panels
            # publicly reachable now (real TLS via the swarm's Traefik +
            # Let's Encrypt, needed for WebAuthn's secure-context
            # requirement) rather than staying mgmt-network-only until
            # WebAuthn lands. The mgmtweb router above is untouched -- this
            # adds a path, it doesn't replace the existing one. Explicit
            # `.service=` on both is required, not optional, once a
            # container has more than one router (verified elsewhere in
            # this codebase already -- Traefik silently drops routers it
            # can't disambiguate otherwise).
            f"traefik.http.routers.{router_id}-public.rule": f"Host(`{admin_hostname}`)",
            f"traefik.http.routers.{router_id}-public.entrypoints": "web",
            f"traefik.http.routers.{router_id}-public.service": router_id,
            **_tls_labels(f"{router_id}-public", should_request_cert_for(admin_hostname)),
            "vhsp.tenant.slug": slug,
            "vhsp.tenant.domain": domain,
        },
    )
    # Second network joined post-create, same reason as the web
    # container's own identical db_network.connect() call: docker-py's
    # network= kwarg on run() only accepts one network at create time.
    client.networks.get(db_network).connect(container)
    return container_name, admin_hostname, admin_password


def _ensure_mail_gateway(client: docker.DockerClient) -> None:
    """Idempotently ensure the single shared inbound SMTP gateway is
    running. Not per-tenant -- architecture.md's diagram shows this as one
    shared front door alongside Traefik, not something each tenant gets
    its own copy of."""
    try:
        client.containers.get(MAILGW_CONTAINER)
        return
    except NotFound:
        pass

    MAILGW_MAPS_DIR.mkdir(parents=True, exist_ok=True)
    for name in ("relay_domains", "transport"):
        f = MAILGW_MAPS_DIR / name
        if not f.exists():
            f.write_text("")

    client.containers.run(
        MAILGW_IMAGE,
        name=MAILGW_CONTAINER,
        detach=True,
        restart_policy={"Name": "unless-stopped"},
        network=GATEWAY_NETWORK,
        ports={"25/tcp": 25},
        environment={"GATEWAY_HOSTNAME": MAILGW_HOSTNAME},
        volumes={str(MAILGW_MAPS_DIR): {"bind": "/etc/postfix/maps", "mode": "rw"}},
        labels={"vhsp.role": "mail-gateway"},
    )


def _regenerate_mail_gateway_maps(client: docker.DockerClient) -> None:
    """Rebuild the gateway's relay_domains/transport_maps from every active
    tenant and reload Postfix. `[container]:25` (brackets) is deliberate,
    not decorative -- verified Postfix's default nexthop resolution tries
    an MX lookup first, and Docker's embedded DNS returns a retryable
    error (not a clean "no MX") for MX queries on container names, so mail
    sits queued forever with "Name service error" unless MX lookup is
    disabled via bracket notation."""
    tenants = registry.list_tenants()
    relay_lines = [f"{t.domain} OK\n" for t in tenants]
    transport_lines = [f"{t.domain} smtp:[{t.mail_container}]:25\n" for t in tenants]

    (MAILGW_MAPS_DIR / "relay_domains").write_text("".join(relay_lines))
    (MAILGW_MAPS_DIR / "transport").write_text("".join(transport_lines))


ROUNDCUBE_EXTRA_CONFIG = """<?php
// Auto-included by the official image's entrypoint (anything dropped in
// /var/roundcube/config/*.php).

// tls://, not ssl://: images/mail/'s ManageSieve service only ever does
// RFC 5804 STARTTLS on 4190, there's no separate implicit-TLS port for it
// the way IMAP/SMTP have -- see entrypoint.sh's comment on that. %d
// resolves the same way imap_host/smtp_host already do: the domain part
// of whatever the user logged in with.
$config['managesieve_host'] = 'tls://%d:4190';

// Each tenant's mail container is reached here via a network alias equal
// to its bare domain (see _create_mail_container), not the "mail.<domain>"
// name its self-signed cert's CN actually says -- verified this makes
// PHP's default strict TLS peer-name verification reject the connection
// ("Could not connect ... Unknown reason"). Fixing the cert instead would
// mean regenerating every tenant's mail container again for a cert that's
// self-signed either way -- no real trust anchor to verify against
// regardless of which hostname is on it, and this connection never
// leaves the internal Docker network. Applies to IMAP/SMTP; managesieve
// gets the same treatment via its own separate connection-options key.
$conn_options = ['ssl' => ['verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true]];
$config['imap_conn_options'] = $conn_options;
$config['smtp_conn_options'] = $conn_options;
$config['managesieve_conn_options'] = $conn_options;
"""


def _regenerate_roundcube_routes(client: docker.DockerClient) -> None:
    """Recreates the one shared Roundcube container with a fresh Traefik
    router for every active tenant's webmail.<domain>.

    Docker labels are fixed at container-create time, and this VM's
    Traefik only has the docker-label provider (no file provider the way
    the swarm's Traefik does) -- so a tenant being created or destroyed
    means the shared container has to be recreated with an updated label
    set, not just a file rewrite + reload the way mailgw's own regenerate
    works above. Deliberately not given its own dedicated per-tenant
    volume/network isolation the way web/mail/db are: it holds no tenant
    data of its own, just its own small address-book/prefs DB (SQLite),
    shared across every tenant's users the same way the DB engine itself
    is shared infrastructure a tenant's mail depends on without owning.

    ONE shared `roundcube` service definition, referenced explicitly via
    `.service=` on every per-tenant router -- same "must be explicit once
    a container has more than one router" gotcha _create_mail_container's
    IMAPS/SMTPS routers already hit (Traefik silently drops routers it
    can't disambiguate otherwise), verified to matter here too.

    Host resolution for IMAP/SMTP relies on `ssl://%d` (Roundcube's own
    built-in template for "domain part of the login") resolving via the
    network alias _create_mail_container gives each tenant's mail
    container -- not public DNS, which would depend on whatever's
    actually forwarded through the firewall for a given tenant and
    wouldn't work for the private/dev-only *.vhsp.dvce.us tenants at all.
    """
    config_dir = ROUNDCUBE_DATA_DIR / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "vhsp.php").write_text(ROUNDCUBE_EXTRA_CONFIG)
    db_dir = ROUNDCUBE_DATA_DIR / "db"
    db_dir.mkdir(parents=True, exist_ok=True)

    try:
        client.containers.get(ROUNDCUBE_CONTAINER).remove(force=True)
    except NotFound:
        pass

    labels = {
        "traefik.enable": "true",
        "traefik.http.services.roundcube.loadbalancer.server.port": "80",
        "vhsp.role": "roundcube",
    }
    for t in registry.list_tenants():
        router_id = f"webmail-{t.slug}"
        labels[f"traefik.http.routers.{router_id}.rule"] = f"Host(`webmail.{t.domain}`)"
        labels[f"traefik.http.routers.{router_id}.entrypoints"] = "web"
        labels[f"traefik.http.routers.{router_id}.service"] = "roundcube"
        # Per-tenant, for the same reason the tenant's own routers get this
        # treatment: without it these inherit the `web` entrypoint's
        # certresolver and every tenant creation orders a webmail
        # certificate that fails while DNS still points elsewhere. Found by
        # running the prevention change end-to-end -- the apex and admin
        # hostnames were silent, and webmail.<domain> still burned one
        # validation per tenant created.
        #
        # Decided per router rather than for the container as a whole: this
        # one container carries every tenant's webmail route, so tenants
        # whose DNS is ready keep their real certificates while a new one
        # waits on the fallback.
        labels.update(_tls_labels(router_id, should_request_cert_for(f"webmail.{t.domain}")))

    client.containers.run(
        ROUNDCUBE_IMAGE,
        name=ROUNDCUBE_CONTAINER,
        detach=True,
        restart_policy={"Name": "unless-stopped"},
        network=GATEWAY_NETWORK,
        environment={
            "ROUNDCUBEMAIL_DB_TYPE": "sqlite",
            "ROUNDCUBEMAIL_DEFAULT_HOST": "ssl://%d",
            "ROUNDCUBEMAIL_DEFAULT_PORT": "993",
            "ROUNDCUBEMAIL_SMTP_SERVER": "ssl://%d",
            "ROUNDCUBEMAIL_SMTP_PORT": "465",
            "ROUNDCUBEMAIL_PLUGINS": "managesieve",
        },
        volumes={
            str(db_dir): {"bind": "/var/roundcube/db", "mode": "rw"},
            str(config_dir): {"bind": "/var/roundcube/config", "mode": "ro"},
        },
        labels=labels,
    )

    gw = client.containers.get(MAILGW_CONTAINER)
    gw.exec_run(["postmap", "/etc/postfix/maps/relay_domains", "/etc/postfix/maps/transport"])
    gw.exec_run(["postfix", "reload"])


def _write_placeholder_index(host_path: str, domain: str) -> None:
    index = f"{host_path}/index.html"
    with open(index, "w") as f:
        f.write(f"<html><body><h1>{domain}</h1><p>Provisioned by VHSP control plane.</p></body></html>\n")


def _export_routing_table() -> None:
    """Domain -> container routing table, consumed later by the SMTP
    gateway's transport_maps generation. HTTP routing itself doesn't need
    this -- Traefik discovers containers via labels directly -- but the
    mail gateway has no equivalent auto-discovery, per architecture.md."""
    tenants = registry.list_tenants()
    table = {
        t.domain: {
            "web_container": t.web_container,
            "ssh_port": t.ssh_port,
            "mail_container": t.mail_container,
            "mail_hostname": t.mail_hostname,
        }
        for t in tenants
    }
    ROUTING_TABLE_PATH.parent.mkdir(parents=True, exist_ok=True)
    ROUTING_TABLE_PATH.write_text(json.dumps(table, indent=2) + "\n")


def create_tenant(domain: str, actor: str = "cli") -> registry.Tenant:
    if registry.get_tenant(domain):
        raise ProvisioningError(f"tenant for domain {domain!r} already exists")

    slug = slugify(domain)
    client = _client()
    _ensure_gateway_network(client)

    ssh_port = _allocate_ssh_port()
    volume_name, host_path = _create_hardened_volume(client, slug, "webroot")
    db_network = _create_db_network(client, slug)

    db_name, db_user, db_password, db_root_password = _generate_db_credentials(slug)
    db_container_name, db_volume_name, db_host_path = _create_db_container(
        client, slug, db_network, db_name, db_user, db_password, db_root_password
    )

    _write_placeholder_index(host_path, domain)

    phpconf_volume, phpconf_host_path = _create_hardened_volume(client, slug, "phpconf")
    logs_volume, logs_host_path = _create_hardened_volume(client, slug, "logs")

    (Path(phpconf_host_path) / "quota_limit_bytes.txt").write_text(str(DEFAULT_TENANT_QUOTA_BYTES))

    # Secure-by-default upload-directory code-execution block (see
    # images/web/entrypoint.sh's write_tenant_nginx_conf) -- seeded here
    # rather than left empty so a fresh tenant is covered before they've
    # ever touched the self-service page, not just after. Uses
    # write_lines_file's own validator rather than writing the file
    # directly so this seed data is held to the exact same rules a tenant
    # editing it later would be.
    toggles.write_lines_file(
        Path(phpconf_host_path), "noexec_dirs.txt",
        "\n".join(toggles.DEFAULT_NOEXEC_DIRS), toggles.validate_noexec_dir_line,
    )

    container_name = _create_web_container(
        client, slug, domain, volume_name, phpconf_volume, logs_volume,
        db_network, db_container_name, db_name, db_user, db_password,
    )
    # Each router decides for itself -- see should_request_cert_for. A
    # tenant who never creates a www record still gets a real certificate
    # on their apex; the reconciler picks up whatever is still waiting.
    waf_container_name = _create_waf_container(client, slug, domain, phpconf_host_path)

    sftp_user = _generate_sftp_user(slug)
    sftp_container_name, ssh_keys_volume, ssh_keys_host_path = _create_sftp_container(
        client, slug, ssh_port, volume_name, sftp_user, logs_volume
    )

    mail_user, mail_password = _generate_mail_credentials()
    mail_container_name, mail_volume, mail_host_path, mail_hostname = _create_mail_container(
        client, slug, domain, mail_user, mail_password, logs_volume, phpconf_volume, phpconf_host_path
    )

    tenant_admin_container, admin_hostname, tenant_admin_password = _create_tenant_admin_container(
        client, slug, domain, phpconf_volume, phpconf_host_path, logs_volume, volume_name,
        db_network, db_container_name, db_name, db_user, db_password, mail_volume,
        ssh_port, sftp_user,
    )

    tenant = registry.Tenant(
        slug=slug,
        domain=domain,
        ssh_port=ssh_port,
        web_container=container_name,
        waf_container=waf_container_name,
        db_network=db_network,
        webroot_volume=volume_name,
        webroot_host_path=host_path,
        db_container=db_container_name,
        db_volume=db_volume_name,
        db_host_path=db_host_path,
        db_name=db_name,
        db_user=db_user,
        db_password=db_password,
        db_root_password=db_root_password,
        sftp_container=sftp_container_name,
        sftp_user=sftp_user,
        ssh_keys_volume=ssh_keys_volume,
        ssh_keys_host_path=ssh_keys_host_path,
        mail_container=mail_container_name,
        mail_volume=mail_volume,
        mail_host_path=mail_host_path,
        mail_hostname=mail_hostname,
        mail_user=mail_user,
        mail_password=mail_password,
        tenant_admin_container=tenant_admin_container,
        phpconf_volume=phpconf_volume,
        phpconf_host_path=phpconf_host_path,
        admin_hostname=admin_hostname,
        logs_volume=logs_volume,
        logs_host_path=logs_host_path,
        tenant_admin_password=tenant_admin_password,
        status="active",
        created_at=registry.now(),
    )
    registry.add_tenant(tenant)
    _export_routing_table()

    _ensure_mail_gateway(client)
    _regenerate_mail_gateway_maps(client)
    _regenerate_roundcube_routes(client)

    # Per-tenant SFTP fail2ban jail -- genuinely isolated per tenant
    # (distinct port, unlike the shared HTTP-layer jails), so this is
    # generated fresh for every new tenant rather than being one static
    # config. See deploy/vhsp-fail2ban-tenant-jail's own header comment.
    _run("sudo", "/usr/local/sbin/vhsp-fail2ban-tenant-jail", slug, str(ssh_port), "install")

    audit.log_action("tenant.create", domain, actor)
    return tenant


def destroy_tenant(domain: str, actor: str = "cli") -> None:
    tenant = registry.get_tenant(domain)
    if not tenant:
        raise ProvisioningError(f"no active tenant for domain {domain!r}")

    client = _client()

    # Unregister this tenant's SFTP fail2ban jail before tearing down
    # the log file/directory it watches -- deliberately first, not last,
    # so fail2ban stops referencing paths that are about to disappear.
    _run("sudo", "/usr/local/sbin/vhsp-fail2ban-tenant-jail", tenant.slug, str(tenant.ssh_port), "remove")

    try:
        client.containers.get(tenant.waf_container).remove(force=True)
    except NotFound:
        pass

    try:
        container = client.containers.get(tenant.web_container)
        container.remove(force=True)
    except NotFound:
        pass

    try:
        client.containers.get(tenant.sftp_container).remove(force=True)
    except NotFound:
        pass

    try:
        client.containers.get(tenant.db_container).remove(force=True)
    except NotFound:
        pass

    try:
        client.containers.get(tenant.mail_container).remove(force=True)
    except NotFound:
        pass

    try:
        client.containers.get(tenant.tenant_admin_container).remove(force=True)
    except NotFound:
        pass

    try:
        client.volumes.get(tenant.webroot_volume).remove()
    except NotFound:
        pass

    try:
        client.volumes.get(tenant.db_volume).remove()
    except NotFound:
        pass

    try:
        client.volumes.get(tenant.ssh_keys_volume).remove()
    except NotFound:
        pass

    try:
        client.volumes.get(tenant.mail_volume).remove()
    except NotFound:
        pass

    try:
        client.volumes.get(tenant.phpconf_volume).remove()
    except NotFound:
        pass

    try:
        client.volumes.get(tenant.logs_volume).remove()
    except NotFound:
        pass

    # No tenant.dkim_volume/dkim_host_path field -- _create_mail_container's
    # own docstring on the dkim volume explains why it was never added to
    # the registry: the name is deterministic from slug alone
    # (_create_hardened_volume's own f"vhsp-{slug}-{purpose}" / TENANTS_DIR
    # / slug / purpose convention), so nothing needed to look it up to
    # reuse it. That reasoning covered recreation but not destroy -- a real
    # leak found and fixed 2026-07-24 (see the control-plane README's
    # "Restore verified end-to-end" section): every tenant destroyed
    # before this fix left its dkim volume and host directory behind
    # forever, silently. Computed here the same deterministic way rather
    # than adding a registry column for a value that never needed one.
    try:
        client.volumes.get(f"vhsp-{tenant.slug}-dkim").remove()
    except NotFound:
        pass

    _remove_host_dir(tenant.webroot_host_path)
    _remove_host_dir(tenant.db_host_path)
    _remove_host_dir(tenant.ssh_keys_host_path)
    _remove_host_dir(tenant.mail_host_path)
    _remove_host_dir(tenant.phpconf_host_path)
    _remove_host_dir(tenant.logs_host_path)
    _remove_host_dir(str(TENANTS_DIR / tenant.slug / "dkim"))

    try:
        client.networks.get(tenant.db_network).remove()
    except NotFound:
        pass

    registry.mark_destroyed(domain)
    _export_routing_table()

    try:
        _ensure_mail_gateway(client)
        _regenerate_mail_gateway_maps(client)
    except NotFound:
        pass  # gateway was never created (no tenants ever provisioned)

    _regenerate_roundcube_routes(client)

    audit.log_action("tenant.destroy", domain, actor)


def _fingerprint_public_key(public_key: str) -> str:
    """Validate `public_key` is a well-formed SSH public key and return its
    fingerprint, via ssh-keygen rather than hand-rolled parsing -- it's the
    thing that actually has to accept the key later, so it's the right
    authority on whether the key is valid."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pub") as f:
        f.write(public_key.strip() + "\n")
        f.flush()
        result = subprocess.run(
            ["ssh-keygen", "-l", "-f", f.name],
            capture_output=True, text=True,
        )
    if result.returncode != 0:
        raise ProvisioningError(f"not a valid SSH public key: {result.stderr.strip()}")
    return result.stdout.strip()


def set_ssh_public_key(domain: str, public_key: str, actor: str = "cli") -> str:
    """Install an operator-supplied public key for the tenant's SFTP
    container, replacing any previously-set key (single operator-managed
    key for now -- no self-service/multi-key support yet). Returns the
    key's fingerprint.

    A plain restart is NOT enough to pick this up -- verified empirically:
    atmoz/sftp's entrypoint only builds ~/.ssh/authorized_keys from the
    keys/ directory on the user's *first-ever* boot (gated on user/home
    creation); a `docker restart` with the new key already on disk skips
    straight to launching sshd and authorized_keys stays exactly as it was
    (in one test, empty). The container has to be recreated so the
    entrypoint's user-bootstrap step runs again. Safe to do: it's
    stateless SFTP-only, no in-flight shell sessions, and all real tenant
    data lives in the separately-mounted webroot volume, not the
    container's own writable layer -- recreation only costs a fresh SSH
    host key (client-visible "host key changed" warning) and a momentary
    port gap.
    """
    tenant = registry.get_tenant(domain)
    if not tenant:
        raise ProvisioningError(f"no active tenant for domain {domain!r}")

    fingerprint = _fingerprint_public_key(public_key)

    keys_dir = Path(tenant.ssh_keys_host_path)
    (keys_dir / "admin.pub").write_text(public_key.strip() + "\n")

    client = _client()
    try:
        client.containers.get(tenant.sftp_container).remove(force=True)
    except NotFound:
        pass
    _create_sftp_container(
        client, tenant.slug, tenant.ssh_port, tenant.webroot_volume,
        tenant.sftp_user, tenant.logs_volume, tenant.ssh_keys_volume,
    )

    registry.set_ssh_key(domain, public_key.strip(), fingerprint)
    audit.log_action("tenant.set_ssh_key", domain, actor)
    return fingerprint


def set_tenant_admin_password(domain: str, password: str | None = None, actor: str = "cli") -> str:
    """Resets the tenant-admin panel's original "admin" user's password
    and returns the value now in effect -- the operator's coarse recovery
    lever, unrelated to whatever additional team-member logins a tenant
    may have added themselves via images/tenant-admin/'s own self-service
    Team page (see that file's docstring: self-service stays local to
    the tenant's own container, this is deliberately NOT a full
    operator-visible roster of every login a tenant has).

    password=None (what the admin UI now always passes) GENERATES a
    random one and flags the account `must_change_password`, so the
    tenant is forced to replace it before they can use the panel at all.
    This inverts the module's original design, which took an
    operator-chosen value on the reasoning that "the operator has to be
    the one who knows it, not the system": an operator-chosen password is
    one the operator still knows afterwards, indefinitely, since nothing
    ever forced it to change. A generated single-use value the tenant
    must immediately replace means the operator only ever holds a
    credential that stops working the first time the tenant logs in.
    An explicit `password` is still accepted for the CLI/scripted path,
    and does NOT set the flag -- same behavior as before.

    What this does NOT do is stop an operator from resetting again later:
    root on the host owns every one of these files, so operator access is
    always recoverable by design. The property gained is narrower and
    real -- an operator cannot passively retain a working tenant password
    without the tenant seeing it get reset.

    Reads/writes tenant_users.json directly rather than going through
    images/tenant-admin/'s own module (this process has no import access
    to that container's code, same trust-boundary reasoning as every
    other cross-container duplication here) -- only ever touches the
    "admin" key, preserving any other team-member entries untouched.
    Creates the file fresh (just this one "admin" entry) if it doesn't
    exist yet, which converges correctly either way: images/tenant-admin/'s
    own lazy migration only runs when this file is ABSENT, so whichever
    of the two writes it first "wins" with the same end state.

    No container restart needed: images/tenant-admin/'s check_login()
    reads this file fresh on every login POST rather than caching it, so
    the new password is live immediately and any already-open session
    (a signed cookie, not a server-side session record) is unaffected --
    same standard behavior as most session-based logins, not a gap
    specific to this one.
    """
    tenant = registry.get_tenant(domain)
    if not tenant:
        raise ProvisioningError(f"no active tenant for domain {domain!r}")

    generated = password is None
    if generated:
        password = secrets.token_urlsafe(18)

    users_file = Path(tenant.phpconf_host_path) / "tenant_users.json"
    users = json.loads(users_file.read_text()) if users_file.exists() else {}
    created_at = users.get("admin", {}).get("created_at") or datetime.now(timezone.utc).isoformat()
    # Preserves "admin"'s existing role if it already has one (a tenant may
    # have since demoted it to member and promoted someone else to owner);
    # defaults to owner only for a truly fresh entry, matching
    # _create_tenant_admin_container's own seeding above.
    role = users.get("admin", {}).get("role", "owner")
    entry = {"password_hash": generate_password_hash(password), "created_at": created_at, "role": role}
    if generated:
        # images/tenant-admin/'s _require_password_change before_request
        # hook reads this and lets the account reach nothing but the
        # change-password page until it's cleared.
        entry["must_change_password"] = True
    users["admin"] = entry
    users_file.write_text(json.dumps(users))

    registry.set_tenant_admin_password(domain, password)
    audit.log_action("tenant.set_admin_password", domain, actor)
    return password


def _tenant_webauthn_file(domain: str) -> Path:
    tenant = registry.get_tenant(domain)
    if not tenant:
        raise ProvisioningError(f"no active tenant for domain {domain!r}")
    return Path(tenant.phpconf_host_path) / "webauthn_credentials.json"


def count_tenant_webauthn_keys(domain: str) -> int:
    """Read-only -- how many WebAuthn keys this tenant currently has
    registered, for display on the operator's tenant detail page. Never
    reads the actual credential data, just the list length."""
    creds_file = _tenant_webauthn_file(domain)
    if not creds_file.exists():
        return 0
    return len(json.loads(creds_file.read_text()))


_OPERATOR_ACCESS_FILENAME = ".vhsp-operator-access.json"
_OPERATOR_ACTOR_PREFIX = "operator:"


def _operator_access_path(domain: str) -> Path:
    tenant = registry.get_tenant(domain)
    if not tenant:
        raise ProvisioningError(f"no active tenant for domain {domain!r}")
    return Path(tenant.phpconf_host_path) / _OPERATOR_ACCESS_FILENAME


def operator_access_status(domain: str) -> dict:
    """Current temporary-operator-access state for this tenant, as plain
    data both admin UIs render. Never includes the token (only its hash
    is stored at all). `active` is computed against the clock on every
    read rather than persisted, so an expired grant needs no sweeper to
    stop being live -- if nothing ever revokes it explicitly, it simply
    stops being active the moment it expires.
    """
    path = _operator_access_path(domain)
    if not path.exists():
        return {"active": False}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"active": False}
    now = datetime.now(timezone.utc)
    expires_at = data.get("expires_at")
    try:
        expired = expires_at is None or datetime.fromisoformat(expires_at) <= now
    except (ValueError, TypeError):
        expired = True
    data["active"] = not data.get("revoked_at") and not expired and not data.get("consumed_denied")
    data["expired"] = expired
    return data


def grant_operator_access(domain: str, operator: str, minutes: int = 30, actor: str = "cli") -> str:
    """Issues a single-use token letting `operator` open this tenant's own
    admin panel as a temporary owner, and returns the token (the only
    time it exists in plaintext).

    Deliberately NOT a password reset or a shared login: the tenant keeps
    their own credentials throughout, the access self-expires, and every
    action taken under it is attributed to `operator:<name>` rather than
    to the tenant -- so the tenant's audit log distinguishes "my host did
    this" from "I did this", which a borrowed password never could.

    Writing the grant also writes a visible entry into the TENANT's own
    audit log, not just the operator's. The tenant finding out that their
    host let themselves in must not depend on the operator choosing to
    tell them, or on the operator's own log which the tenant can't read.
    """
    tenant = registry.get_tenant(domain)
    if not tenant:
        raise ProvisioningError(f"no active tenant for domain {domain!r}")
    if minutes < 1 or minutes > 480:
        raise ProvisioningError("access window must be between 1 and 480 minutes")

    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=minutes)
    _operator_access_path(domain).write_text(json.dumps({
        "token_hash": generate_password_hash(token),
        "operator": operator,
        "issued_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "token_used_at": None,
        "revoked_at": None,
    }))
    audit.log_action("tenant.operator_access_granted", domain, actor)
    append_tenant_audit(
        domain, "operator_access.granted", actor=f"{_OPERATOR_ACTOR_PREFIX}{operator}",
        detail={"expires_at": expires_at.isoformat(), "window_minutes": str(minutes)},
    )
    return token


def revoke_operator_access(domain: str, actor: str = "cli") -> bool:
    """Ends an active grant immediately. Returns whether one was actually
    live -- revoking an already-expired grant is a no-op worth reporting
    honestly rather than a success."""
    path = _operator_access_path(domain)
    status = operator_access_status(domain)
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return False
    was_active = bool(status.get("active"))
    data["revoked_at"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(data))
    audit.log_action("tenant.operator_access_revoked", domain, actor)
    append_tenant_audit(
        domain, "operator_access.revoked",
        actor=f"{_OPERATOR_ACTOR_PREFIX}{data.get('operator', '?')}",
        detail={"was_active": str(was_active).lower()},
    )
    return was_active


def _tenant_audit_file(domain: str) -> Path:
    tenant = registry.get_tenant(domain)
    if not tenant:
        raise ProvisioningError(f"no active tenant for domain {domain!r}")
    return Path(tenant.phpconf_host_path) / "audit.log"


def tenant_audit_entries(
    domain: str, limit: int = 300, action_filter: str = "", actor_filter: str = "",
) -> list[dict]:
    """A tenant's own panel audit log, newest first, read straight off
    the host rather than through their container's /audit page.

    Read-only, and there is deliberately no operator-side writer or
    clear: the operator can see this trail but must not be able to edit
    it from here, or it stops being evidence. (Root on the host can of
    course still edit the file -- what the chain gives is *detectability*,
    same caveat as the operator's own log, see vhsp_ctl/audit.py's module
    docstring.)

    Malformed lines are skipped rather than raising, so one corrupt entry
    can't make the whole page unviewable during an incident --
    tenant_audit_verify() is what reports integrity.
    """
    audit_file = _tenant_audit_file(domain)
    if not audit_file.exists():
        return []
    out = []
    for raw in audit_file.read_bytes().split(b"\n"):
        if not raw.strip():
            continue
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


def tenant_audit_verify(domain: str) -> tuple[bool, int]:
    """(chain_intact, entries_checked), or (False, index_of_first_break)."""
    return audit.verify_chain_at(_tenant_audit_file(domain))


def append_tenant_audit(domain: str, action: str, actor: str, detail: dict | None = None) -> None:
    """Appends a hash-chained entry to a TENANT's own audit log from the
    host side, for the few events the tenant's container can't witness
    itself -- an operator-access grant is issued and revoked out here,
    but it's the tenant who most needs it in their trail.

    Takes an flock for the whole read-hash-append: this file now has two
    independent writers (this process and the tenant's container), and
    without the lock a grant written at the same moment as a tenant's own
    action would interleave and break the chain -- reading as tampering
    when it was only a race. images/tenant-admin/'s audit_log() takes the
    same lock on the same bind-mounted file, which is what makes it hold
    across the container boundary.

    Never raises: failing to write an audit entry must not abort the
    action it describes, which has already happened by now.
    """
    try:
        path = _tenant_audit_file(domain)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a+") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.seek(0)
                lines = [line for line in f.read().encode().split(b"\n") if line]
                prev_hash = hashlib.sha256(lines[-1]).hexdigest() if lines else ""
                entry = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "action": action,
                    "actor": actor,
                    "prev_hash": prev_hash,
                }
                if detail:
                    entry["detail"] = detail
                f.write(json.dumps(entry) + "\n")
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        _chown_tenant_file(path)
    except Exception as e:  # noqa: BLE001 -- see docstring
        print(f"WARNING: tenant audit append failed ({domain} {action}): {e!r}", file=sys.stderr)


def _chown_tenant_file(path: Path) -> None:
    """Keeps a file this process creates on a tenant volume readable by
    the tenant's own container, which runs as root inside its namespace
    -- mirrors images/tenant-admin/'s _chown_to_host in the other
    direction. Best-effort: a failure here is a permissions annoyance,
    not a reason to lose the entry just written."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        print(f"WARNING: could not chmod {path}: {e!r}", file=sys.stderr)


_MIRROR_WATERMARK_FILENAME = ".vhsp-audit-mirror-watermark"


def mirror_tenant_operator_actions(domain: str) -> int:
    """Copies any NEW `operator:`-attributed entries out of this tenant's
    audit log into the OPERATOR's audit log, and returns how many were
    copied. Idempotent via a per-tenant watermark (count of tenant-log
    lines already considered), so running it every minute is cheap and
    never duplicates.

    This is what makes "operator actions appear in both logs" true. The
    tenant's container physically cannot write the operator log (no mount,
    and deliberately no path across that trust boundary), so the copy has
    to be pulled from this side. Driven by the audit-ship timer that
    already runs every minute, rather than by the operator's own browsing
    -- an operator must not be able to keep their actions out of their own
    log simply by never revisiting the page.
    """
    tenant = registry.get_tenant(domain)
    if not tenant:
        return 0
    audit_file = _tenant_audit_file(domain)
    if not audit_file.exists():
        return 0
    watermark_file = Path(tenant.phpconf_host_path) / _MIRROR_WATERMARK_FILENAME
    try:
        seen = int(watermark_file.read_text().strip())
    except (OSError, ValueError):
        seen = 0
    lines = [line for line in audit_file.read_bytes().split(b"\n") if line]
    if len(lines) < seen:
        # Log was rotated/trimmed under us -- restart rather than skip the
        # whole file forever.
        seen = 0
    copied = 0
    for raw in lines[seen:]:
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            continue
        actor = entry.get("actor", "")
        if not actor.startswith(_OPERATOR_ACTOR_PREFIX):
            continue
        audit.log_action(
            f"tenant_panel.{entry.get('action', '?')}", domain, actor,
            ip=entry.get("ip"),
        )
        copied += 1
    watermark_file.write_text(str(len(lines)))
    return copied


def mirror_all_tenant_operator_actions() -> int:
    """Every active tenant, for the audit-ship timer. One tenant's
    failure must not stop the sweep -- same reasoning as
    backup.run_all_due_backups."""
    total = 0
    for tenant in registry.list_tenants():
        try:
            total += mirror_tenant_operator_actions(tenant.domain)
        except Exception as e:  # noqa: BLE001
            print(f"WARNING: mirror failed for {tenant.domain}: {e!r}", file=sys.stderr)
    return total


def _tenant_totp_file(domain: str) -> Path:
    tenant = registry.get_tenant(domain)
    if not tenant:
        raise ProvisioningError(f"no active tenant for domain {domain!r}")
    return Path(tenant.phpconf_host_path) / "totp_secrets.json"


def count_tenant_totp(domain: str) -> int:
    """Read-only -- how many of this tenant's panel logins have an
    authenticator app (TOTP) enrolled. Never reads the secrets
    themselves, just how many entries there are."""
    totp_file = _tenant_totp_file(domain)
    if not totp_file.exists():
        return 0
    return len(json.loads(totp_file.read_text()))


def clear_tenant_totp(domain: str, actor: str = "cli") -> int:
    """Deletes ALL of a tenant's enrolled authenticator apps (TOTP) and
    returns how many were removed -- the exact counterpart of
    clear_tenant_webauthn_keys, for the other kind of second factor.

    Without this there was no operator recovery path at all for the far
    more common lockout: a tenant whose authenticator app is gone (phone
    lost/wiped, or the enrollment was done by someone who's no longer
    around) can't complete login, and can't reach their own security
    page to remove the enrollment either -- the same dead end
    clear_tenant_webauthn_keys already existed to solve for hardware
    keys, but TOTP is what most tenants actually enroll.

    Clears every entry rather than one login at a time, same reasoning as
    clear_tenant_webauthn_keys: from the operator's side there's no way
    to tell which enrollment is the stale one, and if the tenant can't
    get in, they need the whole thing dropped back to password-only and
    re-enrolled from scratch either way.

    No container restart needed -- images/tenant-admin/'s has_totp() and
    totp_verify() both read this file fresh on every login attempt.
    """
    totp_file = _tenant_totp_file(domain)
    count = 0
    if totp_file.exists():
        count = len(json.loads(totp_file.read_text()))
        totp_file.write_text("{}")
    audit.log_action("tenant.clear_totp", domain, actor)
    return count


def clear_tenant_webauthn_keys(domain: str, actor: str = "cli") -> int:
    """Deletes ALL of a tenant's registered WebAuthn keys and returns how
    many were removed. This is the recovery path for a tenant locked out
    with no working key left: once ANY key is registered,
    images/tenant-admin/'s login() requires it unconditionally with no
    in-app fallback, and a tenant who can't complete the challenge can't
    reach their own security-key page to remove a key either -- resetting
    their password (set_tenant_admin_password above) doesn't help, since
    that's a separate file the WebAuthn check doesn't look at. Clears
    everything rather than one key at a time deliberately: from the
    operator's side there's no way to tell which of a locked-out tenant's
    registered keys is the broken one, and it doesn't matter -- if none
    of them work, the tenant needs to fall back to password-only and
    re-register from scratch either way.

    No container restart needed, same reasoning as
    set_tenant_admin_password: the file is read fresh on every login
    attempt, not cached.
    """
    creds_file = _tenant_webauthn_file(domain)
    count = 0
    if creds_file.exists():
        count = len(json.loads(creds_file.read_text()))
        creds_file.write_text("[]")
    audit.log_action("tenant.clear_webauthn", domain, actor)
    return count


def reset_tenant_panel_access(domain: str, actor: str = "cli") -> str:
    """Coarse incident-response lever: wipes every tenant-admin panel
    login -- not just "admin", any team member the tenant added via their
    own self-service Team page -- down to one fresh "admin" account, and
    returns its new password (shown once, same pattern as every other
    generated credential here). Same "go nuclear, not targeted" reasoning
    as clear_tenant_webauthn_keys above: the operator has no visibility
    into which of a tenant's logins (if any past the original "admin") is
    the compromised one, and an attacker who reached the panel could have
    added a login of their own -- resetting only the one account known to
    be compromised wouldn't remove that backdoor.

    Also rotates the panel's Flask session-signing secret
    (tenant_admin_flask_secret) and restarts (not recreates -- nothing
    about the container's image or env changes, it just needs to reread
    this file at startup) the tenant-admin container. Without this, an
    attacker with an *already-established* session cookie would keep
    working right through a plain password reset -- session validity
    here is a signed cookie checked against this secret, not re-checked
    against tenant_users.json on every request, so rotating the secret is
    what actually ends a live session rather than just blocking new ones.
    This is the actual point of the lever: password-only reset handles
    "credentials leaked," not "attacker is in the panel right now."
    """
    tenant = registry.get_tenant(domain)
    if not tenant:
        raise ProvisioningError(f"no active tenant for domain {domain!r}")

    password = secrets.token_urlsafe(18)
    phpconf_dir = Path(tenant.phpconf_host_path)
    (phpconf_dir / "tenant_users.json").write_text(json.dumps({
        "admin": {
            "password_hash": generate_password_hash(password),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "role": "owner",
            # Single-use, same as set_tenant_admin_password's generated
            # reset: this password is read off an operator's screen and
            # handed over, so the tenant replaces it on first login.
            "must_change_password": True,
        }
    }))
    (phpconf_dir / "tenant_admin_flask_secret").write_text(secrets.token_hex(32))
    # Second factors go too, or this lever doesn't actually do its job:
    # login() gates on has_totp(username)/_has_credentials(username),
    # both keyed by USERNAME, and this function recreates "admin" from
    # scratch. An attacker who enrolled their own authenticator (or key)
    # against "admin" would keep gating the fresh account with it --
    # the reset would hand the tenant a new password that still can't
    # complete login, while leaving the attacker's factor in place. Both
    # files are wiped rather than pruned for the same "no way to tell
    # which enrollment is the hostile one" reason as the standalone
    # clear_* levers above.
    (phpconf_dir / "totp_secrets.json").write_text("{}")
    (phpconf_dir / "webauthn_credentials.json").write_text("[]")

    registry.set_tenant_admin_password(domain, password)

    client = _client()
    try:
        client.containers.get(tenant.tenant_admin_container).restart()
    except NotFound:
        pass  # not running right now -- it'll read both fresh files whenever it next starts anyway

    audit.log_action("tenant.reset_panel_access", domain, actor)
    return password


def reset_tenant_mailbox_passwords(domain: str, actor: str = "cli") -> dict[str, str]:
    """Coarse incident-response lever, mailbox side: regenerates every
    mailbox's password at once and returns {user: new_password} (shown
    once each). Same reasoning as reset_tenant_panel_access above --
    panel access already exposes this tenant's DB credentials in plain
    text right on the Overview page to any logged-in panel user
    (including a member), and mailbox self-service (images/tenant-admin/'s
    Email page) isn't owner-gated at all, so a compromised *panel* login
    of any role is also a plausible route to a compromised *mailbox*.
    No container restart needed -- images/mail/'s entrypoint watches
    mailboxes.txt and reloads Dovecot on change, same live-reload path
    the tenant's own self-service mailbox reset already uses."""
    tenant = registry.get_tenant(domain)
    if not tenant:
        raise ProvisioningError(f"no active tenant for domain {domain!r}")
    new_passwords = toggles.reset_all_mailbox_passwords(Path(tenant.phpconf_host_path))
    audit.log_action("tenant.reset_mailbox_passwords", domain, actor)
    return new_passwords


def reset_tenant_db_password(domain: str, actor: str = "cli") -> str:
    """Coarse incident-response lever, DB side: rotates this tenant's
    application DB user's password (never db_root_password -- that's the
    control plane's own credential, used for administrative exec_run
    calls like get_tenant_disk_usage's below, never exposed to or usable
    by the tenant's own application, so it isn't part of what a
    compromised *application* credential would expose).

    Unlike the panel/mailbox levers above, this is real credential
    rotation -- something this platform has never had at all
    (architecture.md and README both flag "DB/SFTP/mail credential
    rotation" as a standing gap) -- and it costs real, if brief, downtime
    on the tenant's actual website: DB_PASSWORD is baked into the web and
    tenant-admin containers' env at create time, not hot-reloadable, so
    both have to be recreated (not just restarted) to pick up the new
    value. The `ALTER USER` itself takes effect immediately against the
    live DB; the two recreates are what make every other consumer of
    that password agree with it again. Recreating tenant-admin doesn't
    touch tenant_users.json/webauthn_credentials.json -- same
    already-provisioned check _create_tenant_admin_container always does,
    so this doesn't undo a panel-access reset done alongside it.
    """
    tenant = registry.get_tenant(domain)
    if not tenant:
        raise ProvisioningError(f"no active tenant for domain {domain!r}")

    new_password = secrets.token_urlsafe(18)
    client = _client()

    db_container = client.containers.get(tenant.db_container)
    exit_code, output = db_container.exec_run([
        "mariadb", "-uroot", f"-p{tenant.db_root_password}", "-e",
        f"ALTER USER '{tenant.db_user}'@'%' IDENTIFIED BY '{new_password}'; FLUSH PRIVILEGES;",
    ])
    if exit_code != 0:
        raise ProvisioningError(f"ALTER USER failed: {output.decode(errors='replace')}")

    registry.set_tenant_db_password(domain, new_password)

    for container_name in (tenant.web_container, tenant.tenant_admin_container):
        try:
            client.containers.get(container_name).remove(force=True)
        except NotFound:
            pass

    _create_web_container(
        client, tenant.slug, tenant.domain, tenant.webroot_volume, tenant.phpconf_volume,
        tenant.logs_volume, tenant.db_network, tenant.db_container, tenant.db_name,
        tenant.db_user, new_password,
    )
    _create_tenant_admin_container(
        client, tenant.slug, tenant.domain, tenant.phpconf_volume, tenant.phpconf_host_path,
        tenant.logs_volume, tenant.webroot_volume, tenant.db_network, tenant.db_container,
        tenant.db_name, tenant.db_user, new_password, tenant.mail_volume,
        tenant.ssh_port, tenant.sftp_user,
    )

    audit.log_action("tenant.reset_db_password", domain, actor)
    return new_password


def reset_tenant_all_passwords(domain: str, actor: str = "cli") -> dict:
    """Composite "nuke everything" lever: panel access, every mailbox,
    and the DB password, in that order -- DB last since it's the only
    one that costs real site downtime, so a failure partway through still
    leaves the cheaper, zero-downtime resets already applied rather than
    the reverse. Returns {"admin_password": str, "mailbox_passwords":
    dict, "db_password": str} -- everything each individual lever would
    have returned on its own, since the operator still needs to actually
    hand these to someone."""
    return {
        "admin_password": reset_tenant_panel_access(domain, actor=actor),
        "mailbox_passwords": reset_tenant_mailbox_passwords(domain, actor=actor),
        "db_password": reset_tenant_db_password(domain, actor=actor),
    }


def _tenant_quota_file(domain: str) -> Path:
    tenant = registry.get_tenant(domain)
    if not tenant:
        raise ProvisioningError(f"no active tenant for domain {domain!r}")
    return Path(tenant.phpconf_host_path) / "quota_limit_bytes.txt"


def get_tenant_quota_limit(domain: str) -> int:
    """Bytes. Lives in a plain file on phpconf, not a registry column --
    both this (operator) side and images/tenant-admin/'s own display read
    it fresh, same "shared file is the single source of truth, no
    duplicated/driftable copy" pattern as every other per-tenant setting
    in this codebase (mailboxes.txt, admin_credentials.json, etc.)."""
    f = _tenant_quota_file(domain)
    if not f.exists():
        return DEFAULT_TENANT_QUOTA_BYTES
    return int(f.read_text().strip())


def set_tenant_quota_limit(domain: str, limit_bytes: int, actor: str = "cli") -> None:
    f = _tenant_quota_file(domain)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(str(limit_bytes))
    audit.log_action("tenant.set_quota", domain, actor)


def set_tenant_billing_account_id(domain: str, billing_account_id: str, actor: str = "cli") -> None:
    """Ties this tenant to an account in external billing software --
    operator-set only (see registry.set_tenant_billing_account_id's own
    docstring for why there's deliberately no writer for this on the
    tenant-facing side). No container/volume/DNS side effects, unlike
    most of this file's other setters -- it's a plain registry column."""
    registry.set_tenant_billing_account_id(domain, billing_account_id)
    audit.log_action("tenant.set_billing_account_id", domain, actor)


def _maintenance_marker_for(tenant: registry.Tenant) -> Path:
    return Path(tenant.phpconf_host_path) / ".vhsp-maintenance"


def _tenant_maintenance_marker(domain: str) -> Path:
    tenant = registry.get_tenant(domain)
    if not tenant:
        raise ProvisioningError(f"no active tenant for domain {domain!r}")
    return _maintenance_marker_for(tenant)


def tenant_maintenance_enabled(domain: str) -> bool:
    return _tenant_maintenance_marker(domain).exists()


def tenant_maintenance_enabled_for(tenant: registry.Tenant) -> bool:
    """Same answer as tenant_maintenance_enabled(), but against a Tenant
    row the caller already holds. Exists for the admin UI's tenant LIST,
    which renders one row per tenant: the domain-keyed variant above does
    a registry.get_tenant() lookup per call, so calling it in that loop
    would turn a single-query page into one extra query per tenant. This
    stays a bare stat() on a path we already have.
    """
    return _maintenance_marker_for(tenant).exists()


def set_tenant_maintenance_mode(domain: str, enabled: bool, actor: str = "cli") -> None:
    """Operator-only hold: visitors see a neutral "temporarily undergoing
    maintenance" page (images/web/maintenance.html) instead of the
    tenant's real site, and mail clients can't log in (IMAP/submission),
    while inbound mail delivery keeps working -- see
    images/web/nginx.conf and images/mail/entrypoint.sh for where each
    half is actually enforced. Deliberately a marker file on phpconf,
    the same volume every other operator/tenant-admin toggle already
    uses, but with NO corresponding route anywhere in
    images/tenant-admin/'s app.py -- that asymmetry is the whole point:
    unlike every other toggle here, a tenant must not be able to lift
    this themselves (e.g. a billing hold), only see that it's on.
    """
    marker = _tenant_maintenance_marker(domain)
    if enabled:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    else:
        marker.unlink(missing_ok=True)
    audit.log_action("tenant.maintenance_" + ("on" if enabled else "off"), domain, actor)


_TENANT_PLATFORM_ACCESS_DEFAULTS = {
    "api_allowed": False, "mcp_allowed": False, "api_enabled": False, "mcp_enabled": False,
}


def _tenant_platform_access_path(domain: str) -> Path:
    tenant = registry.get_tenant(domain)
    if not tenant:
        raise ProvisioningError(f"no active tenant for domain {domain!r}")
    return Path(tenant.phpconf_host_path) / ".vhsp-platform-access.json"


def tenant_platform_access(domain: str) -> dict:
    """Current state of all four tenant API/MCP flags -- the two-layer
    permission model architecture.md's "API and MCP access for operators
    and tenants" section describes: api_allowed/mcp_allowed are
    operator-set (Layer 1, see set_tenant_api_allowed/set_tenant_mcp_allowed
    below); api_enabled/mcp_enabled are tenant-set (Layer 2), written
    directly by images/tenant-admin/app.py's own /api-tokens route via
    the identical host path -- not through this process at all, the same
    cross-container marker-file convention every other operator/tenant
    toggle here already uses (see _tenant_maintenance_marker's own
    docstring). Missing file or missing keys default to all-False, same
    "absent means off" posture as every other opt-in flag in this
    codebase."""
    path = _tenant_platform_access_path(domain)
    if not path.exists():
        return dict(_TENANT_PLATFORM_ACCESS_DEFAULTS)
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        data = {}
    return {key: bool(data.get(key, default)) for key, default in _TENANT_PLATFORM_ACCESS_DEFAULTS.items()}


def _set_tenant_platform_access(domain: str, **updates: bool) -> None:
    path = _tenant_platform_access_path(domain)
    current = tenant_platform_access(domain)
    current.update(updates)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(current))


def set_tenant_api_allowed(domain: str, allowed: bool, actor: str = "cli") -> None:
    """Layer 1 of the tenant API/MCP permission model -- operator-only,
    the precondition images/tenant-admin/app.py's own Layer-2 enable
    toggle checks server-side before honoring anything (never just
    hiding the control -- see that route's own docstring). Setting this
    False doesn't revoke any already-minted token or wait for anything
    else to catch up: vhsp_ctl/api.py's `/api/v1/self/*` routes and
    mcp_server.py's tenant-scoped tools both re-check this flag live on
    every single call (see tenant_api_auth.py's own docstring on why
    nothing in this model is cached/frozen the way the operator-level
    toggle's own flags briefly were) -- disallowing here takes effect on
    the very next request."""
    _set_tenant_platform_access(domain, api_allowed=allowed)
    audit.log_action("tenant.api_allow" if allowed else "tenant.api_disallow", domain, actor)


def set_tenant_mcp_allowed(domain: str, allowed: bool, actor: str = "cli") -> None:
    """See set_tenant_api_allowed's docstring -- identical reasoning,
    the MCP half of the same two-layer model."""
    _set_tenant_platform_access(domain, mcp_allowed=allowed)
    audit.log_action("tenant.mcp_allow" if allowed else "tenant.mcp_disallow", domain, actor)


def _du_bytes(path: Path) -> int:
    """Real, on-disk usage (`du`, not a plain sum of file sizes -- matters
    for e.g. MariaDB's sparse-ish datadir files). Missing directories
    (a tenant with no mail sent yet, say) are 0 usage, not an error."""
    if not path.exists():
        return 0
    result = subprocess.run(["du", "-sb", str(path)], capture_output=True, text=True)
    if result.returncode != 0:
        return 0
    return int(result.stdout.split()[0])


def get_tenant_disk_usage(domain: str) -> dict:
    """{'web': bytes, 'db': bytes, 'mail': bytes, 'total': bytes}. Web and
    mail are measured directly on the host (`du` on the bind-mounted
    directories -- provisioner.py already runs on the host, no need to go
    through a container for this). DB has no on-disk directory that maps
    cleanly to "this tenant's data" (MariaDB's own datadir layout, shared
    ibdata/redo logs alongside the per-table .ibd files
    innodb_file_per_table gives us -- confirmed ON for this image), so
    it's measured via a real query against information_schema instead,
    exec'd inside the tenant's own DB container with docker-py rather
    than requiring a MySQL client library in the control plane's own
    venv. COALESCE handles a tenant schema with zero tables yet (a fresh
    GROUP BY would simply omit the row rather than reporting 0 -- verified
    this while researching the feature).
    """
    tenant = registry.get_tenant(domain)
    if not tenant:
        raise ProvisioningError(f"no active tenant for domain {domain!r}")

    web_bytes = _du_bytes(Path(tenant.webroot_host_path))
    mail_bytes = _du_bytes(Path(tenant.mail_host_path))

    db_bytes = 0
    try:
        client = _client()
        container = client.containers.get(tenant.db_container)
        exit_code, output = container.exec_run([
            "mariadb", "-uroot", f"-p{tenant.db_root_password}", "-N", "-e",
            "SELECT COALESCE(SUM(data_length+index_length),0) FROM information_schema.tables "
            f"WHERE table_schema='{tenant.db_name}'",
        ])
        if exit_code == 0:
            db_bytes = int(output.decode().strip() or 0)
    except (NotFound, ValueError):
        pass

    return {
        "web": web_bytes,
        "db": db_bytes,
        "mail": mail_bytes,
        "total": web_bytes + db_bytes + mail_bytes,
    }


def _traefik_gateway_info(client: docker.DockerClient) -> tuple[str, str]:
    """(gateway_ip, subnet_cidr) for GATEWAY_NETWORK, looked up live --
    same technique _create_waf_container already uses for the subnet half
    (see that function's own comment on why this varies by deployment and
    isn't hardcoded). The gateway IP is the other half of the same
    IPAM.Config entry -- this is what a bare host process (not a
    container) reaches a Traefik-fronted container's own network through,
    the same role 172.18.0.1 plays in the existing static vhsp-admin.yml
    route."""
    ipam_config = client.networks.get(GATEWAY_NETWORK).attrs["IPAM"]["Config"][0]
    return ipam_config["Gateway"], ipam_config["Subnet"]


_MCP_TRAEFIK_ROUTE_PATH = TRAEFIK_DYNAMIC_DIR / "vhsp-mcp.yml"

_MCP_TRAEFIK_ROUTE_TEMPLATE = """\
# Generated by provisioner.enable_mcp_server() -- do not hand-edit, it
# will be overwritten (and removed entirely) the next time the MCP
# toggle on /account/api-tokens is used. Routes the operator MCP server
# (a bare systemd process on 0.0.0.0:{mcp_port}, not a Docker container) through
# the same local Traefik/ACME path, under a PathPrefix on the existing
# admin-UI host+cert rather than a new subdomain -- avoids a second Let's
# Encrypt cert/DNS record for a server with exactly one client type (MCP
# clients, not browsers). fastmcp's own default Streamable HTTP path is
# /mcp, matching the PathPrefix here. Port {mcp_port} is firewalled (ufw) to only
# accept connections from this same gateway network's subnet.
#
# priority MUST stay explicit and higher than vhsp-admin's own
# auto-computed value (Traefik computes a router's default priority from
# its rule's string length when none is set -- vhsp-admin's plain
# Host(...) rule computes to roughly 21; a lower or unset priority here
# was tried and confirmed to silently lose, routing all /mcp traffic into
# the admin UI instead -- this exact bug was hit and fixed once already
# building this feature by hand).
http:
  routers:
    vhsp-mcp:
      rule: "Host(`{rp_id}`) && PathPrefix(`/mcp`)"
      entryPoints:
        - web
      service: vhsp-mcp
      priority: 100
  services:
    vhsp-mcp:
      loadBalancer:
        servers:
          - url: "http://{gateway_ip}:{mcp_port}"
"""


def enable_mcp_server(actor: str = "cli") -> None:
    """Installs/enables the vhsp-mcp.service systemd unit, opens the
    firewall rule scoped to GATEWAY_NETWORK's own subnet, and writes the
    Traefik route -- the three one-time, by-hand DEPLOYMENT.md steps this
    feature required until now, run together as one idempotent action
    from the operator UI's MCP toggle. Doesn't itself flip
    config.MCP_ENABLED -- that's platform_settings.set_mcp_enabled(),
    called by web.py alongside this, since that flag governs
    mcp_server.py's own startup gate (a separate concern from whether the
    systemd unit/firewall/route exist)."""
    client = _client()
    gateway_ip, subnet = _traefik_gateway_info(client)

    try:
        _run("sudo", "/usr/local/sbin/vhsp-mcp-toggle", "enable")
    except subprocess.CalledProcessError as e:
        raise ProvisioningError(f"installing/enabling vhsp-mcp.service failed: {e.stderr}")

    try:
        _run("sudo", "/usr/local/sbin/vhsp-mcp-firewall", "enable", subnet)
    except subprocess.CalledProcessError as e:
        raise ProvisioningError(f"opening the MCP firewall rule failed: {e.stderr}")

    _MCP_TRAEFIK_ROUTE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _MCP_TRAEFIK_ROUTE_PATH.write_text(
        _MCP_TRAEFIK_ROUTE_TEMPLATE.format(rp_id=ADMIN_RP_ID, gateway_ip=gateway_ip, mcp_port=MCP_BIND_PORT)
    )

    audit.log_action("admin.mcp_service_enable", "", actor)


def disable_mcp_server(actor: str = "cli") -> None:
    """Reverses enable_mcp_server() completely -- stops/disables the
    systemd unit, removes the firewall rule, deletes the Traefik route
    file. Full symmetry rather than partial teardown: "off" means
    genuinely unroutable and unreachable, not just "the process stopped
    but the route/firewall hole are still there."""
    client = _client()
    _, subnet = _traefik_gateway_info(client)

    try:
        _run("sudo", "/usr/local/sbin/vhsp-mcp-toggle", "disable")
    except subprocess.CalledProcessError as e:
        raise ProvisioningError(f"disabling vhsp-mcp.service failed: {e.stderr}")

    try:
        _run("sudo", "/usr/local/sbin/vhsp-mcp-firewall", "disable", subnet)
    except subprocess.CalledProcessError as e:
        raise ProvisioningError(f"removing the MCP firewall rule failed: {e.stderr}")

    _MCP_TRAEFIK_ROUTE_PATH.unlink(missing_ok=True)

    audit.log_action("admin.mcp_service_disable", "", actor)


class CertReissueError(ProvisioningError):
    """Distinct from a generic ProvisioningError so callers can tell
    "you asked at the wrong time" (DNS not ready) from "the recreate
    itself broke", and word the two differently."""


def reissue_tenant_certificates(domain: str, actor: str = "cli") -> dict:
    """Make Traefik ask Let's Encrypt again for this tenant's certificates.

    Exists because a failed certificate order never retries on its own.
    Traefik resolves a router's certificate when it *discovers the
    router*, so an order placed while the tenant's DNS still pointed
    elsewhere fails and then nothing happens -- not on later HTTPS
    requests, not after the tenant's containers restart. Measured on a
    real host: five failed orders in sixteen seconds at creation, then no
    further attempt for an hour, across repeated HTTPS handshakes once
    DNS was correct and across a `docker restart` of the container
    carrying the router. See issue #18.

    What does work is replacing the container. A restart keeps the same
    container, so the Docker provider reports the same router with
    identical labels and Traefik has no reason to re-resolve; a remove +
    create produces a new container and therefore a genuine provider
    event, and Traefik requests the certificate as it registers the
    router. Verified as the *only* difference between the two: attempts
    held flat at 4 across idle and across restart, and went to 5
    immediately on recreate.

    So this recreates the containers carrying the tenant's own HTTP
    routers -- the WAF sidecar (Host(<domain>)) and the tenant-admin
    container (Host(admin.<domain>)). Those are exactly the two hostnames
    dns_records.cert_status() reports on, so what this fixes and what the
    UI shows stay in step.

    `webmail.<domain>` is deliberately NOT covered. Its router lives on
    the shared Roundcube container, so reissuing it would recreate a
    container every other tenant is also served by -- a per-tenant action
    with cross-tenant blast radius, which needs its own decision rather
    than being smuggled in here.

    Refuses unless DNS already resolves to this host. That isn't
    politeness: Let's Encrypt allows five failed validations per hostname
    per hour, so retrying blindly against DNS that is still wrong spends
    a limited budget to achieve nothing, and can lock out the retry that
    *would* have worked once DNS caught up.

    Brief downtime is unavoidable -- recreating the WAF container drops
    the tenant's site for a moment. That is worth stating in any UI that
    calls this, since the tenant is usually already serving a browser
    warning and the operator is choosing between two visible faults.
    """
    tenant = registry.get_tenant(domain)
    if not tenant:
        raise CertReissueError(f"no active tenant for domain {domain!r}")
    if not dns_records.PLATFORM_PUBLIC_IP:
        raise CertReissueError(
            "VHSP_PLATFORM_PUBLIC_IP is not set, so there is nothing to check DNS against -- "
            "set it on vhsp-admin.service before using this"
        )

    admin_hostname = f"admin.{domain}"
    # Only the hostnames this call can actually act on. webmail's router
    # lives on the shared Roundcube container and is left to the
    # reconciler's own regeneration, so demanding its DNS here would
    # refuse a reissue this call could have completed.
    not_live = [
        host for host in (domain, admin_hostname)
        if not should_request_cert_for(host)
    ]
    if not_live:
        raise CertReissueError(
            f"DNS for {', '.join(not_live)} does not resolve to {dns_records.PLATFORM_PUBLIC_IP} yet. "
            "Fix the A record(s) first -- reissuing now would only burn one of the five "
            "failed validations Let's Encrypt allows per hostname per hour."
        )

    client = _client()
    recreated = []

    if tenant.waf_container:
        try:
            client.containers.get(tenant.waf_container).remove(force=True)
        except NotFound:
            pass
        name = _create_waf_container(client, tenant.slug, tenant.domain, tenant.phpconf_host_path)
        registry.set_tenant_waf_container(domain, name)
        recreated.append(domain)

    try:
        client.containers.get(tenant.tenant_admin_container).remove(force=True)
    except NotFound:
        pass
    _create_tenant_admin_container(
        client, tenant.slug, tenant.domain, tenant.phpconf_volume, tenant.phpconf_host_path,
        tenant.logs_volume, tenant.webroot_volume, tenant.db_network, tenant.db_container,
        tenant.db_name, tenant.db_user, tenant.db_password, tenant.mail_volume,
        tenant.ssh_port, tenant.sftp_user,
    )
    recreated.append(admin_hostname)

    audit.log_action("tenant.cert_reissue", domain, actor)
    return {"domain": domain, "hostnames": recreated}


def tenant_has_certresolver(client, tenant) -> bool:
    """Does this tenant's public router currently carry the resolver?

    Read off the running container's own labels rather than tracked in
    the registry. The labels are what Traefik actually acts on, so they
    are the only answer that cannot drift -- a registry column would be a
    second copy of the truth that a hand-run recreate_*.py could silently
    invalidate.

    False if the container is missing, which is the useful answer for a
    reconciler: nothing to flip, and something else is already wrong.
    """
    if not tenant.waf_container:
        return False
    try:
        labels = client.containers.get(tenant.waf_container).labels or {}
    except NotFound:
        return False
    return any(k.endswith(".tls.certresolver") for k in labels)


def reconcile_tenant_certificates(actor: str = "reconciler") -> list[dict]:
    """Give a real certificate to any tenant whose DNS has since caught up.

    The other half of should_request_cert_for. A tenant created before its A
    records pointed here comes up on the self-signed fallback with no
    resolver, asking Let's Encrypt for nothing; this notices when that
    changes and recreates the containers so Traefik orders at a moment the
    challenge can actually succeed.

    Skips tenants that already carry the resolver, so it is a no-op on a
    healthy platform -- it does not recreate containers to no purpose, and
    a tenant whose certificate merely failed for some other reason is left
    for the explicit reissue action rather than being retried on a timer
    into the rate limit.

    Per-tenant failures are swallowed for the same reason run_all_due_backups
    swallows them: one tenant's problem must not stop the pass reaching the
    rest. Returns what it changed, for the caller to log.
    """
    client = _client()
    flipped = []
    for tenant in registry.list_tenants():
        try:
            if tenant_has_certresolver(client, tenant):
                continue
            if not any(should_request_cert_for(h) for h in tenant_cert_hostnames(tenant.domain)):
                continue
            result = reissue_tenant_certificates(tenant.domain, actor=actor)
            flipped.append(result)
        except Exception:
            continue
    return flipped
