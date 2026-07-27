"""Suggested DNS records for a tenant domain (architecture.md's "DNS
automation for new tenants" list). No push/API integration exists (that
section documents two not-yet-decided models, platform-hosted vs
tenant-hosted zone) -- this only ever computes and displays what a human
would paste into whatever actually hosts the zone. Never write to real
DNS from here.
"""
import logging
import re
import socket
import ssl
import subprocess
from dataclasses import asdict, dataclass

import docker
from docker.errors import NotFound

from vhsp_ctl.config import DKIM_SELECTOR, DOCKER_HOST_URL, MAILGW_HOSTNAME, PLATFORM_PUBLIC_IP

logger = logging.getLogger(__name__)


class DnsRecordsError(Exception):
    pass


@dataclass
class DnsRecord:
    kind: str  # A / MX / TXT
    name: str
    value: str
    note: str = ""


def is_record_live(kind: str, name: str, expected_value: str) -> bool:
    """Best-effort: does `name`'s CURRENT live DNS (via a real `dig`
    lookup, not anything cached from provisioning time) already contain
    `expected_value`? Read-only, no side effects -- safe to call from a
    plain GET. False on any lookup failure (timeout, NXDOMAIN, no `dig`),
    never raises: a DNS check that can't complete should just show
    "not yet", not break the page.

    TXT rows (SPF/DKIM/DMARC) match on SUBSTRING, not exact equality --
    a domain can carry other TXT records alongside the one that matters,
    and a tenant who already customized DMARC to e.g. p=reject instead of
    our suggested p=quarantine has a perfectly good, working record that
    just won't literal-match; substring keeps SPF/DKIM (where the
    suggested value IS what must appear, verbatim, as one piece of a
    larger record) correct while not flagging every legitimate
    customization as "broken".
    """
    try:
        # @1.1.1.1, not the ambient resolver: this process's own tenant
        # container (mail, same GATEWAY_NETWORK) gets a network alias
        # equal to the bare domain (see provisioner._create_mail_container's
        # docstring), which Docker's embedded DNS (127.0.0.11, the default
        # resolver everywhere on that network including here) shadows the
        # REAL public A record with -- verified directly, an ambient
        # lookup for a tenant's own apex domain returns the mail
        # container's internal 172.18.x.x address, not its real public IP.
        # Querying a real external resolver directly sidesteps that
        # shadowing entirely, on both the host (web.py) and in-container
        # (tenant-admin) call sites.
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
        # dig prints "10 mail.dvce.us." -- trailing dot, expected_value has none.
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
            # Each line is one TXT record, its value(s) double-quoted --
            # possibly split into several adjacent quoted strings the same
            # way opendkim-genkey's own output is (see dkim_txt_value's
            # docstring); join them the same way before comparing.
            segments = re.findall(r'"([^"]*)"', line)
            joined = "".join(segments) if segments else line
            if expected_value in joined:
                return True
        logger.warning(
            "dns check: TXT %s wanted %r, dig returned %r", name, expected_value, lines,
        )
        return False

    return False


def is_cert_live(hostname: str) -> bool:
    """Best-effort: has Traefik actually obtained a real, browser-trusted
    cert for `hostname` yet, as opposed to still serving its own
    self-signed fallback (what it hands back for any SNI it has no ACME
    cert for)? This is the direct answer to "did my cert actually get
    issued" -- distinct from (and checked separately from) whether the
    DNS records above are live, because the two aren't the same event:
    Traefik requests/retries a cert lazily, on the next TLS handshake for
    that SNI, not once-at-provisioning-time and never again. A tenant
    created before its DNS was live will keep failing the ACME HTTP-01
    challenge on every handshake attempt until the A record actually
    resolves here -- there's nothing to retry in code, just DNS
    propagating and then one more HTTPS request coming in to retrigger
    Traefik's own attempt.

    Talks to Traefik over loopback (this platform's own Traefik always
    publishes :443 on the host per DEPLOYMENT.md, and this process
    already runs on that same host) rather than the tenant's public IP,
    so this check works regardless of whether `hostname`'s own DNS has
    propagated yet -- same reasoning as is_record_live's own `@1.1.1.1`
    choice, just solving the opposite direction of the same shadowing
    problem. False on any connection/handshake/verification failure
    (timeout, refused, self-signed fallback cert, expired cert): never
    raises, same contract as is_record_live.
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection(("127.0.0.1", 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True
    except (OSError, ssl.SSLError) as exc:
        logger.warning("cert check: TLS handshake for %r raised %r", hostname, exc)
        return False


def dkim_txt_value(client: docker.DockerClient, mail_container: str, domain: str) -> str:
    """Reads the opendkim-genkey-produced BIND-format .txt file straight
    out of the tenant's own running mail container (docker exec, not a
    host filesystem read -- avoids the exact "container chowns its data
    to an internal uid" permission trap backup.py's _tar_directory hit for
    this same volume family) and collapses it into the single unbroken
    value most DNS providers' UIs actually want, e.g.:

        v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBg...AQAB

    rather than the quoted/line-wrapped BIND zone-file form opendkim-genkey
    writes (that form is for a zone file text include, not a UI text box).
    """
    try:
        container = client.containers.get(mail_container)
    except NotFound:
        raise DnsRecordsError(f"{mail_container!r} isn't running -- DKIM key hasn't been generated yet")
    path = f"/etc/opendkim/keys/{domain}/{DKIM_SELECTOR}.txt"
    exit_code, output = container.exec_run(["cat", path])
    if exit_code != 0:
        raise DnsRecordsError(
            f"couldn't read {path} from {mail_container} (exit {exit_code}) -- "
            "container may not have finished its first boot yet"
        )
    raw = output.decode()
    # Every double-quoted segment, in order, concatenated -- exactly what
    # a receiving resolver does with a multi-string TXT RDATA, and what
    # collapses opendkim-genkey's line-wrapped form back into one value.
    segments = re.findall(r'"([^"]*)"', raw)
    if not segments:
        raise DnsRecordsError(f"couldn't parse DKIM TXT record out of {path}'s contents")
    return "".join(segments)


def compute_records(
    client: docker.DockerClient, domain: str, mail_container: str, mail_hostname: str,
) -> list[DnsRecord]:
    """The full record set architecture.md's "DNS automation for new
    tenants" section lists, computed fresh from current platform config
    plus this one tenant's live DKIM key. Raises DnsRecordsError with a
    clear reason if anything required (platform IP, mail gateway
    hostname, a running mail container) isn't configured/available yet,
    rather than silently emitting a record with a blank/wrong value.

    Takes an already-open docker client + the container/hostname strings
    directly, not a registry.Tenant -- callers during provisioning (before
    a tenant's row exists in the registry yet) and the CLI/tenant-admin
    write path (registry row already exists) both need this, and this
    module deliberately doesn't import vhsp_ctl.provisioner (which itself
    would need to import this module for the write-on-provision step
    below) to avoid a circular import.
    """
    if not PLATFORM_PUBLIC_IP:
        raise DnsRecordsError(
            "VHSP_PLATFORM_PUBLIC_IP isn't configured -- refusing to guess the platform's public IP"
        )

    dkim_value = dkim_txt_value(client, mail_container, domain)

    return [
        DnsRecord("A", domain, PLATFORM_PUBLIC_IP),
        DnsRecord("A", f"www.{domain}", PLATFORM_PUBLIC_IP),
        DnsRecord("A", mail_hostname, PLATFORM_PUBLIC_IP,
                  note="SNI-routed IMAPS/SMTPS target"),
        DnsRecord("A", f"webmail.{domain}", PLATFORM_PUBLIC_IP,
                  note="Webmail -- same platform IP as your main site."),
        DnsRecord("A", f"admin.{domain}", PLATFORM_PUBLIC_IP,
                  note="Your self-service admin panel -- needs to be publicly "
                       "reachable over HTTPS for security-key (WebAuthn) login to "
                       "work."),
        DnsRecord("MX", domain, f"10 {MAILGW_HOSTNAME}",
                  note=f"Requires {MAILGW_HOSTNAME} to itself have an A record "
                       "pointing at the platform IP, and inbound port 25 reachable "
                       "through the firewall to this host."),
        DnsRecord("TXT", domain, f"v=spf1 ip4:{PLATFORM_PUBLIC_IP} ~all",
                  note="Softfail (~all), not hardfail (-all) -- this platform "
                       "shares one IP across multiple sites, so a hard fail here "
                       "risks flagging legitimate mail too aggressively."),
        DnsRecord("TXT", f"{DKIM_SELECTOR}._domainkey.{domain}", dkim_value),
        DnsRecord("TXT", f"_dmarc.{domain}",
                  f"v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}",
                  note="p=quarantine as a cautious starting default, not p=reject -- "
                       "tighten once SPF/DKIM are confirmed passing in the rua reports"),
    ]


def platform_records() -> list[DnsRecord]:
    """Records that exist once for the whole platform, not per-tenant --
    currently just the shared inbound mail gateway's own hostname, which
    every tenant's MX record (see compute_records) points at. The
    operator admin UI is the only audience for this (a tenant has no
    reason to see or manage it), unlike everything in compute_records.
    """
    if not PLATFORM_PUBLIC_IP:
        raise DnsRecordsError(
            "VHSP_PLATFORM_PUBLIC_IP isn't configured -- refusing to guess the platform's public IP"
        )
    return [
        DnsRecord("A", MAILGW_HOSTNAME, PLATFORM_PUBLIC_IP,
                  note="the shared inbound mail gateway every tenant's MX record points at -- "
                       "needs this record, AND inbound port 25 actually forwarded through the "
                       "firewall to this host, before any tenant's MX can work"),
    ]


def check_records_live(records: list[dict]) -> list[dict]:
    """Takes plain dicts (asdict(DnsRecord) shape -- both the cached
    dns_records.json a route reads off disk and a freshly-computed
    platform_records() list normalize to this before getting here) and
    returns the same dicts with an added "ok" key. Deliberately not baked
    into DnsRecord/records_as_json itself: a live-check result would go
    stale sitting in the cached file, this is only ever computed fresh,
    on demand, when a caller explicitly asks (the admin UI's "Check
    records" button), never automatically on a normal page load."""
    return [{**r, "ok": is_record_live(r["kind"], r["name"], r["value"])} for r in records]


def cert_status(domain: str, admin_hostname: str) -> list[dict]:
    """SSL certificate status for the two Traefik HTTP routers a tenant
    actually gets (the main site, and the admin panel -- WebAuthn login
    there specifically needs a real cert, per admin_hostname's own
    routing comment in provisioner.py). Same on-demand-only shape as
    check_records_live: computed fresh when a caller explicitly asks,
    never cached, since "issued" is exactly the kind of state that
    changes underneath a stale cache the moment DNS catches up."""
    return [
        {"label": "Main site", "hostname": domain, "ok": is_cert_live(domain)},
        {"label": "Admin panel", "hostname": admin_hostname, "ok": is_cert_live(admin_hostname)},
    ]


def records_as_json(records: list[DnsRecord]) -> str:
    import json
    return json.dumps([asdict(r) for r in records])


def suggested_records(domain: str) -> list[DnsRecord]:
    """CLI-facing convenience wrapper: looks the tenant up in the registry
    and opens its own docker client, rather than requiring the caller to
    already have both on hand the way compute_records() does."""
    from vhsp_ctl import registry
    tenant = registry.get_tenant(domain)
    if not tenant:
        raise DnsRecordsError(f"no active tenant for domain {domain!r}")
    client = docker.DockerClient(base_url=DOCKER_HOST_URL)
    return compute_records(client, domain, tenant.mail_container, tenant.mail_hostname)
