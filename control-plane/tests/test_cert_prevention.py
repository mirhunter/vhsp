"""Tests for not ordering certificates before DNS can satisfy the challenge.

The mechanism, measured on a live host rather than inferred: Traefik's
`web` entrypoint sets `http.tls.certresolver`, and a router with no TLS
config of its own inherits it and triggers an ACME order the instant the
router is discovered -- at container start, before anyone can have
pointed DNS here. A router that declares its own `tls` does *not* inherit
the resolver. `tls=true` alone produced zero ACME orders and served the
self-signed fallback; adding `tls.certresolver` to the same router
produced an order immediately.

So the whole prevention story reduces to one label, and these tests pin
that label's presence and absence in the cases that matter. They assert
on the labels rather than on Traefik, which is the honest boundary: what
Traefik does with them was established by experiment, not by unit test.
"""

from unittest.mock import MagicMock

import pytest

from vhsp_ctl import provisioner


RESOLVER_SUFFIX = ".tls.certresolver"


# --- the label helper --------------------------------------------------

def test_without_dns_the_router_gets_tls_but_no_resolver():
    """TLS still on: the tenant-admin panel takes a password and must
    never be served over plain HTTP, so a self-signed warning is the
    right intermediate state rather than an unencrypted one."""
    labels = provisioner._tls_labels("r", with_certresolver=False)
    assert labels["traefik.http.routers.r.tls"] == "true"
    assert not any(k.endswith(RESOLVER_SUFFIX) for k in labels)


def test_with_dns_the_resolver_is_requested():
    labels = provisioner._tls_labels("r", with_certresolver=True)
    assert labels["traefik.http.routers.r.tls.certresolver"] == "letsencrypt"


# --- reading current state off the container --------------------------

def _tenant(waf="waf-c"):
    return type("T", (), {"domain": "t.example.com", "waf_container": waf})()


def test_detects_a_tenant_already_holding_the_resolver():
    client = MagicMock()
    client.containers.get.return_value.labels = {
        "traefik.http.routers.vhsp-t.tls": "true",
        "traefik.http.routers.vhsp-t.tls.certresolver": "letsencrypt",
    }
    assert provisioner.tenant_has_certresolver(client, _tenant())


def test_detects_a_tenant_still_on_the_fallback():
    client = MagicMock()
    client.containers.get.return_value.labels = {"traefik.http.routers.vhsp-t.tls": "true"}
    assert not provisioner.tenant_has_certresolver(client, _tenant())


def test_a_missing_container_is_not_reported_as_having_a_cert():
    from docker.errors import NotFound
    client = MagicMock()
    client.containers.get.side_effect = NotFound("gone")
    assert not provisioner.tenant_has_certresolver(client, _tenant())


# --- the reconciler ----------------------------------------------------

@pytest.fixture
def recon(monkeypatch):
    client = MagicMock()
    monkeypatch.setattr(provisioner, "_client", lambda: client)
    calls = []
    monkeypatch.setattr(provisioner, "reissue_tenant_certificates",
                        lambda domain, actor="x": calls.append(domain) or {"domain": domain, "hostnames": [domain]})
    return monkeypatch, calls


def test_skips_tenants_that_already_have_a_certificate(recon):
    monkeypatch, calls = recon
    monkeypatch.setattr(provisioner.registry, "list_tenants", lambda: [_tenant()])
    monkeypatch.setattr(provisioner, "tenant_has_certresolver", lambda c, t: True)
    monkeypatch.setattr(provisioner, "should_request_cert_for",
                        lambda h: pytest.fail("must not check DNS for a tenant already holding a cert"))

    assert provisioner.reconcile_tenant_certificates() == []
    assert calls == []


def test_skips_tenants_whose_dns_is_still_wrong(recon):
    monkeypatch, calls = recon
    monkeypatch.setattr(provisioner.registry, "list_tenants", lambda: [_tenant()])
    monkeypatch.setattr(provisioner, "tenant_has_certresolver", lambda c, t: False)
    monkeypatch.setattr(provisioner, "should_request_cert_for", lambda h: False)

    assert provisioner.reconcile_tenant_certificates() == []
    assert calls == [], "reissuing here would burn a validation that cannot succeed"


def test_flips_a_tenant_whose_dns_has_caught_up(recon):
    monkeypatch, calls = recon
    monkeypatch.setattr(provisioner.registry, "list_tenants", lambda: [_tenant()])
    monkeypatch.setattr(provisioner, "tenant_has_certresolver", lambda c, t: False)
    monkeypatch.setattr(provisioner, "should_request_cert_for", lambda h: True)

    result = provisioner.reconcile_tenant_certificates()
    assert calls == ["t.example.com"]
    assert result[0]["domain"] == "t.example.com"


def test_one_tenants_failure_does_not_stop_the_pass(recon):
    """Same resilience run_all_due_backups needs: this loop covers every
    tenant, so one broken tenant must not strand the rest."""
    monkeypatch, calls = recon
    a, b = _tenant(), _tenant()
    b.domain = "second.example.com"
    monkeypatch.setattr(provisioner.registry, "list_tenants", lambda: [a, b])
    monkeypatch.setattr(provisioner, "tenant_has_certresolver", lambda c, t: False)
    monkeypatch.setattr(provisioner, "should_request_cert_for", lambda h: True)

    def boom(domain, actor="x"):
        if domain == "t.example.com":
            raise RuntimeError("docker exploded")
        calls.append(domain)
        return {"domain": domain, "hostnames": [domain]}
    monkeypatch.setattr(provisioner, "reissue_tenant_certificates", boom)

    result = provisioner.reconcile_tenant_certificates()
    assert calls == ["second.example.com"]
    assert len(result) == 1





# --- per-hostname gating ----------------------------------------------

@pytest.fixture
def dns(monkeypatch):
    monkeypatch.setattr(provisioner.dns_records, "PLATFORM_PUBLIC_IP", "203.0.113.1")
    return monkeypatch


def test_a_hostname_pointing_here_may_be_issued_for(dns):
    dns.setattr(provisioner.dns_records, "is_record_live", lambda *a: True)
    assert provisioner.should_request_cert_for("t.example.com")


def test_a_hostname_pointing_elsewhere_may_not(dns):
    dns.setattr(provisioner.dns_records, "is_record_live", lambda *a: False)
    assert not provisioner.should_request_cert_for("t.example.com")


def test_an_unconfigured_platform_ip_blocks_issuance(monkeypatch):
    monkeypatch.setattr(provisioner.dns_records, "PLATFORM_PUBLIC_IP", "")
    monkeypatch.setattr(provisioner.dns_records, "is_record_live",
                        lambda *a: pytest.fail("must not look up DNS with nothing to compare against"))
    assert not provisioner.should_request_cert_for("t.example.com")


def test_one_missing_record_does_not_block_the_others(dns):
    """The reason this is per hostname. Requiring every name to be live
    meant a tenant who never created a webmail or www record left their
    main site on a self-signed certificate permanently."""
    dns.setattr(provisioner.dns_records, "is_record_live",
                lambda kind, host, ip: not host.startswith(("webmail.", "www.")))
    assert provisioner.should_request_cert_for("t.example.com")
    assert provisioner.should_request_cert_for("admin.t.example.com")
    assert not provisioner.should_request_cert_for("webmail.t.example.com")
    assert not provisioner.should_request_cert_for("www.t.example.com")


def test_the_hostname_list_covers_every_router_we_issue_for():
    hosts = provisioner.tenant_cert_hostnames("t.example.com")
    assert hosts == ["t.example.com", "www.t.example.com",
                     "admin.t.example.com", "webmail.t.example.com"]
    assert not any(h.startswith("mail.") for h in hosts), (
        "mail uses TLS passthrough -- Traefik terminates nothing for it"
    )


# --- the www router ----------------------------------------------------

def _waf_labels(monkeypatch, tmp_path, live):
    from unittest.mock import MagicMock
    client = MagicMock()
    monkeypatch.setattr(provisioner.dns_records, "PLATFORM_PUBLIC_IP", "203.0.113.1")
    monkeypatch.setattr(provisioner.dns_records, "is_record_live",
                        lambda kind, host, ip: host in live)
    provisioner._create_waf_container(client, "t-example-com", "t.example.com", str(tmp_path))
    return client.containers.run.call_args.kwargs["labels"]


def test_www_is_actually_routed(monkeypatch, tmp_path):
    """It was suggested in the DNS records and routed nowhere -- every
    tenant's www returned 404 behind the self-signed fallback."""
    labels = _waf_labels(monkeypatch, tmp_path, {"t.example.com"})
    rules = [v for k, v in labels.items() if k.endswith(".rule")]
    assert "Host(`www.t.example.com`)" in rules


def test_www_redirects_to_the_apex_preserving_the_path(monkeypatch, tmp_path):
    labels = _waf_labels(monkeypatch, tmp_path, {"t.example.com"})
    regex = next(v for k, v in labels.items() if k.endswith("redirectregex.regex"))
    repl = next(v for k, v in labels.items() if k.endswith("redirectregex.replacement"))
    assert regex.startswith("^https?://www\\.")
    assert repl == "https://t.example.com/$1"


def test_www_has_its_own_router_so_it_cannot_block_the_apex(monkeypatch, tmp_path):
    """Folding www into the apex rule would put both names in one ACME
    order, so a tenant who never points www here would block their own
    apex certificate. Separate routers keep each hostname's fate its own."""
    labels = _waf_labels(monkeypatch, tmp_path, {"t.example.com"})  # www NOT live

    apex = "traefik.http.routers.vhsp-t-example-com"
    www = "traefik.http.routers.vhsp-t-example-com-www"
    assert labels[f"{apex}.tls.certresolver"] == "letsencrypt", "apex must still be issued"
    assert labels[f"{www}.tls"] == "true"
    assert f"{www}.tls.certresolver" not in labels, "www must wait for its own DNS"
    # And the apex rule must not have absorbed www.
    assert "www" not in labels[f"{apex}.rule"]


def test_www_gets_its_resolver_once_its_own_dns_lands(monkeypatch, tmp_path):
    labels = _waf_labels(monkeypatch, tmp_path, {"t.example.com", "www.t.example.com"})
    assert labels["traefik.http.routers.vhsp-t-example-com-www.tls.certresolver"] == "letsencrypt"


# --- the shared webmail container -------------------------------------

def test_webmail_routers_are_gated_per_tenant(monkeypatch):
    """Found by running prevention end-to-end rather than by review: the
    apex and admin hostnames went quiet but webmail.<domain> still burned
    one validation per tenant created, because its router lives on the
    shared Roundcube container and inherited the entrypoint's resolver.

    Gated per router, not per container: one container carries every
    tenant's webmail route, so a tenant whose DNS is ready must keep its
    real certificate while a newly created one waits on the fallback.
    """
    import re
    from pathlib import Path
    src = Path(provisioner.__file__).read_text()
    body = src[src.index("def _regenerate_roundcube_routes"):]
    body = body[:body.index("\ndef ", 1)]

    assert "_tls_labels(router_id, should_request_cert_for(f\"webmail.{t.domain}\"))" in body, (
        "webmail routers must opt out of the entrypoint's certresolver until "
        "that tenant's DNS resolves here"
    )
    # The decision must be per-tenant, not hoisted out of the loop.
    loop = body[body.index("for t in registry.list_tenants():"):]
    assert "_tls_labels" in loop

