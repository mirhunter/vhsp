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


# --- the decision ------------------------------------------------------

@pytest.fixture
def dns(monkeypatch):
    monkeypatch.setattr(provisioner.dns_records, "PLATFORM_PUBLIC_IP", "203.0.113.1")
    return monkeypatch


def test_requests_a_cert_when_both_hostnames_resolve_here(dns):
    dns.setattr(provisioner.dns_records, "is_record_live", lambda *a: True)
    assert provisioner.should_request_cert("t.example.com")


def test_holds_off_when_neither_resolves(dns):
    dns.setattr(provisioner.dns_records, "is_record_live", lambda *a: False)
    assert not provisioner.should_request_cert("t.example.com")


def test_holds_off_when_only_the_apex_resolves(dns):
    """One order per hostname, so issuing while admin. still 404s the
    challenge spends a validation that cannot succeed."""
    dns.setattr(provisioner.dns_records, "is_record_live",
                lambda kind, host, ip: not host.startswith("admin."))
    assert not provisioner.should_request_cert("t.example.com")


def test_holds_off_when_the_platform_ip_is_unset(monkeypatch):
    """No evidence DNS is right is not the same as evidence it is."""
    monkeypatch.setattr(provisioner.dns_records, "PLATFORM_PUBLIC_IP", "")
    monkeypatch.setattr(provisioner.dns_records, "is_record_live",
                        lambda *a: pytest.fail("must not look up DNS with no IP to compare against"))
    assert not provisioner.should_request_cert("t.example.com")


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
    monkeypatch.setattr(provisioner, "should_request_cert",
                        lambda d: pytest.fail("must not check DNS for a tenant already holding a cert"))

    assert provisioner.reconcile_tenant_certificates() == []
    assert calls == []


def test_skips_tenants_whose_dns_is_still_wrong(recon):
    monkeypatch, calls = recon
    monkeypatch.setattr(provisioner.registry, "list_tenants", lambda: [_tenant()])
    monkeypatch.setattr(provisioner, "tenant_has_certresolver", lambda c, t: False)
    monkeypatch.setattr(provisioner, "should_request_cert", lambda d: False)

    assert provisioner.reconcile_tenant_certificates() == []
    assert calls == [], "reissuing here would burn a validation that cannot succeed"


def test_flips_a_tenant_whose_dns_has_caught_up(recon):
    monkeypatch, calls = recon
    monkeypatch.setattr(provisioner.registry, "list_tenants", lambda: [_tenant()])
    monkeypatch.setattr(provisioner, "tenant_has_certresolver", lambda c, t: False)
    monkeypatch.setattr(provisioner, "should_request_cert", lambda d: True)

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
    monkeypatch.setattr(provisioner, "should_request_cert", lambda d: True)

    def boom(domain, actor="x"):
        if domain == "t.example.com":
            raise RuntimeError("docker exploded")
        calls.append(domain)
        return {"domain": domain, "hostnames": [domain]}
    monkeypatch.setattr(provisioner, "reissue_tenant_certificates", boom)

    result = provisioner.reconcile_tenant_certificates()
    assert calls == ["second.example.com"]
    assert len(result) == 1


# --- the gate must cover exactly what we issue for ---------------------

def test_the_gate_covers_webmail_too(dns):
    """We request certificates for apex, admin AND webmail. Checking only
    the first two meant a tenant with those correct but webmail missing
    still ordered a webmail certificate whose challenge could not be
    answered."""
    checked = []
    dns.setattr(provisioner.dns_records, "is_record_live",
                lambda kind, host, ip: checked.append(host) or True)
    provisioner.should_request_cert("t.example.com")
    assert set(checked) == {"t.example.com", "admin.t.example.com", "webmail.t.example.com"}


def test_a_missing_webmail_record_blocks_issuance(dns):
    dns.setattr(provisioner.dns_records, "is_record_live",
                lambda kind, host, ip: not host.startswith("webmail."))
    assert not provisioner.should_request_cert("t.example.com")


def test_the_gate_matches_the_routers_that_carry_a_resolver():
    """Structural guard against the two drifting apart. Every Host() rule
    given a certresolver needs a corresponding DNS check, or we order for
    a name nobody verified."""
    import re
    from pathlib import Path
    src = Path(provisioner.__file__).read_text()

    gate = src[src.index("def should_request_cert"):]
    gate = gate[:gate.index("\ndef ", 1)]
    checked_suffixes = set(re.findall(r'f"([a-z]+)\.\{domain\}"', gate)) | {""}

    # Router rules that get _tls_labels applied somewhere in the module.
    assert "webmail" in checked_suffixes, "webmail router carries a resolver but isn't gated"
    assert "admin" in checked_suffixes, "admin router carries a resolver but isn't gated"
    assert "www" not in checked_suffixes, (
        "www has no router, so gating on it would stall certificates on a "
        "record that routes nothing -- see the docstring"
    )
